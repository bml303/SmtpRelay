#!/usr/bin/env python3
"""Build a self-contained deployment payload under ``dist/``.

Runs on any host OS. Both the wheels and the CPython runtime are fetched for the
*target* platform, so one build host produces payloads that install on Windows
or Linux with no internet access, no compiler, and no pre-existing Python.

    .venv/bin/python scripts/build_dist.py                              # win_arm64
    .venv/bin/python scripts/build_dist.py --platform win_amd64 --zip
    .venv/bin/python scripts/build_dist.py --platform linux_x86_64 --zip   # .tar.gz
    .venv/bin/python scripts/build_dist.py --platform linux_aarch64 --zip

Windows runtimes come from the nuget CPython packages, Linux runtimes from
python-build-standalone (the builds `uv` installs); both are full CPython layouts
with pip bundled. The runtime is bundled rather than discovered because the
alternative is fragile on a service host: on Windows the Python Install Manager
hides runtimes behind per-user app-execution aliases, and on Linux the distro
interpreter is whatever version the distro froze on.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import tarfile

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DIST_ROOT = PROJECT_ROOT / "dist"
INSTALLER_DIR = PROJECT_ROOT / "installer"
WINDOWS_INSTALLER_DIR = INSTALLER_DIR / "windows"
LINUX_INSTALLER_DIR = INSTALLER_DIR / "linux"


@dataclass(frozen=True)
class Target:
    """One deployable platform."""

    family: str                  #: "windows" | "linux" - which installer ships
    machine: str                 #: platform_machine for PEP 508 marker evaluation
    pip_platforms: tuple[str, ...]  #: --platform tags, most specific first
    archive: str                 #: "zip" | "tar.gz"

    @property
    def sys_platform(self) -> str:
        return "win32" if self.family == "windows" else "linux"


#: pip's --platform is a single tag per flag, and manylinux wheels are tagged
#: with the glibc floor they need, so Linux lists every tag a cp315 wheel on
#: PyPI might carry (pip accepts the flag repeatedly). Nothing here is musl:
#: python-build-standalone's gnu runtime is what gets bundled.
TARGETS: dict[str, Target] = {
    "win_amd64": Target("windows", "AMD64", ("win_amd64",), "zip"),
    "win_arm64": Target("windows", "ARM64", ("win_arm64",), "zip"),
    "linux_x86_64": Target(
        "linux", "x86_64",
        ("manylinux_2_28_x86_64", "manylinux_2_17_x86_64", "manylinux2014_x86_64", "linux_x86_64"),
        "tar.gz",
    ),
    "linux_aarch64": Target(
        "linux", "aarch64",
        ("manylinux_2_28_aarch64", "manylinux_2_17_aarch64", "manylinux2014_aarch64", "linux_aarch64"),
        "tar.gz",
    ),
}

#: nuget package id per Windows platform tag. There is no 32-bit package.
NUGET_RUNTIME_PACKAGES = {
    "win_amd64": "python",
    "win_arm64": "pythonarm64",
}

NUGET_URL = (
    "https://api.nuget.org/v3-flatcontainer/{pkg}/{version}/{pkg}.{version}.nupkg"
)

#: python-build-standalone target triple per Linux platform tag. The
#: ``install_only_stripped`` flavour is a plain, relocatable CPython tree with
#: pip, without the debug symbols and static libraries of the full builds.
PBS_TRIPLES = {
    "linux_x86_64": "x86_64-unknown-linux-gnu",
    "linux_aarch64": "aarch64-unknown-linux-gnu",
}
PBS_LATEST_API = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest"
PBS_DOWNLOAD = "https://github.com/astral-sh/python-build-standalone/releases/download/{tag}/{name}"
#: Pin a python-build-standalone release tag (e.g. 20261026) instead of "latest";
#: the tag used is recorded in MANIFEST.json either way.
PBS_RELEASE_ENV = "PBS_RELEASE"

#: Staged into the payload. Deliberately an allowlist: config.toml is excluded
#: because the developer's copy may hold a real SMTP password or API token.
SOURCE_FILES = ["pyproject.toml", "README.md", "config.example.toml", "requirements.txt"]
SOURCE_DIRS = ["app"]

#: Runtime directory name inside the payload and under the install prefix.
RUNTIME_DIRNAME = "python"

#: Needed to build the project's own wheel offline, and as the pip bootstrap
#: fallback if ensurepip misbehaves. Not `wheel`: setuptools >= 70.1 builds
#: wheels itself, and the wheel package would drag in `packaging`, which nothing
#: at runtime needs.
BUILD_BACKEND_PACKAGES = ["pip", "setuptools>=70.1"]

DEFAULT_RUNTIME_VERSION = "3.15.2"


def find_pwsh() -> str | None:
    """Locate a PowerShell interpreter, for syntax-checking the installer."""
    override = os.environ.get("PWSH")
    if override and Path(override).is_file():
        return override
    return shutil.which("pwsh") or shutil.which("powershell")


#: Uses the real PowerShell parser. __PATHS__ is substituted with a literal array.
_PARSE_PROBE = (
    "$fail=$false;"
    "foreach($p in @(__PATHS__)){"
    "$e=$null;$t=$null;"
    "[System.Management.Automation.Language.Parser]::ParseFile($p,[ref]$t,[ref]$e)|Out-Null;"
    "if($e -and $e.Count -gt 0){$fail=$true;Write-Host \"PARSE FAIL: $p\";"
    "foreach($x in $e){Write-Host ('  line {0}: {1}' -f $x.Extent.StartLineNumber,$x.Message)}}"
    "else{Write-Host \"  parsed OK: $p\"}};"
    "if($fail){exit 1}else{exit 0}"
)


def validate_powershell_syntax(scripts: list[Path]) -> None:
    """Parse-check the installer scripts when a PowerShell is available.

    A PowerShell *parse* error means the script never runs at all - not even its
    first line - so on the target it appears as a wall of parser output instead of
    a usable diagnostic. Three such bugs shipped before this check existed; the
    last was ``$ServiceName:(OI)(CI)RX`` inside a hint string, which the parser
    rejects as an invalid drive-qualified variable reference.

    Skipped with a loud warning when no interpreter is found. Set ``PWSH`` to the
    path of one - the self-contained Linux tarball works fine - so that builds on
    a Linux host are checked too.
    """
    if not scripts:
        return
    pwsh = find_pwsh()
    if pwsh is None:
        print(
            "  WARNING: no pwsh found - installer scripts were NOT syntax-checked. "
            "Set PWSH=/path/to/pwsh to enable this."
        )
        return

    paths = ",".join("'{}'".format(str(s).replace("'", "''")) for s in scripts)
    probe = _PARSE_PROBE.replace("__PATHS__", paths)
    result = subprocess.run(
        [pwsh, "-NoProfile", "-Command", probe],
        capture_output=True,
        text=True,
    )
    for line in (result.stdout or "").strip().splitlines():
        print(f"  {line}")
    if result.returncode != 0:
        raise SystemExit(
            "Installer scripts have PowerShell syntax errors (above). A parse "
            "error means the script will not run at all on the target."
        )


def validate_bash_syntax(scripts: list[Path]) -> None:
    """``bash -n`` each script. bash is always present on a Linux build host."""
    bash = shutil.which("bash")
    if bash is None:
        print("  WARNING: no bash found - Linux installer scripts were NOT syntax-checked.")
        return
    for script in scripts:
        result = subprocess.run([bash, "-n", str(script)], capture_output=True, text=True)
        if result.returncode != 0:
            raise SystemExit(f"{script.name} has bash syntax errors:\n{result.stderr}")
        print(f"  parsed OK: {script.name}")


def render_unit(template: Path, *, install_dir: str, config_dir: str, user: str, group: str) -> str:
    """The same four substitutions install.sh performs with sed."""
    text = template.read_text()
    for token, value in {
        "@INSTALL_DIR@": install_dir, "@CONFIG_DIR@": config_dir, "@USER@": user, "@GROUP@": group,
    }.items():
        text = text.replace(token, value)
    leftover = re.search(r"@[A-Z_]+@", text)
    if leftover:
        raise SystemExit(f"unrendered token left in {template.name}: {leftover.group(0)}")
    return text


def validate_systemd_unit(template: Path) -> None:
    """Run ``systemd-analyze verify`` on a rendered copy of the unit template.

    verify insists that ExecStart points at an existing executable, so the
    rendering points INSTALL_DIR at a scratch tree holding a stub python3. The
    user has to exist too; the build user does. Skipped with a warning where
    systemd-analyze is unavailable (macOS, containers without systemd).
    """
    analyze = shutil.which("systemd-analyze")
    if analyze is None:
        print("  WARNING: no systemd-analyze found - the unit template was NOT verified.")
        return
    import getpass
    import grp
    user = getpass.getuser()
    group = grp.getgrgid(os.getgid()).gr_name
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        stub = root / "python" / "bin" / "python3"
        stub.parent.mkdir(parents=True)
        stub.write_text("#!/bin/sh\n")
        stub.chmod(0o755)
        unit = root / template.name
        unit.write_text(render_unit(template, install_dir=str(root), config_dir=str(root), user=user, group=group))
        result = subprocess.run(
            [analyze, "verify", "--man=no", "--generators=no", str(unit)],
            capture_output=True, text=True,
        )
    ours = [l for l in (result.stdout + result.stderr).splitlines() if template.name in l]
    for line in ours:
        print(f"  {line}")
    if result.returncode != 0 or ours:
        raise SystemExit(f"systemd-analyze verify rejected {template.name} (above).")
    print(f"  verified OK: {template.name}")


def validate_installer(target: Target) -> None:
    if target.family == "windows":
        validate_powershell_syntax(sorted(WINDOWS_INSTALLER_DIR.glob("*.ps1")))
    else:
        validate_bash_syntax(sorted(LINUX_INSTALLER_DIR.glob("*.sh")))
        validate_systemd_unit(LINUX_INSTALLER_DIR / "smtp-relay.service")


def read_version() -> str:
    data = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text())
    return data["project"]["version"]


def bump_version(version: str) -> str:
    """Increment the patch component: 0.1.0 -> 0.1.1, 0.1.9 -> 0.1.10."""
    if not isinstance(version, str):
        raise SystemExit(
            f"cannot bump {version!r}: expected a version string like 0.1.0. "
            "Pass --version X.Y.Z to set one explicitly."
        )
    parts = version.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise SystemExit(
            f"cannot bump {version!r}: expected a three-component numeric version. "
            "Pass --version X.Y.Z to set one explicitly."
        )
    parts[2] = str(int(parts[2]) + 1)
    return ".".join(parts)


def write_version(version: str, root: Path = PROJECT_ROOT) -> None:
    """Write the version to both places that carry it, under ``root``.

    ``pyproject.toml`` and ``app/__init__.py`` must agree - a test asserts it, and
    the running service reports ``app.__version__`` at ``/health`` while the
    payload name and Apps & features entry come from pyproject. Called twice per
    build: once against the staged payload (so it is self-consistent before the
    manifest hashes it) and once against the project on success.
    """
    targets = (
        (root / "pyproject.toml", r'^version\s*=\s*"[^"]+"', f'version = "{version}"'),
        (root / "app" / "__init__.py", r'^__version__\s*=\s*"[^"]+"', f'__version__ = "{version}"'),
    )
    # Validate every target before writing any of them. Writing as we go would
    # leave the two files disagreeing if the second pattern stopped matching,
    # which is worse than failing outright.
    prepared: list[tuple[Path, str]] = []
    for path, pattern, replacement in targets:
        text = path.read_text()
        # A lambda avoids re.sub interpreting backslashes/group refs in the value.
        updated, count = re.subn(pattern, lambda _m: replacement, text, count=1, flags=re.M)
        if count != 1:
            raise SystemExit(f"could not find the version string in {path}")
        prepared.append((path, updated))

    for path, updated in prepared:
        path.write_text(updated)


def run(cmd: list[str], *, cwd: Path | None = None) -> None:
    print(f"  $ {' '.join(cmd)}")
    subprocess.run(cmd, check=True, cwd=cwd)


def target_for(platform: str) -> Target:
    try:
        return TARGETS[platform]
    except KeyError:
        raise SystemExit(
            f"no bundled CPython for platform {platform!r}; "
            f"supported: {', '.join(sorted(TARGETS))}"
        ) from None


def runtime_package_for(platform: str) -> str:
    target_for(platform)
    try:
        return NUGET_RUNTIME_PACKAGES[platform]
    except KeyError:
        raise SystemExit(f"{platform} is not a Windows target; its runtime comes from python-build-standalone") from None


def marker_environment(platform: str, runtime_version: str) -> dict[str, str]:
    """PEP 508 environment for the *target*, for selecting pins and checking the closure."""
    target = target_for(platform)
    python_version = wheel_tag_for(runtime_version)
    full = runtime_version if runtime_version.count(".") == 2 else f"{python_version}.0"
    return {
        "sys_platform": target.sys_platform,
        "os_name": "nt" if target.family == "windows" else "posix",
        "platform_system": "Windows" if target.family == "windows" else "Linux",
        "platform_machine": target.machine,
        "python_version": python_version,
        "python_full_version": full,
        "implementation_name": "cpython",
        "platform_python_implementation": "CPython",
    }


def wheel_tag_for(runtime_version: str) -> str:
    """Derive the pip --python-version tag from the runtime version.

    Deriving rather than accepting both independently is the point: the wheels
    must match the bundled interpreter's minor version, and a mismatch would only
    surface on the target as an incomprehensible "no matching distribution".
    """
    if not isinstance(runtime_version, str):
        raise SystemExit(
            f"--runtime-version must be a string like 3.15.2, got {runtime_version!r}"
        )
    parts = runtime_version.split(".")
    if len(parts) < 2 or not parts[0].isdigit() or not parts[1].isdigit():
        raise SystemExit(
            f"--runtime-version must look like 3.15 or 3.15.2, got {runtime_version!r}"
        )
    return f"{parts[0]}.{parts[1]}"


def fetch_python_runtime(platform: str, runtime_version: str, dest: Path) -> tuple[int, str]:
    """Fetch the target's CPython into ``dest``. Returns (file count, source label)."""
    if target_for(platform).family == "windows":
        return _fetch_nuget_runtime(platform, runtime_version, dest), f"nuget:{runtime_package_for(platform)}"
    return _fetch_pbs_runtime(platform, runtime_version, dest)


def _latest_pbs_release() -> str:
    request = urllib.request.Request(
        PBS_LATEST_API, headers={"Accept": "application/vnd.github+json", "User-Agent": "smtp-relay-build"}
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)["tag_name"]


def _fetch_pbs_runtime(platform: str, runtime_version: str, dest: Path) -> tuple[int, str]:
    """Download a python-build-standalone ``install_only_stripped`` tarball,
    verify it against the release's SHA256SUMS, and extract it into ``dest``.

    Assets are named ``cpython-<ver>+<release>-<triple>-install_only_stripped.tar.gz``
    and every asset's hash is in the release's ``SHA256SUMS``; there is no
    per-file sidecar. The archive's single top-level directory ``python/`` is
    stripped so ``dest/bin/python3`` is the interpreter, mirroring the Windows
    layout where ``dest/python.exe`` is.
    """
    triple = PBS_TRIPLES[platform]
    tag = os.environ.get(PBS_RELEASE_ENV) or _latest_pbs_release()
    name = f"cpython-{runtime_version}+{tag}-{triple}-install_only_stripped.tar.gz"
    print(f"  fetching {name} from python-build-standalone release {tag}")

    with urllib.request.urlopen(PBS_DOWNLOAD.format(tag=tag, name="SHA256SUMS"), timeout=60) as response:
        sums = response.read().decode()
    expected = next((line.split()[0] for line in sums.splitlines() if line.strip().endswith(" " + name) or line.strip().endswith("  " + name)), None)
    if expected is None:
        raise SystemExit(
            f"python-build-standalone release {tag} ships no {name}. Either CPython "
            f"{runtime_version} is not in that release, or pass {PBS_RELEASE_ENV}=<tag> of one that has it."
        )

    dest.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / name
        urllib.request.urlretrieve(PBS_DOWNLOAD.format(tag=tag, name=name), archive)
        actual = hashlib.sha256(archive.read_bytes()).hexdigest()
        if actual != expected:
            raise SystemExit(f"checksum mismatch for {name}: expected {expected}, got {actual}")
        print(f"  sha256 verified against release SHA256SUMS")

        extracted = 0
        with tarfile.open(archive, "r:gz") as tf:
            for member in tf.getmembers():
                if not member.name.startswith("python/"):
                    raise SystemExit(f"unexpected top-level entry in runtime archive: {member.name}")
                member.name = member.name[len("python/"):]
                if not member.name:
                    continue
                target = dest / member.name
                if not target.resolve().is_relative_to(dest.resolve()):
                    raise SystemExit(f"refusing to extract suspicious path: {member.name}")
                tf.extract(member, dest, filter="data")
                if member.isfile():
                    extracted += 1

    python = dest / "bin" / "python3"
    if not python.is_file():
        raise SystemExit(f"runtime extraction produced no bin/python3 in {dest}")
    if not list(dest.glob("lib/python3.*/ensurepip")):
        raise SystemExit("bundled runtime has no ensurepip; offline pip bootstrap would fail")
    print(f"  runtime: {extracted} files -> {dest.name}/")
    return extracted, f"python-build-standalone:{tag}"


def _fetch_nuget_runtime(platform: str, runtime_version: str, dest: Path) -> int:
    """Download the nuget CPython package and extract its ``tools/`` into ``dest``.

    The nuget package is a full CPython layout: loose ``Lib/``, ``ensurepip`` with
    a bundled pip wheel, ``venv``, and crucially **no ``._pth`` file**, so
    ``site.py`` runs and ``.pth`` files are processed. python.org's embeddable zip
    is not usable here - its ``._pth`` ships with ``import site`` commented out,
    which stops ``pywin32.pth`` from adding ``win32``/``win32\\lib`` to sys.path
    and from running ``pywin32_bootstrap``, so ``import win32service`` fails and
    the service cannot start.
    """
    pkg = runtime_package_for(platform)
    url = NUGET_URL.format(pkg=pkg, version=runtime_version)
    print(f"  fetching {pkg} {runtime_version} from nuget")

    dest.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        nupkg = Path(tmp) / "runtime.nupkg"
        urllib.request.urlretrieve(url, nupkg)

        extracted = 0
        with zipfile.ZipFile(nupkg) as zf:
            for info in zf.infolist():
                name = info.filename
                if info.is_dir() or not name.startswith("tools/"):
                    continue
                relative = name[len("tools/"):]
                target = dest / relative
                # Guard against a crafted archive escaping the destination.
                if not target.resolve().is_relative_to(dest.resolve()):
                    raise SystemExit(f"refusing to extract suspicious path: {name}")
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
                extracted += 1

    if not (dest / "python.exe").is_file():
        raise SystemExit(f"runtime extraction produced no python.exe in {dest}")
    if (dest / "Lib" / "ensurepip").is_dir() is False:
        raise SystemExit("bundled runtime has no ensurepip; offline pip bootstrap would fail")
    if list(dest.glob("python*._pth")):
        raise SystemExit("bundled runtime has a ._pth file, which would disable site and break pywin32")

    print(f"  runtime: {extracted} files -> {dest.name}/")
    return extracted


def select_requirements(platform: str, python_version: str, dest: Path) -> Path:
    """Materialize the pins the *target* would actually resolve.

    pip evaluates PEP 508 markers against the *running* interpreter, so handing it
    requirements.txt with --platform win_amd64 produces a false failure: a
    ``sys_platform != 'win32'`` pin stays required while --platform forbids its
    (absent) Windows wheels. Evaluate the markers for the target first, then
    resolve only the survivors.
    """
    from packaging.markers import Marker

    env = marker_environment(platform, python_version)

    selected: list[str] = []
    for raw in (PROJECT_ROOT / "requirements.txt").read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        spec, _, marker = line.partition(";")
        if not marker.strip() or Marker(marker.strip()).evaluate(env):
            selected.append(spec.strip())

    dest.write_text("\n".join(selected) + "\n")
    print(f"  {len(selected)} packages selected for {env['sys_platform']} / cp{python_version.replace('.', '')}")
    return dest


def select_windows_requirements(python_version: str, dest: Path) -> Path:
    return select_requirements("win_amd64", python_version, dest)


def download_wheels(wheel_dir: Path, requirements: Path, platform: str, python_version: str) -> int:
    """Fetch every wheel the target needs. Fails loudly if any would need a build."""
    wheel_dir.mkdir(parents=True, exist_ok=True)
    base = [sys.executable, "-m", "pip", "download", "--no-deps", "--only-binary=:all:"]
    for tag in target_for(platform).pip_platforms:
        base += ["--platform", tag]
    base += ["--python-version", python_version, "--dest", str(wheel_dir)]
    # --only-binary=:all: is what makes this a compiler check as well as a
    # download: anything without a matching wheel fails here, on the build host,
    # instead of on the target machine demanding MSVC.
    run(base + ["-r", str(requirements)])
    run(base + BUILD_BACKEND_PACKAGES)

    wheels = sorted(wheel_dir.glob("*.whl"))
    print(f"  {len(wheels)} wheels downloaded")
    return len(wheels)


def verify_dependency_closure(
    wheel_dir: Path, *, platform: str, runtime_version: str
) -> dict[str, list[str]]:
    """Return ``{missing package: [reason]}`` for the target platform.

    This cannot be delegated to pip. pip evaluates PEP 508 markers against the
    *host* interpreter, so neither ``pip freeze`` on Linux nor
    ``pip download --platform win_arm64`` will ever surface a Windows-only
    transitive dependency. ``pytest``'s ``colorama>=0.4; sys_platform == "win32"``
    is exactly that, and it broke the first real offline install on the target
    with "No matching distribution found". So the closure is computed here from
    each wheel's own METADATA, with markers evaluated for the target.
    """
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name

    env_base = marker_environment(platform, runtime_version)

    def norm(name: str) -> str:
        return canonicalize_name(name).replace("_", "-")

    requires: dict[str, list[str]] = {}
    for wheel in sorted(wheel_dir.glob("*.whl")):
        with zipfile.ZipFile(wheel) as zf:
            metas = [n for n in zf.namelist() if n.endswith(".dist-info/METADATA")]
            if not metas:
                continue
            text = zf.read(metas[0]).decode("utf-8", "replace")
        requires[norm(wheel.name.split("-")[0])] = re.findall(
            r"^Requires-Dist:\s*(.+)$", text, re.M
        )

    #: Extras the project actually requests. ``pydantic[email]`` is the only one,
    #: and without this its ``email-validator`` requirement would be skipped.
    requested_extras: dict[str, set[str]] = {"pydantic": {"email"}}

    missing: dict[str, list[str]] = {}
    for package, lines in sorted(requires.items()):
        active = requested_extras.get(package, set())
        for line in lines:
            try:
                req = Requirement(line)
            except Exception:
                continue
            if req.marker is not None:
                matched = False
                for extra in active | {""}:
                    env = dict(env_base)
                    env["extra"] = extra
                    try:
                        if req.marker.evaluate(env):
                            matched = True
                            break
                    except Exception:
                        pass
                if not matched:
                    continue
            name = norm(req.name)
            if name not in requires:
                missing.setdefault(name, []).append(f"{package} requires {line}")
    return missing


def installer_files(target: Target) -> list[Path]:
    if target.family == "windows":
        return sorted(WINDOWS_INSTALLER_DIR.glob("*.ps1"))
    return sorted(LINUX_INSTALLER_DIR.glob("*.sh")) + [LINUX_INSTALLER_DIR / "smtp-relay.service"]


def stage_source(payload: Path, platform: str = "win_arm64") -> None:
    for name in SOURCE_FILES:
        src = PROJECT_ROOT / name
        if not src.is_file():
            raise SystemExit(f"expected source file missing: {src}")
        shutil.copy2(src, payload / name)

    for name in SOURCE_DIRS:
        src = PROJECT_ROOT / name
        dst = payload / name
        # dirs_exist_ok: --keep-existing reuses a payload directory that already
        # holds a staged copy, and copytree otherwise raises FileExistsError.
        shutil.copytree(
            src, dst,
            ignore=shutil.ignore_patterns("__pycache__", "*.py[cod]"),
            dirs_exist_ok=True,
        )

    files = installer_files(target_for(platform))
    for script in files:
        dst = payload / script.name
        shutil.copy2(script, dst)
        if script.suffix == ".sh":
            dst.chmod(0o755)

    print(f"  staged: {', '.join(SOURCE_DIRS + SOURCE_FILES)} + {len(files)} installer file(s)")


def write_manifest(
    payload: Path,
    *,
    version: str,
    platform: str,
    runtime_version: str,
    runtime_files: int,
    runtime_source: str = "",
    wheel_count: int,
) -> None:
    digest = hashlib.sha256()
    files = {}
    for path in sorted(payload.rglob("*")):
        if path.is_file() and path.name != "MANIFEST.json":
            rel = path.relative_to(payload).as_posix()
            file_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            files[rel] = file_hash
            digest.update(f"{rel}:{file_hash}\n".encode())

    manifest = {
        "name": "SmtpRelay",
        "version": version,
        "platform": platform,
        "family": target_for(platform).family,
        "runtime_version": runtime_version,
        "runtime_files": runtime_files,
        "runtime_source": runtime_source,
        "wheel_tag": f"cp{runtime_version.split('.')[0]}{runtime_version.split('.')[1]}",
        "wheel_count": wheel_count,
        "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "built_on": sys.platform,
        "payload_sha256": digest.hexdigest(),
        "files": files,
    }
    (payload / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"  manifest: {len(files)} files, payload sha256 {digest.hexdigest()[:16]}...")


def make_tarball(payload: Path) -> Path:
    """``.tar.gz`` for Linux: it keeps the executable bits on install.sh and
    bin/python3, which a zip would lose. Named like make_zip, for the same reason."""
    archive = payload.with_name(payload.name + ".tar.gz")
    with tarfile.open(archive, "w:gz") as tf:
        for path in sorted(payload.rglob("*")):
            if path.is_file() or path.is_symlink():
                tf.add(path, arcname=path.relative_to(payload.parent).as_posix(), recursive=False)
    print(f"  archive: {archive.name} ({archive.stat().st_size / 1e6:.1f} MB)")
    return archive


def make_archive(payload: Path, platform: str) -> Path:
    return make_zip(payload) if target_for(platform).archive == "zip" else make_tarball(payload)


def make_zip(payload: Path) -> Path:
    """Archive the payload, preserving its full name.

    Deliberately not ``payload.with_suffix(".zip")``: the directory name contains
    dots (``SmtpRelay-0.1.0-win_amd64-cp315``), so pathlib treats
    ``.0-win_amd64-cp315`` as the suffix and every payload for a given minor
    version collapses onto one archive name. That would silently overwrite, say,
    the win_arm64 build with the win_amd64 one - same filename, wrong wheels.
    """
    archive = payload.with_name(payload.name + ".zip")
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(payload.rglob("*")):
            if path.is_file():
                # Store relative to the parent so extracting recreates the
                # named payload directory rather than spilling files loose.
                zf.write(path, path.relative_to(payload.parent))
    print(f"  archive: {archive.name} ({archive.stat().st_size / 1e6:.1f} MB)")
    return archive


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--platform", default="win_arm64",
        choices=sorted(TARGETS),
        help="target platform (default: win_arm64)",
    )
    parser.add_argument(
        "--runtime-version", default=DEFAULT_RUNTIME_VERSION,
        help=f"bundled CPython version (default: {DEFAULT_RUNTIME_VERSION}); "
             "the wheel tag is derived from it so they cannot disagree",
    )
    parser.add_argument(
        "--zip", "--archive", dest="zip", action="store_true",
        help="also produce an archive (.zip for Windows targets, .tar.gz for Linux)",
    )
    parser.add_argument(
        "--keep-existing", action="store_true",
        help="do not delete an existing payload directory",
    )
    parser.add_argument(
        "--version",
        help="set the version explicitly instead of bumping the patch component",
    )
    parser.add_argument(
        "--no-bump", action="store_true",
        help="build without incrementing the version (the payload name will repeat)",
    )
    args = parser.parse_args()

    current = read_version()
    if args.version:
        version = args.version
    elif args.no_bump:
        version = current
    else:
        # Every build gets a distinct version so two payloads can never share a
        # filename. Without this, five materially different builds were all
        # "SmtpRelay-0.1.0-win_arm64-cp315.zip" and only a hash distinguished
        # them - which is how a stale download nearly got installed as current.
        version = bump_version(current)

    python_version = wheel_tag_for(args.runtime_version)
    tag = f"cp{python_version.replace('.', '')}"
    payload = DIST_ROOT / f"SmtpRelay-{version}-{args.platform}-{tag}"

    print(f"Building {payload.name} (CPython {args.runtime_version}, {args.platform})")
    if version != current:
        print(f"  version {current} -> {version}")

    # Fail before downloading anything: a script the target cannot parse is
    # worthless no matter how correct the payload around it is.
    target = target_for(args.platform)
    print("Checking installer scripts")
    validate_installer(target)

    if payload.exists():
        if args.keep_existing:
            print("  reusing existing payload directory")
        else:
            shutil.rmtree(payload)
    payload.mkdir(parents=True, exist_ok=True)

    runtime_files, runtime_source = fetch_python_runtime(
        args.platform, args.runtime_version, payload / RUNTIME_DIRNAME
    )

    with tempfile.TemporaryDirectory() as tmp:
        requirements = select_requirements(args.platform, python_version, Path(tmp) / f"requirements-{args.platform}.txt")
        wheel_count = download_wheels(
            payload / "wheels", requirements, args.platform, python_version
        )

    missing = verify_dependency_closure(
        payload / "wheels", platform=args.platform, runtime_version=args.runtime_version
    )
    if missing:
        detail = "\n".join(
            f"    {name}\n      <- {'; '.join(reasons)}"
            for name, reasons in sorted(missing.items())
        )
        raise SystemExit(
            "Dependency closure is incomplete for the target platform:\n"
            f"{detail}\n"
            "Add each missing package to requirements.txt with a "
            f"`; sys_platform == '{target.sys_platform}'` marker, then rebuild. An offline "
            "install on the target cannot fetch what is not bundled."
        )
    print("  dependency closure verified for the target platform")

    stage_source(payload, args.platform)
    if version != current:
        # Patch the staged copies so the payload is internally consistent: its
        # pyproject.toml, app.__version__ (served at /health), MANIFEST.json and
        # directory name must all agree. Done before the manifest hashes anything.
        write_version(version, payload)
    write_manifest(
        payload,
        version=version,
        platform=args.platform,
        runtime_version=args.runtime_version,
        runtime_files=runtime_files,
        runtime_source=runtime_source,
        wheel_count=wheel_count,
    )
    if args.zip:
        make_archive(payload, args.platform)

    size = sum(p.stat().st_size for p in payload.rglob("*") if p.is_file())
    print(f"\nDone: {payload} ({size / 1e6:.1f} MB)")
    if target.family == "windows":
        print("Copy the payload to the target and, from an elevated prompt:")
        print("  powershell -ExecutionPolicy Bypass -File .\\install.ps1")
    else:
        print("Copy the payload to the target and run:")
        print("  sudo ./install.sh")

    # Only touch the source tree once the payload actually exists, so a failed
    # build does not leave a version bump behind with nothing to show for it.
    if version != current:
        write_version(version)
        print(f"\nVersion bumped {current} -> {version} in pyproject.toml and app/__init__.py.")
        print("Commit it: git add pyproject.toml app/__init__.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
