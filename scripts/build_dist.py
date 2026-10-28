#!/usr/bin/env python3
"""Build a self-contained Windows deployment payload under ``dist/``.

Runs on any host OS. Both the wheels and the CPython runtime are fetched for the
*target* platform, so a Linux build host produces a payload that installs on
Windows with no internet access, no C/C++ compiler, and no pre-existing Python.

    .venv/bin/python scripts/build_dist.py
    .venv/bin/python scripts/build_dist.py --runtime-version 3.15.1
    .venv/bin/python scripts/build_dist.py --platform win_amd64 --zip

The runtime is bundled rather than discovered because the alternative is fragile
on a service host: the Python Install Manager puts runtimes in a per-user
%LOCALAPPDATA% behind app-execution aliases, and a LocalSystem or virtual-service
account should not depend on one user's profile.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DIST_ROOT = PROJECT_ROOT / "dist"
INSTALLER_DIR = PROJECT_ROOT / "installer"

#: nuget package id per pip platform tag. There is no 32-bit package.
NUGET_RUNTIME_PACKAGES = {
    "win_amd64": "python",
    "win_arm64": "pythonarm64",
}

NUGET_URL = (
    "https://api.nuget.org/v3-flatcontainer/{pkg}/{version}/{pkg}.{version}.nupkg"
)

#: Staged into the payload. Deliberately an allowlist: config.toml is excluded
#: because the developer's copy may hold a real SMTP password or API token.
SOURCE_FILES = ["pyproject.toml", "README.md", "config.example.toml", "requirements.txt"]
SOURCE_DIRS = ["app"]

#: Runtime directory name inside the payload and under the install prefix.
RUNTIME_DIRNAME = "python"

#: Needed to build the project's own wheel offline, and as the pip bootstrap
#: fallback if ensurepip misbehaves.
BUILD_BACKEND_PACKAGES = ["pip", "setuptools>=68", "wheel"]

DEFAULT_RUNTIME_VERSION = "3.15.2"


def read_version() -> str:
    data = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text())
    return data["project"]["version"]


def run(cmd: list[str], *, cwd: Path | None = None) -> None:
    print(f"  $ {' '.join(cmd)}")
    subprocess.run(cmd, check=True, cwd=cwd)


def runtime_package_for(platform: str) -> str:
    try:
        return NUGET_RUNTIME_PACKAGES[platform]
    except KeyError:
        raise SystemExit(
            f"no bundled CPython for platform {platform!r}; "
            f"supported: {', '.join(sorted(NUGET_RUNTIME_PACKAGES))}"
        ) from None


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


def fetch_python_runtime(platform: str, runtime_version: str, dest: Path) -> int:
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


def select_windows_requirements(python_version: str, dest: Path) -> Path:
    """Materialize the pins a Windows install would actually resolve.

    pip evaluates PEP 508 markers against the *running* interpreter, so handing it
    requirements.txt with --platform win_amd64 produces a false failure: a
    ``sys_platform != 'win32'`` pin stays required while --platform forbids its
    (absent) Windows wheels. Evaluate the markers for a synthetic Windows
    environment first, then resolve only the survivors.
    """
    from packaging.markers import Marker

    env = {
        "sys_platform": "win32",
        "os_name": "nt",
        "platform_system": "Windows",
        "platform_machine": "AMD64",
        "python_version": python_version,
        "python_full_version": f"{python_version}.0",
        "implementation_name": "cpython",
    }

    selected: list[str] = []
    for raw in (PROJECT_ROOT / "requirements.txt").read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        spec, _, marker = line.partition(";")
        if not marker.strip() or Marker(marker.strip()).evaluate(env):
            selected.append(spec.strip())

    dest.write_text("\n".join(selected) + "\n")
    print(f"  {len(selected)} packages selected for win32 / cp{python_version.replace('.', '')}")
    return dest


def download_wheels(wheel_dir: Path, requirements: Path, platform: str, python_version: str) -> int:
    """Fetch every wheel the target needs. Fails loudly if any would need a build."""
    wheel_dir.mkdir(parents=True, exist_ok=True)
    base = [
        sys.executable, "-m", "pip", "download",
        "--no-deps", "--only-binary=:all:",
        "--platform", platform,
        "--python-version", python_version,
        "--dest", str(wheel_dir),
    ]
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

    machine = "ARM64" if platform == "win_arm64" else "AMD64"
    env_base = {
        "sys_platform": "win32",
        "os_name": "nt",
        "platform_system": "Windows",
        "platform_machine": machine,
        "python_version": wheel_tag_for(runtime_version),
        "python_full_version": runtime_version,
        "implementation_name": "cpython",
        "platform_python_implementation": "CPython",
    }

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


def stage_source(payload: Path) -> None:
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

    for script in sorted(INSTALLER_DIR.glob("*.ps1")):
        shutil.copy2(script, payload / script.name)

    print(f"  staged: {', '.join(SOURCE_DIRS + SOURCE_FILES)} + {len(list(INSTALLER_DIR.glob('*.ps1')))} installer script(s)")


def write_manifest(
    payload: Path,
    *,
    version: str,
    platform: str,
    runtime_version: str,
    runtime_files: int,
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
        "runtime_version": runtime_version,
        "runtime_files": runtime_files,
        "wheel_tag": f"cp{runtime_version.split('.')[0]}{runtime_version.split('.')[1]}",
        "wheel_count": wheel_count,
        "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "built_on": sys.platform,
        "payload_sha256": digest.hexdigest(),
        "files": files,
    }
    (payload / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"  manifest: {len(files)} files, payload sha256 {digest.hexdigest()[:16]}...")


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
        choices=sorted(NUGET_RUNTIME_PACKAGES),
        help="target platform (default: win_arm64)",
    )
    parser.add_argument(
        "--runtime-version", default=DEFAULT_RUNTIME_VERSION,
        help=f"bundled CPython version (default: {DEFAULT_RUNTIME_VERSION}); "
             "the wheel tag is derived from it so they cannot disagree",
    )
    parser.add_argument("--zip", action="store_true", help="also produce a .zip")
    parser.add_argument(
        "--keep-existing", action="store_true",
        help="do not delete an existing payload directory",
    )
    args = parser.parse_args()

    version = read_version()
    python_version = wheel_tag_for(args.runtime_version)
    tag = f"cp{python_version.replace('.', '')}"
    payload = DIST_ROOT / f"SmtpRelay-{version}-{args.platform}-{tag}"

    print(f"Building {payload.name} (CPython {args.runtime_version}, {args.platform})")
    if payload.exists():
        if args.keep_existing:
            print("  reusing existing payload directory")
        else:
            shutil.rmtree(payload)
    payload.mkdir(parents=True, exist_ok=True)

    runtime_files = fetch_python_runtime(
        args.platform, args.runtime_version, payload / RUNTIME_DIRNAME
    )

    with tempfile.TemporaryDirectory() as tmp:
        requirements = select_windows_requirements(python_version, Path(tmp) / "requirements-win.txt")
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
            "`; sys_platform == 'win32'` marker, then rebuild. An offline install "
            "on the target cannot fetch what is not bundled."
        )
    print("  dependency closure verified for the target platform")

    stage_source(payload)
    write_manifest(
        payload,
        version=version,
        platform=args.platform,
        runtime_version=args.runtime_version,
        runtime_files=runtime_files,
        wheel_count=wheel_count,
    )
    if args.zip:
        make_zip(payload)

    size = sum(p.stat().st_size for p in payload.rglob("*") if p.is_file())
    print(f"\nDone: {payload} ({size / 1e6:.1f} MB)")
    print("Copy the payload to the target and, from an elevated prompt:")
    print("  powershell -ExecutionPolicy Bypass -File .\\install.ps1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
