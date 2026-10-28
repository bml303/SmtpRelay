#!/usr/bin/env python3
"""Build a self-contained Windows deployment payload under ``dist/``.

Runs on any host OS. Wheels are fetched for the *target* platform and CPython
version through pip's cross-platform resolver, so a Linux build host can produce a
payload that installs on Windows with no internet access and no C/C++ compiler.

    .venv/bin/python scripts/build_dist.py
    .venv/bin/python scripts/build_dist.py --python-version 3.13
    .venv/bin/python scripts/build_dist.py --platform win_arm64 --zip

The payload installs offline: ``install.ps1`` creates a venv and installs from the
bundled ``wheels/`` directory with ``--no-index``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import tomllib
import zipfile
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DIST_ROOT = PROJECT_ROOT / "dist"
INSTALLER_DIR = PROJECT_ROOT / "installer"

#: Staged into the payload. Deliberately an allowlist: config.toml is excluded
#: because the developer's copy may hold a real SMTP password or API token.
SOURCE_FILES = ["pyproject.toml", "README.md", "config.example.toml", "requirements.txt"]
SOURCE_DIRS = ["app"]

#: Needed to build the project's own sdist/wheel offline. Python 3.12+ venvs no
#: longer ship setuptools, and pip's build isolation would otherwise reach out to
#: PyPI - which defeats the point of an offline bundle.
BUILD_BACKEND_PACKAGES = ["setuptools>=68", "wheel"]


def read_version() -> str:
    data = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text())
    return data["project"]["version"]


def run(cmd: list[str], *, cwd: Path | None = None) -> None:
    print(f"  $ {' '.join(cmd)}")
    subprocess.run(cmd, check=True, cwd=cwd)


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


def write_manifest(payload: Path, *, version: str, platform: str, python_version: str, wheel_count: int) -> None:
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
        "python_version": python_version,
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
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--platform", default="win_amd64", help="pip platform tag (default: win_amd64)")
    parser.add_argument("--python-version", default="3.15", help="target CPython version (default: 3.15)")
    parser.add_argument("--zip", action="store_true", help="also produce a .zip alongside the directory")
    parser.add_argument("--keep-existing", action="store_true", help="do not delete an existing payload directory")
    args = parser.parse_args()

    version = read_version()
    tag = f"cp{args.python_version.replace('.', '')}"
    payload = DIST_ROOT / f"SmtpRelay-{version}-{args.platform}-{tag}"

    print(f"Building {payload.name}")
    if payload.exists():
        if not args.keep_existing:
            shutil.rmtree(payload)
        else:
            print("  reusing existing payload directory")
    payload.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        requirements = select_windows_requirements(args.python_version, Path(tmp) / "requirements-win.txt")
        wheel_count = download_wheels(payload / "wheels", requirements, args.platform, args.python_version)

    stage_source(payload)
    write_manifest(
        payload,
        version=version,
        platform=args.platform,
        python_version=args.python_version,
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
