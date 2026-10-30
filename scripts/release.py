#!/usr/bin/env python3
"""Release metadata for the tag-driven pipeline: version check and release notes.

Standard library only, so it runs on a CI runner with nothing installed and by
hand from the development venv alike:

    scripts/release.py check-version --tag v0.2.0   # fail unless pyproject agrees
    scripts/release.py notes --tag v0.2.0           # what the release body will be

Release notes come from the annotated tag's message. A lightweight tag falls
back to the one-line subjects of the commits since the previous tag. Publishing
itself is done by `gh release` in .github/workflows/release.yaml.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?$")


class ReleaseError(Exception):
    pass


# --- pure helpers -------------------------------------------------------------


def version_from_tag(tag: str) -> str:
    """``v0.2.0`` -> ``0.2.0``. Anything that is not ``vX.Y.Z[-pre]`` is refused."""
    if not tag.startswith("v"):
        raise ReleaseError(f"tag {tag!r} does not start with 'v' (expected e.g. v0.2.0)")
    version = tag[1:]
    if not VERSION_RE.match(version):
        raise ReleaseError(f"tag {tag!r} is not vX.Y.Z or vX.Y.Z-prerelease")
    return version


def is_prerelease(version: str) -> bool:
    return "-" in version


def project_version(pyproject: Path = PROJECT_ROOT / "pyproject.toml") -> str:
    with pyproject.open("rb") as handle:
        return tomllib.load(handle)["project"]["version"]


def check_version(tag: str, pyproject: Path = PROJECT_ROOT / "pyproject.toml") -> str:
    """The tag is the source of truth for the artefact name; the file must agree,
    otherwise a payload is labelled with a version its ``/health`` denies."""
    wanted = version_from_tag(tag)
    found = project_version(pyproject)
    if wanted != found:
        raise ReleaseError(
            f"tag {tag} says {wanted} but {pyproject.name} says {found}. "
            f"Bump the version (scripts/build_dist.py --version {wanted}) and re-tag."
        )
    return wanted


def _git(*args: str, cwd: Path = PROJECT_ROOT) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout


def release_notes(tag: str, cwd: Path = PROJECT_ROOT) -> str:
    """Annotated tag message, or the commit subjects since the previous tag."""
    annotation = _git(
        "for-each-ref", f"refs/tags/{tag}", "--format=%(contents)", cwd=cwd
    ).strip()
    # A lightweight tag has no contents of its own; for-each-ref then prints the
    # commit message, which we detect by comparing object types.
    objecttype = _git("for-each-ref", f"refs/tags/{tag}", "--format=%(objecttype)", cwd=cwd).strip()
    if objecttype == "tag" and annotation:
        return annotation

    previous = _git("describe", "--tags", "--abbrev=0", f"{tag}^", cwd=cwd).strip() if _has_previous_tag(tag, cwd) else None
    span = f"{previous}..{tag}" if previous else tag
    subjects = _git("log", "--format=- %s", span, cwd=cwd).strip()
    heading = f"Changes since {previous}" if previous else "Changes"
    return f"{heading}\n\n{subjects}\n" if subjects else f"{tag}\n"


def _has_previous_tag(tag: str, cwd: Path) -> bool:
    try:
        _git("describe", "--tags", "--abbrev=0", f"{tag}^", cwd=cwd)
        return True
    except subprocess.CalledProcessError:
        return False


# --- CLI ----------------------------------------------------------------------


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--tag", required=True, help="release tag, e.g. v0.2.0")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check-version", help="fail unless the tag matches pyproject.toml")
    _common(check)

    notes = sub.add_parser("notes", help="print the release notes that publish would use")
    _common(notes)


    args = parser.parse_args(argv)
    try:
        if args.command == "check-version":
            print(check_version(args.tag))
            return 0
        if args.command == "notes":
            print(release_notes(args.tag), end="")
            return 0

        raise ReleaseError(f"unknown command {args.command}")
    except ReleaseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
