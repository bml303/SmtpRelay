#!/usr/bin/env python3
"""Publish a Gitea release for a tag from the payloads in ``dist/``.

Standard library only, so it runs on a CI runner with nothing installed and by
hand from the development venv alike:

    GITEA_TOKEN=... scripts/publish_release.py publish --tag v0.2.0 \\
        dist/SmtpRelay-0.2.0-*.zip dist/SHA256SUMS

    scripts/publish_release.py check-version --tag v0.2.0
    scripts/publish_release.py notes --tag v0.2.0

Idempotent: an existing release for the tag is updated, and an asset with the
same name as one being uploaded is replaced rather than duplicated, so a re-run
after a partial failure converges instead of erroring.

Release notes come from the annotated tag's message. A lightweight tag falls
back to the one-line subjects of the commits since the previous tag.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import re
import subprocess
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TOKEN_ENV = "GITEA_TOKEN"

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


def split_repo(slug: str) -> tuple[str, str]:
    owner, _, name = slug.partition("/")
    if not owner or not name or "/" in name:
        raise ReleaseError(f"--repo must be owner/name, got {slug!r}")
    return owner, name


def repo_from_git_remote(cwd: Path = PROJECT_ROOT) -> tuple[str, str]:
    """``git@host:owner/name.git`` or ``https://host/owner/name(.git)`` -> owner, name."""
    url = _git("remote", "get-url", "origin", cwd=cwd).strip()
    return split_repo(repo_slug_from_url(url))


def repo_slug_from_url(url: str) -> str:
    path = url.rsplit(":", 1)[-1] if url.startswith("git@") else urllib.parse.urlparse(url).path
    path = path.strip("/")
    if path.endswith(".git"):
        path = path[: -len(".git")]
    return path


def server_from_git_remote(cwd: Path = PROJECT_ROOT) -> str:
    url = _git("remote", "get-url", "origin", cwd=cwd).strip()
    if url.startswith("git@"):
        host = url[len("git@"):].split(":", 1)[0]
        return f"https://{host}"
    parsed = urllib.parse.urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


# --- release notes ------------------------------------------------------------


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


# --- Gitea API ----------------------------------------------------------------


class Gitea:
    def __init__(self, server: str, owner: str, repo: str, token: str) -> None:
        self.base = f"{server.rstrip('/')}/api/v1/repos/{owner}/{repo}"
        self.token = token

    def _request(self, method: str, path: str, *, body: bytes | None = None, content_type: str | None = None, query: dict[str, str] | None = None):
        url = self.base + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        request = urllib.request.Request(url, data=body, method=method)
        request.add_header("Authorization", f"token {self.token}")
        request.add_header("Accept", "application/json")
        if content_type:
            request.add_header("Content-Type", content_type)
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                raw = response.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            detail = exc.read().decode(errors="replace")[:500]
            raise ReleaseError(f"{method} {url} -> HTTP {exc.code}: {detail}") from exc

    def _json(self, method: str, path: str, payload: dict):
        return self._request(method, path, body=json.dumps(payload).encode(), content_type="application/json")

    def release_by_tag(self, tag: str) -> dict | None:
        return self._request("GET", f"/releases/tags/{urllib.parse.quote(tag)}")

    def ensure_release(self, tag: str, title: str, notes: str, prerelease: bool) -> dict:
        existing = self.release_by_tag(tag)
        payload = {"tag_name": tag, "name": title, "body": notes, "draft": False, "prerelease": prerelease}
        if existing is None:
            print(f"  creating release {tag}")
            return self._json("POST", "/releases", payload)
        print(f"  updating release {tag} (id {existing['id']})")
        return self._json("PATCH", f"/releases/{existing['id']}", payload)

    def replace_asset(self, release: dict, path: Path) -> None:
        for asset in release.get("assets") or []:
            if asset["name"] == path.name:
                print(f"  replacing existing asset {path.name}")
                self._request("DELETE", f"/releases/{release['id']}/assets/{asset['id']}")
        boundary = uuid.uuid4().hex
        mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        head = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="attachment"; filename="{path.name}"\r\n'
            f"Content-Type: {mime}\r\n\r\n"
        ).encode()
        body = head + path.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
        print(f"  uploading {path.name} ({path.stat().st_size:,} bytes)")
        self._request(
            "POST",
            f"/releases/{release['id']}/assets",
            body=body,
            content_type=f"multipart/form-data; boundary={boundary}",
            query={"name": path.name},
        )


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

    publish = sub.add_parser("publish", help="create/update the release and upload assets")
    _common(publish)
    publish.add_argument("assets", nargs="*", type=Path, help="files to attach")
    publish.add_argument("--server", help="Gitea base URL (default: from the origin remote)")
    publish.add_argument("--repo", help="owner/name (default: from the origin remote)")
    publish.add_argument("--title", help="release title (default: 'SMTP Relay <version>')")
    publish.add_argument("--notes-file", type=Path, help="release notes (default: tag annotation)")

    args = parser.parse_args(argv)
    try:
        if args.command == "check-version":
            print(check_version(args.tag))
            return 0
        if args.command == "notes":
            print(release_notes(args.tag), end="")
            return 0

        version = version_from_tag(args.tag)
        token = os.environ.get(TOKEN_ENV)
        if not token:
            raise ReleaseError(f"{TOKEN_ENV} is not set")
        missing = [str(p) for p in args.assets if not p.is_file()]
        if missing:
            raise ReleaseError("asset not found: " + ", ".join(missing))

        server = args.server or server_from_git_remote()
        owner, repo = split_repo(args.repo) if args.repo else repo_from_git_remote()
        body = args.notes_file.read_text() if args.notes_file else release_notes(args.tag)
        title = args.title or f"SMTP Relay {version}"

        print(f"Publishing {args.tag} to {server}/{owner}/{repo}")
        api = Gitea(server, owner, repo, token)
        release = api.ensure_release(args.tag, title, body, is_prerelease(version))
        for path in args.assets:
            api.replace_asset(release, path)
        print(f"Done: {release.get('html_url', '')}")
        return 0
    except ReleaseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
