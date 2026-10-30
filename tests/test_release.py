"""The release publisher's offline logic: tag parsing, the tag/pyproject
agreement check, remote parsing and note generation. The API client itself is
exercised by the release workflow, not here."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import release as pr


@pytest.mark.parametrize(
    "tag, version, pre",
    [("v0.2.0", "0.2.0", False), ("v1.0.0-rc.1", "1.0.0-rc.1", True), ("v10.20.30", "10.20.30", False)],
)
def test_version_from_tag(tag, version, pre):
    assert pr.version_from_tag(tag) == version
    assert pr.is_prerelease(version) is pre


@pytest.mark.parametrize("tag", ["0.2.0", "v0.2", "release-1", "v0.2.0.1", "vlatest"])
def test_malformed_tags_are_refused(tag):
    with pytest.raises(pr.ReleaseError):
        pr.version_from_tag(tag)


def test_check_version_requires_agreement(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nname = "x"\nversion = "0.2.0"\n')

    assert pr.check_version("v0.2.0", pyproject) == "0.2.0"
    with pytest.raises(pr.ReleaseError) as excinfo:
        pr.check_version("v0.3.0", pyproject)
    assert "0.3.0" in str(excinfo.value) and "0.2.0" in str(excinfo.value)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        cwd=repo, check=True, capture_output=True,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "a").write_text("1")
    _git(tmp_path, "add", "a")
    _git(tmp_path, "commit", "-q", "-m", "first commit")
    _git(tmp_path, "tag", "-a", "v0.1.0", "-m", "0.1.0 notes")
    (tmp_path / "a").write_text("2")
    _git(tmp_path, "commit", "-q", "-am", "second change")
    (tmp_path / "a").write_text("3")
    _git(tmp_path, "commit", "-q", "-am", "third change")
    return tmp_path


def test_annotated_tag_message_is_the_release_notes(repo):
    _git(repo, "tag", "-a", "v0.2.0", "-m", "Release 0.2.0\n\n- did things")

    assert pr.release_notes("v0.2.0", cwd=repo) == "Release 0.2.0\n\n- did things"


def test_lightweight_tag_falls_back_to_commit_subjects_since_previous_tag(repo):
    _git(repo, "tag", "v0.2.0")

    notes = pr.release_notes("v0.2.0", cwd=repo)

    assert notes.startswith("Changes since v0.1.0")
    assert "- third change" in notes and "- second change" in notes
    assert "first commit" not in notes


def test_first_lightweight_tag_lists_everything(tmp_path):
    _git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "a").write_text("1")
    _git(tmp_path, "add", "a")
    _git(tmp_path, "commit", "-q", "-m", "only commit")
    _git(tmp_path, "tag", "v0.1.0")

    notes = pr.release_notes("v0.1.0", cwd=tmp_path)

    assert notes.startswith("Changes\n") and "- only commit" in notes
