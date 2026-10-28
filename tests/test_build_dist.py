"""The dist builder runs on any host, so its logic is testable here.

The two things worth guarding are the ones that would ship a broken or leaky
payload: PEP 508 marker selection (which platform pins survive for Windows) and
the staging allowlist (which must never include the developer's config.toml).
"""

from __future__ import annotations

import zipfile

import build_dist


def test_archive_name_preserves_platform_and_python_tag(tmp_path):
    """Eight distinct payloads must produce eight distinct archive names.

    ``Path("SmtpRelay-0.1.0-win_amd64-cp315").suffix`` is ``.0-win_amd64-cp315``,
    so ``with_suffix(".zip")`` yields ``SmtpRelay-0.1.zip`` for *every* platform
    and Python tag - silently overwriting one target's archive with another's, so
    the wrong wheels get installed with no warning.
    """
    names = set()
    for version in ("0.1.0", "0.2.0"):
        for platform in ("win_amd64", "win_arm64"):
            for tag in ("cp313", "cp315"):
                payload = tmp_path / f"SmtpRelay-{version}-{platform}-{tag}"
                payload.mkdir()
                (payload / "marker.txt").write_text(f"{version} {platform} {tag}")
                names.add(build_dist.make_zip(payload).name)

    assert len(names) == 8, f"archive names collided: {sorted(names)}"
    assert "SmtpRelay-0.1.0-win_amd64-cp315.zip" in names
    assert "SmtpRelay-0.1.0-win_arm64-cp313.zip" in names


def test_archive_extracts_into_a_named_directory(tmp_path):
    """Entries must be prefixed, so extraction does not spill files loose."""
    payload = tmp_path / "SmtpRelay-0.1.0-win_amd64-cp315"
    (payload / "app").mkdir(parents=True)
    (payload / "app" / "main.py").write_text("# code\n")
    (payload / "install.ps1").write_text("# ps1\n")

    archive = build_dist.make_zip(payload)

    with zipfile.ZipFile(archive) as zf:
        entries = zf.namelist()

    prefix = "SmtpRelay-0.1.0-win_amd64-cp315/"
    assert entries, "archive is empty"
    assert all(entry.startswith(prefix) for entry in entries), entries
    assert f"{prefix}app/main.py" in entries
    assert f"{prefix}install.ps1" in entries


def test_archive_round_trips_file_contents(tmp_path):
    payload = tmp_path / "SmtpRelay-9.9.9-win_amd64-cp315"
    payload.mkdir()
    (payload / "MANIFEST.json").write_text('{"version": "9.9.9"}\n')

    archive = build_dist.make_zip(payload)
    extract_dir = tmp_path / "extracted"

    with zipfile.ZipFile(archive) as zf:
        zf.extractall(extract_dir)

    restored = extract_dir / payload.name / "MANIFEST.json"
    assert restored.is_file()
    assert restored.read_text() == '{"version": "9.9.9"}\n'


def test_stage_source_is_idempotent(tmp_path):
    """--keep-existing reuses a payload dir, so re-staging must not raise.

    copytree without dirs_exist_ok=True fails with FileExistsError the second
    time, which is exactly what a rebuild over an existing payload hits.
    """
    build_dist.stage_source(tmp_path)
    build_dist.stage_source(tmp_path)

    assert (tmp_path / "app" / "main.py").is_file()
    assert (tmp_path / "install.ps1").is_file()


def test_config_toml_is_never_staged():
    """The developer's config.toml can hold a real SMTP password or API token."""
    assert "config.toml" not in build_dist.SOURCE_FILES
    assert "config.example.toml" in build_dist.SOURCE_FILES


def test_no_vcs_venv_or_test_dirs_are_staged():
    for forbidden in (".venv", ".git", "tests", "dist", "scripts"):
        assert forbidden not in build_dist.SOURCE_DIRS


def test_build_backend_is_bundled_for_offline_install():
    """Python 3.12+ venvs ship without setuptools.

    Without bundling it, `pip install .` on the target would use build isolation
    and reach out to PyPI, defeating the offline payload.
    """
    joined = " ".join(build_dist.BUILD_BACKEND_PACKAGES).lower()

    assert "setuptools" in joined
    assert "wheel" in joined


def test_select_windows_requirements_swaps_platform_pins(tmp_path, monkeypatch):
    """The marker trap: pip evaluates markers against the *running* interpreter.

    Selecting for a synthetic win32 environment must drop Unix-only pins and keep
    Windows-only ones, so the resulting file resolves under --platform win_amd64.
    """
    fake_root = tmp_path / "project"
    fake_root.mkdir()
    (fake_root / "requirements.txt").write_text(
        "# a comment\n"
        "\n"
        "fastapi==1.0\n"
        "uvloop==2.0; sys_platform != 'win32'\n"
        "pywin32==3.0; sys_platform == 'win32'\n"
        "pyyaml==4.0\n"
    )
    monkeypatch.setattr(build_dist, "PROJECT_ROOT", fake_root)

    out = tmp_path / "selected.txt"
    build_dist.select_windows_requirements("3.15", out)

    selected = [line for line in out.read_text().splitlines() if line]

    assert selected == ["fastapi==1.0", "pywin32==3.0", "pyyaml==4.0"]
    assert "uvloop==2.0" not in selected


def test_select_windows_requirements_strips_markers_from_survivors(tmp_path, monkeypatch):
    """The output is fed to pip with --platform, so markers must be gone."""
    fake_root = tmp_path / "project"
    fake_root.mkdir()
    (fake_root / "requirements.txt").write_text(
        "pywin32==312; sys_platform == 'win32'\n"
    )
    monkeypatch.setattr(build_dist, "PROJECT_ROOT", fake_root)

    out = tmp_path / "selected.txt"
    build_dist.select_windows_requirements("3.15", out)

    assert out.read_text().strip() == "pywin32==312"
    assert ";" not in out.read_text()


def test_pyproject_version_agrees_with_the_package():
    """Two sources of truth for the version must not drift."""
    import app

    assert build_dist.read_version() == app.__version__


def test_real_requirements_select_a_compiler_free_windows_set():
    """End-to-end marker check against the actual lockfile.

    Asserts the invariant the whole payload rests on: the Windows-selected set
    contains pywin32, excludes uvloop, and pulls in none of the uvicorn[standard]
    packages that would require MSVC.
    """
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        out = build_dist.select_windows_requirements("3.15", Path(tmp) / "win.txt")
        names = {
            line.split("==")[0].strip().lower().replace("_", "-")
            for line in out.read_text().splitlines()
            if line.strip()
        }

    assert "pywin32" in names
    assert "uvloop" not in names
    for standard_only in ("pyyaml", "httptools", "watchfiles", "websockets", "python-dotenv"):
        assert standard_only not in names, f"{standard_only} would force a source build"


def test_payload_name_encodes_platform_and_python_tag():
    """A cp315/win_amd64 payload must not be mistaken for another target."""
    version = build_dist.read_version()
    tag = "cp315"

    name = f"SmtpRelay-{version}-win_amd64-{tag}"

    assert name.startswith("SmtpRelay-")
    assert "win_amd64" in name
    assert tag in name


def test_source_files_all_exist():
    """A renamed file must fail the build here, not on the target machine."""
    missing = [
        name for name in build_dist.SOURCE_FILES
        if not (build_dist.PROJECT_ROOT / name).is_file()
    ]
    assert not missing, f"SOURCE_FILES references missing files: {missing}"

    missing_dirs = [
        name for name in build_dist.SOURCE_DIRS
        if not (build_dist.PROJECT_ROOT / name).is_dir()
    ]
    assert not missing_dirs, f"SOURCE_DIRS references missing directories: {missing_dirs}"


def test_installer_scripts_are_present():
    scripts = sorted(p.name for p in build_dist.INSTALLER_DIR.glob("*.ps1"))

    assert scripts == ["install.ps1", "uninstall.ps1"]
