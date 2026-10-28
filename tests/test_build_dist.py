"""The dist builder runs on any host, so its logic is testable here.

Guards the things that would otherwise ship a broken or leaky payload: PEP 508
marker selection (which platform pins survive for Windows), the staging allowlist
(which must never include the developer's config.toml), archive naming (which must
not collide across targets), the runtime/wheel-tag coupling, and the fact that the
installer uses the bundled runtime rather than discovering a system interpreter.
"""

from __future__ import annotations

import zipfile

import pytest

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


# --- bundled CPython runtime ----------------------------------------------


def test_runtime_package_mapping_covers_both_supported_platforms():
    assert build_dist.NUGET_RUNTIME_PACKAGES == {
        "win_amd64": "python",
        "win_arm64": "pythonarm64",
    }


def test_unsupported_platform_is_rejected_with_a_clear_message():
    """There is no 32-bit nuget CPython package, so fail at build time."""
    with pytest.raises(SystemExit) as excinfo:
        build_dist.runtime_package_for("win32")

    assert "win32" in str(excinfo.value)
    assert "win_arm64" in str(excinfo.value)


@pytest.mark.parametrize(
    ("runtime_version", "expected"),
    [("3.15.2", "3.15"), ("3.15", "3.15"), ("3.13.1", "3.13"), ("3.11.0", "3.11")],
)
def test_wheel_tag_is_derived_from_the_runtime_version(runtime_version, expected):
    """Deriving the tag is the point: wheels must match the bundled interpreter."""
    assert build_dist.wheel_tag_for(runtime_version) == expected


@pytest.mark.parametrize("bad", ["3", "latest", "", "3.x.1", None])
def test_malformed_runtime_version_is_rejected(bad):
    with pytest.raises(SystemExit):
        build_dist.wheel_tag_for(bad)


def test_default_runtime_version_yields_a_consistent_tag():
    tag = build_dist.wheel_tag_for(build_dist.DEFAULT_RUNTIME_VERSION)

    assert tag == ".".join(build_dist.DEFAULT_RUNTIME_VERSION.split(".")[:2])


def test_pip_is_bundled_so_bootstrap_has_an_offline_fallback():
    """ensurepip is primary, but the wheel must be present if it misbehaves."""
    joined = " ".join(build_dist.BUILD_BACKEND_PACKAGES).lower()

    assert "pip" in joined
    assert "setuptools" in joined


# --- installer must use the bundled runtime, not discover one --------------


def test_installer_does_not_discover_a_system_interpreter():
    """Regression guard: the payload is self-contained by design.

    Interpreter discovery is what makes the install depend on the Python Install
    Manager's per-user %LOCALAPPDATA% runtime, which a service account cannot
    rely on.
    """
    script = (build_dist.INSTALLER_DIR / "install.ps1").read_text()

    for forbidden in ("py.exe", "Get-Command python", "-m venv", "$PythonExecutable", "$PythonVersion"):
        assert forbidden not in script, f"install.ps1 still contains {forbidden!r}"


def test_installer_uses_the_bundled_runtime():
    script = (build_dist.INSTALLER_DIR / "install.ps1").read_text()

    assert "$RuntimeSrc" in script
    assert "'python'" in script, "the runtime directory is not copied into InstallDir"
    # install.ps1 composes the path with Join-Path rather than a literal.
    assert "Join-Path $RuntimeDir 'python.exe'" in script
    assert "-m ensurepip" in script
    # Every install step must go through the bundled interpreter.
    assert script.count("& $Python -m pip install") >= 3


def test_uninstaller_uses_the_bundled_runtime():
    script = (build_dist.INSTALLER_DIR / "uninstall.ps1").read_text()

    assert "python\\python.exe" in script
    assert ".venv" not in script


# --- dependency closure ----------------------------------------------------


def make_wheel(directory, name: str, version: str, requires=()) -> "Path":
    """A minimal wheel whose METADATA carries the given Requires-Dist lines."""
    from pathlib import Path as _P

    wheel = _P(directory) / f"{name}-{version}-py3-none-any.whl"
    dist_info = f"{name}-{version}.dist-info"
    metadata = ["Metadata-Version: 2.1", f"Name: {name}", f"Version: {version}"]
    metadata += [f"Requires-Dist: {r}" for r in requires]
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr(f"{dist_info}/METADATA", "\n".join(metadata) + "\n")
        zf.writestr(f"{dist_info}/WHEEL", "Wheel-Version: 1.0\n")
    return wheel


def closure(wheel_dir, platform="win_arm64"):
    return build_dist.verify_dependency_closure(
        wheel_dir, platform=platform, runtime_version="3.15.2"
    )


def test_closure_reports_a_windows_only_dependency_that_is_missing(tmp_path):
    """The exact failure that broke the first real offline install."""
    make_wheel(tmp_path, "pytest", "9.2.0", requires=['colorama>=0.4; sys_platform == "win32"'])

    missing = closure(tmp_path)

    assert "colorama" in missing
    assert any("pytest requires" in reason for reason in missing["colorama"])


def test_closure_is_satisfied_when_the_dependency_is_bundled(tmp_path):
    make_wheel(tmp_path, "pytest", "9.2.0", requires=['colorama>=0.4; sys_platform == "win32"'])
    make_wheel(tmp_path, "colorama", "0.4.6")

    assert closure(tmp_path) == {}


def test_closure_ignores_unix_only_dependencies(tmp_path):
    """The inverse case must not produce a false positive."""
    make_wheel(tmp_path, "uvicorn", "0.54.0", requires=['uvloop>=0.15; sys_platform != "win32"'])

    assert closure(tmp_path) == {}


def test_closure_honours_requested_extras(tmp_path):
    """pydantic[email] is used, so email-validator counts as required."""
    make_wheel(
        tmp_path, "pydantic", "2.14.1",
        requires=['email-validator>=2.0.0; extra == "email"'],
    )

    assert "email-validator" in closure(tmp_path)


def test_closure_ignores_extras_that_are_not_requested(tmp_path):
    make_wheel(
        tmp_path, "uvicorn", "0.54.0",
        requires=['watchfiles>=0.20; extra == "standard"'],
    )

    assert closure(tmp_path) == {}


def test_closure_normalizes_underscores_and_case(tmp_path):
    """pydantic_core and Pydantic-Core are the same distribution."""
    make_wheel(tmp_path, "pydantic", "2.14.1", requires=["Pydantic-Core>=2.14.1"])
    make_wheel(tmp_path, "pydantic_core", "2.50.1")

    assert closure(tmp_path) == {}


def test_requirements_pin_the_windows_only_transitive_dep():
    """`pip freeze` on Linux can never emit this line, so guard it explicitly."""
    text = (build_dist.PROJECT_ROOT / "requirements.txt").read_text()
    lines = [ln for ln in text.splitlines() if ln.strip().lower().startswith("colorama")]

    assert lines, "colorama is missing from requirements.txt"
    assert "sys_platform == 'win32'" in lines[0]
