"""The dist builder runs on any host, so its logic is testable here.

Guards the things that would otherwise ship a broken or leaky payload: PEP 508
marker selection (which platform pins survive for Windows), the staging allowlist
(which must never include the developer's config.toml), archive naming (which must
not collide across targets), the runtime/wheel-tag coupling, and the fact that the
installer uses the bundled runtime rather than discovering a system interpreter.
"""

from __future__ import annotations

import re
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
    # Not the `wheel` package: setuptools >= 70.1 builds wheels itself, and
    # wheel 0.48 would pull `packaging` into every payload for nothing.
    assert "wheel" not in joined.split()


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
    # app/tls.py (PKCS#12 and the Windows certificate store) and its closure.
    assert {"cryptography", "cffi", "pycparser"} <= names


def test_cryptography_is_pinned_where_win_arm64_still_has_a_wheel():
    """47+ publishes no win_arm64 wheel; a bump would break that payload's build.

    The pin is deliberately one version for every target so each release has a
    single SBOM entry for it. Lift this test when a newer win_arm64 wheel exists.
    """
    pins = {
        line.split("==")[0].strip(): line.split("==")[1].split(";")[0].strip()
        for line in (build_dist.PROJECT_ROOT / "requirements.txt").read_text().splitlines()
        if "==" in line and not line.lstrip().startswith("#")
    }
    major = int(pins["cryptography"].split(".")[0])
    assert major == 46, f"cryptography {pins['cryptography']}: check win_arm64 wheels before bumping"


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


# --- version bumping -------------------------------------------------------


@pytest.mark.parametrize(
    ("current", "expected"),
    [("0.1.0", "0.1.1"), ("0.1.9", "0.1.10"), ("1.2.3", "1.2.4"), ("0.0.0", "0.0.1")],
)
def test_bump_version_increments_the_patch_component(current, expected):
    assert build_dist.bump_version(current) == expected


@pytest.mark.parametrize("bad", ["0.1", "1.2.3.4", "v1.2.3", "latest", "", "0.1.x", None])
def test_bump_version_rejects_anything_that_is_not_three_numeric_parts(bad):
    with pytest.raises(SystemExit):
        build_dist.bump_version(bad)


def _versioned_tree(root):
    (root / "app").mkdir()
    (root / "pyproject.toml").write_text(
        '[project]\nname = "smtp-relay"\nversion = "0.1.0"\n'
        'requires-python = ">=3.11"\ndependencies = ["fastapi>=0.115"]\n'
    )
    (root / "app" / "__init__.py").write_text('"""Doc."""\n\n__version__ = "0.1.0"\n')
    return root


def test_write_version_keeps_both_sources_in_sync(tmp_path):
    """/health reports app.__version__; the payload name comes from pyproject."""
    root = _versioned_tree(tmp_path)

    build_dist.write_version("9.9.9", root)

    assert 'version = "9.9.9"' in (root / "pyproject.toml").read_text()
    assert '__version__ = "9.9.9"' in (root / "app" / "__init__.py").read_text()


def test_write_version_leaves_other_version_strings_alone(tmp_path):
    root = _versioned_tree(tmp_path)

    build_dist.write_version("0.2.0", root)

    text = (root / "pyproject.toml").read_text()
    assert 'requires-python = ">=3.11"' in text
    assert "fastapi>=0.115" in text
    assert text.count('version = "0.2.0"') == 1


def test_write_version_is_atomic_across_both_files(tmp_path):
    """A missing pattern must not leave pyproject and __init__ disagreeing."""
    root = tmp_path
    (root / "app").mkdir()
    # Single quotes: the double-quoted pattern will not match.
    (root / "pyproject.toml").write_text("[project]\nversion = '0.1.0'\n")
    init = root / "app" / "__init__.py"
    init.write_text('__version__ = "0.1.0"\n')

    with pytest.raises(SystemExit):
        build_dist.write_version("1.0.0", root)

    assert init.read_text() == '__version__ = "0.1.0"\n', "second file was written despite the first failing"


def test_project_version_sources_currently_agree():
    """The invariant write_version maintains, checked against the real tree."""
    import app

    assert build_dist.read_version() == app.__version__


def test_installer_scripts_are_present():
    windows = sorted(p.name for p in build_dist.WINDOWS_INSTALLER_DIR.iterdir())
    linux = sorted(p.name for p in build_dist.LINUX_INSTALLER_DIR.iterdir())

    assert windows == ["README.txt", "install.ps1", "uninstall.ps1"]
    assert linux == ["README.txt", "install.sh", "smtp-relay.service", "uninstall.sh"]


@pytest.mark.parametrize("platform", ["win_arm64", "linux_x86_64"])
def test_every_installer_file_is_staged_into_the_payload_root(tmp_path, platform):
    files = build_dist.installer_files(build_dist.target_for(platform))

    assert all(f.is_file() for f in files), files
    assert "README.txt" in {f.name for f in files}


@pytest.mark.parametrize(
    ("readme", "uninstaller"),
    [
        (build_dist.WINDOWS_INSTALLER_DIR / "README.txt", "uninstall.ps1"),
        (build_dist.LINUX_INSTALLER_DIR / "README.txt", "uninstall.sh"),
    ],
)
def test_payload_readme_covers_install_check_and_uninstall(readme, uninstaller):
    """The README.txt is what an operator without the repository sees first."""
    text = readme.read_text()

    for heading in ("Install", "Configure", "Check before starting", "Upgrade", "Uninstall", "Logs"):
        assert f"\n{heading}\n" in text, f"{readme.name} lacks a '{heading}' section"
    assert "-m app --check" in text
    assert "NOTHING IS SENT" in text
    assert uninstaller in text
    # Plain text for Notepad and less alike: ASCII only, no line beyond 80 columns.
    assert text.isascii()
    assert max(len(line) for line in text.splitlines()) <= 120


def test_targets_cover_both_families_and_archive_kinds():
    assert set(build_dist.TARGETS) == {"win_amd64", "win_arm64", "linux_x86_64", "linux_aarch64"}
    for name, target in build_dist.TARGETS.items():
        assert target.family == ("windows" if name.startswith("win_") else "linux")
        assert target.archive == ("zip" if target.family == "windows" else "tar.gz")
    # Linux wheels: glibc-tagged manylinux first, generic linux last.
    assert build_dist.TARGETS["linux_x86_64"].pip_platforms[0].startswith("manylinux_2_28")
    assert build_dist.TARGETS["linux_x86_64"].pip_platforms[-1] == "linux_x86_64"


def test_select_requirements_for_linux_drops_the_windows_pins(tmp_path, monkeypatch):
    fake_root = tmp_path / "project"
    fake_root.mkdir()
    (fake_root / "requirements.txt").write_text(
        "fastapi==1.0\n"
        "pywin32==3.0; sys_platform == 'win32'\n"
        "colorama==0.4.6; sys_platform == 'win32'\n"
        "uvloop==2.0; sys_platform != 'win32'\n"
    )
    monkeypatch.setattr(build_dist, "PROJECT_ROOT", fake_root)
    out = tmp_path / "linux.txt"

    build_dist.select_requirements("linux_aarch64", "3.15", out)

    assert out.read_text().split() == ["fastapi==1.0", "uvloop==2.0"]


def test_linux_payload_is_staged_with_executable_scripts_and_the_unit(tmp_path):
    build_dist.stage_source(tmp_path, "linux_x86_64")

    assert (tmp_path / "install.sh").stat().st_mode & 0o111
    assert (tmp_path / "uninstall.sh").stat().st_mode & 0o111
    assert (tmp_path / "smtp-relay.service").is_file()
    assert not (tmp_path / "install.ps1").exists()


def test_tarball_preserves_name_and_prefix(tmp_path):
    import tarfile
    payload = tmp_path / "SmtpRelay-0.3.0-linux_x86_64-cp315"
    payload.mkdir()
    (payload / "install.sh").write_text("#!/bin/sh\n")
    (payload / "install.sh").chmod(0o755)

    archive = build_dist.make_archive(payload, "linux_x86_64")

    assert archive.name == "SmtpRelay-0.3.0-linux_x86_64-cp315.tar.gz"
    with tarfile.open(archive) as tf:
        member = tf.getmember("SmtpRelay-0.3.0-linux_x86_64-cp315/install.sh")
    assert member.mode & 0o111, "executable bit lost"


def test_marker_environment_matches_the_target():
    win = build_dist.marker_environment("win_arm64", "3.15.2")
    lin = build_dist.marker_environment("linux_aarch64", "3.15.2")

    assert (win["sys_platform"], win["os_name"], win["platform_machine"]) == ("win32", "nt", "ARM64")
    assert (lin["sys_platform"], lin["os_name"], lin["platform_machine"]) == ("linux", "posix", "aarch64")
    assert win["python_version"] == lin["python_version"] == "3.15"
    assert lin["python_full_version"] == "3.15.2"


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
    script = (build_dist.WINDOWS_INSTALLER_DIR / "install.ps1").read_text()

    for forbidden in ("py.exe", "Get-Command python", "-m venv", "$PythonExecutable", "$PythonVersion"):
        assert forbidden not in script, f"install.ps1 still contains {forbidden!r}"


def test_installer_uses_the_bundled_runtime():
    script = (build_dist.WINDOWS_INSTALLER_DIR / "install.ps1").read_text()

    assert "$RuntimeSrc" in script
    assert "'python'" in script, "the runtime directory is not copied into InstallDir"
    # install.ps1 composes the path with Join-Path rather than a literal.
    assert "Join-Path $RuntimeDir 'python.exe'" in script
    assert "-m ensurepip" in script
    # Every install step must go through the bundled interpreter.
    assert script.count("& $Python -m pip install") >= 3


def test_installer_grants_acls_via_dotnet_not_icacls():
    """icacls cannot grant to a virtual service SID, in any syntax.

    Even the documented ``*S-1-5-80-...`` numeric form fails with 1332
    ERROR_NONE_MAPPED, because icacls performs its own SID->name lookup and a
    virtual service SID has no name in the account database. Confirmed on a real
    Windows 11 ARM64 host with SERVICE_SID_TYPE already UNRESTRICTED, and with the
    ``NT SERVICE\\<name>`` form as well. The .NET ACL API takes a
    SecurityIdentifier object and never calls LookupAccountSid.
    """
    script = (build_dist.WINDOWS_INSTALLER_DIR / "install.ps1").read_text()

    assert not re.search(r"&\s+icacls\.exe", script), (
        "icacls cannot resolve a virtual service SID; use Get-Acl/Set-Acl"
    )
    for required in (
        "System.Security.Principal.SecurityIdentifier",
        "System.Security.AccessControl.FileSystemAccessRule",
        "AddAccessRule",
        "Get-Acl",
        "Set-Acl",
    ):
        assert required in script, f"missing {required}"

    # Well-known SIDs for SYSTEM and Administrators, not localized names - the
    # latter fail on non-English Windows.
    assert "S-1-5-18" in script
    assert "S-1-5-32-544" in script


def test_config_dir_acls_protect_secrets_without_locking_out_admins():
    """Stripping inheritance must be paired with explicit SYSTEM+Admins grants.

    Otherwise Set-Acl can leave a directory nobody but the service can open -
    including the administrator who has to edit config.toml.
    """
    script = (build_dist.WINDOWS_INSTALLER_DIR / "install.ps1").read_text()

    assert "SetAccessRuleProtection($true, $false)" in script
    # The three grants must all be present and applied before Set-Acl.
    for rights in ("'FullControl'", "'Read'", "'ReadAndExecute'"):
        assert rights in script, f"missing grant {rights}"
    assert script.index("SetAccessRuleProtection") < script.index("Set-Acl -Path $ConfigDir")


def test_installer_resolves_service_sid_with_sc_showsid_and_confirms_with_lsa():
    """`sc.exe showsid` computes the virtual SID from the name; LSA must agree.

    The LSA lookup is the same one the SCM performs at logon. On Windows 11
    build 28000 ARM64 it failed with 1332 ERROR_NONE_MAPPED for a service whose
    account had been set after creation, and the service then failed to start
    with 1069 / System event 7038. Checking it at install time turns that into
    an installer error with the cause named, instead of a start failure later.
    """
    script = (build_dist.WINDOWS_INSTALLER_DIR / "install.ps1").read_text()

    assert "sc.exe showsid" in script, "SID must come from sc.exe showsid"
    assert "S-1-5-80-" in script, "the virtual-service SID prefix is not matched"
    assert "Translate([System.Security.Principal.SecurityIdentifier])" in script
    assert "7038" in script, "the LSA failure must be explained in the SCM's own terms"
    assert "REBOOT" in script, "the one known remedy must be in the error text"
    # LSA check happens after the SID type is set and before anything is granted.
    assert script.index("sc.exe sidtype") < script.index("$lsaSid") < script.index("Set-Acl")
    # The SID feeds a SecurityIdentifier object, not an icacls "*SID" string.
    assert "SecurityIdentifier($serviceSid)" in script


def test_installer_sets_the_account_at_creation_not_afterwards():
    """Every install is a clean registration with the account in CreateService.

    pywin32's --username reaches CreateService directly, so the account travels
    with `install`. An existing service must be deleted first: pywin32 would
    otherwise fall through to `update` and patch the account into a service
    whose previous logon state is unknown. (The 1069 / event 7038 failure that
    prompted this turned out to be LSA host state cleared by a reboot; see the
    LSA check test. The clean registration is kept as the canonical form.)
    """
    script = (build_dist.WINDOWS_INSTALLER_DIR / "install.ps1").read_text()

    assert "--username $ServiceAccount" in script
    assert "--username $ServiceAccount --startup auto install" in script
    code = "\n".join(l for l in script.splitlines() if not l.lstrip().startswith("#"))
    assert "obj=" not in code, "the account must not be set after creation"
    # Existing service handling precedes registration.
    assert script.index("sc.exe delete $ServiceName") < script.index("--username $ServiceAccount")
    assert "Get-Service -Name $ServiceName" in script


def test_installer_sets_service_sid_type_unrestricted():
    """Without this, every ACL grant to the virtual SID is inert.

    CreateService leaves SERVICE_SID_TYPE at NONE, so the service process never
    carries the virtual SID in its token. It must be set explicitly and read
    back, before any grant.
    """
    script = (build_dist.WINDOWS_INSTALLER_DIR / "install.ps1").read_text()

    assert "sc.exe sidtype $ServiceName unrestricted" in script
    # Must happen before any grant, and be read back rather than assumed.
    assert script.index("sc.exe sidtype") < script.index("SecurityIdentifier")
    assert "qsidtype" in script, "SERVICE_SID_TYPE is never verified after being set"


def test_installer_confirms_the_service_account_took_effect():
    """A silently-ignored account surfaces later as a permissions or logon failure."""
    script = (build_dist.WINDOWS_INSTALLER_DIR / "install.ps1").read_text()

    assert "sc.exe qc" in script
    assert "SERVICE_START_NAME" in script


def test_acl_failure_is_fatal_not_a_warning():
    """Without these grants the service cannot read its runtime or config."""
    script = (build_dist.WINDOWS_INSTALLER_DIR / "install.ps1").read_text()

    assert "$aclFailures" in script
    assert "Stop-WithError" in script.split("$aclFailures.Count")[1][:400]


def test_installer_imports_the_pfx_with_an_exportable_key():
    """The service exports the key through CryptoAPI at start (OpenSSL cannot
    use a CNG handle), so a non-exportable import would only fail at runtime."""
    script = (build_dist.WINDOWS_INSTALLER_DIR / "install.ps1").read_text()

    assert "Import-PfxCertificate" in script
    assert "Exportable = $true" in script
    assert "CertStoreLocation = $storePath" in script and "Cert:\\LocalMachine\\My" in script
    # A pre-existing certificate (-CertThumbprint) is checked for the same property.
    assert "CngExportPolicies]::AllowExport" in script
    assert "CspKeyContainerInfo.Exportable" in script
    assert "NOT exportable" in script


def test_installer_grants_the_private_key_to_the_service_sid_via_dotnet():
    """Same constraint as the directory ACLs: icacls cannot address a virtual
    service SID, so the key file is granted through FileSystemAccessRule."""
    script = (build_dist.WINDOWS_INSTALLER_DIR / "install.ps1").read_text()
    step = script[script.index("API TLS certificate"):script.index("# ------------------------------------------------------------------ firewall")]

    assert "Microsoft\\Crypto" in step, "key files live under ProgramData\\Microsoft\\Crypto"
    assert "Key.UniqueName" in step and "UniqueKeyContainerName" in step, "both CNG and CAPI key files"
    assert "FileSystemAccessRule" in step and "$sidObj" in step
    assert "FileSystemRights]::Read" in step
    assert not re.search(r"^\s*(&\s*)?icacls", step, re.M), "icacls must not be invoked on the key"


def test_installer_points_config_at_the_imported_certificate():
    script = (build_dist.WINDOWS_INSTALLER_DIR / "install.ps1").read_text()
    step = script[script.index("API TLS certificate"):script.index("# ------------------------------------------------------------------ firewall")]

    assert 'ssl_cert_thumbprint = `"$($certificate.Thumbprint)`"' in step
    # Replaces a commented template line, else inserts under [api]; never duplicates.
    assert "#?[ \\t]*ssl_cert_thumbprint" in step
    assert "^\\[api\\][ \\t]*$" in step
    # Warns about a conflicting second source instead of leaving a service that cannot start.
    assert "'ssl_certfile', 'ssl_pfxfile'" in step


def test_installer_validates_certificate_switches_before_changing_anything():
    """A bad -PfxPath or thumbprint, or the passphrase prompt, must come before
    the install directory is touched, so a typo cannot half-install the service."""
    script = (build_dist.WINDOWS_INSTALLER_DIR / "install.ps1").read_text()

    checks = script.index("-PfxPath and -CertThumbprint are mutually exclusive")
    prompt = script.index("Read-Host -Prompt")
    first_change = script.index('Write-Step "Preparing $InstallDir"')
    assert checks < first_change and prompt < first_change
    assert "-AsSecureString" in script, "the passphrase must not be read as plain text"
    assert "[securestring] $PfxPassword" in script


def test_uninstaller_uses_the_bundled_runtime():
    script = (build_dist.WINDOWS_INSTALLER_DIR / "uninstall.ps1").read_text()

    assert "python\\python.exe" in script
    assert ".venv" not in script


def test_installer_scripts_have_valid_powershell_syntax():
    """A parse error means the script never runs - not even its first line.

    Three PowerShell bugs shipped before this guard existed. The last was
    `$ServiceName:(OI)(CI)RX` inside a hint string: PowerShell reads `$Name:` as a
    drive-qualified variable reference and rejects the whole file, so the target
    saw a wall of parser output and the installer did nothing at all.
    """
    if build_dist.find_pwsh() is None:
        pytest.skip("no pwsh available; set PWSH=/path/to/pwsh to enable this check")

    scripts = sorted(build_dist.INSTALLER_DIR.glob("*.ps1"))
    assert scripts, "no installer scripts found"

    # Raises SystemExit if any script fails to parse.
    build_dist.validate_powershell_syntax(scripts)


def test_uninstaller_removes_every_artifact_the_installer_creates():
    """A clean-slate reinstall must leave no residue behind.

    Deleting a service does NOT remove its Event Log source registration, and
    install.ps1 -OpenFirewall creates an inbound rule. Both would otherwise
    survive every reinstall, so a subsequent run would not be a clean test.
    """
    script = (build_dist.WINDOWS_INSTALLER_DIR / "uninstall.ps1").read_text()

    assert "EventLog\\Application\\$ServiceName" in script, "Event Log source not removed"
    assert "Remove-NetFirewallRule" in script, "firewall rule not removed"
    assert "CurrentVersion\\Uninstall\\$ServiceName" in script, "Apps & features entry not removed"
    assert "sc.exe delete" in script, "no fallback when the runtime is already gone"
    # Must verify afterwards rather than assume each removal succeeded.
    assert "Verifying nothing remains" in script


def test_uninstaller_rule_name_matches_the_installer():
    """A display-name mismatch would silently leave the firewall rule behind."""
    install = (build_dist.WINDOWS_INSTALLER_DIR / "install.ps1").read_text()
    uninstall = (build_dist.WINDOWS_INSTALLER_DIR / "uninstall.ps1").read_text()

    created = re.search(r'New-NetFirewallRule\s+-DisplayName\s+"([^"]+)"', install)
    removed = re.search(r'\$ruleName\s*=\s*"([^"]+)"', uninstall)

    assert created, "install.ps1 creates no named firewall rule"
    assert removed, "uninstall.ps1 does not name the rule it removes"
    assert created.group(1) == removed.group(1), (created.group(1), removed.group(1))


def test_uninstaller_offers_a_clean_slate_switch():
    """Config is preserved by default, so removal must be explicitly available."""
    script = (build_dist.WINDOWS_INSTALLER_DIR / "uninstall.ps1").read_text()

    assert "[switch] $RemoveConfig" in script
    assert "-RemoveConfig" in script


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


def test_requirements_pin_the_windows_only_runtime_dep():
    """`pip freeze` on Linux can never emit this line, so guard it explicitly."""
    text = (build_dist.PROJECT_ROOT / "requirements.txt").read_text()
    lines = [ln for ln in text.splitlines() if ln.strip().lower().startswith("pywin32")]

    assert lines, "pywin32 is missing from requirements.txt"
    assert "sys_platform == 'win32'" in lines[0]


def test_installer_registers_the_event_log_source_with_both_message_files():
    """The virtual service account cannot register the source itself.

    NTEventLogHandler ignores the access-denied on first use, so without the
    installer doing it every record renders as "The description for Event ID
    ... cannot be found". Two writers, two message tables: win32service.pyd for
    the app's ID-1 records and servicemanager.pyd for pywin32's own messages.
    """
    script = (build_dist.WINDOWS_INSTALLER_DIR / "install.ps1").read_text()

    assert "EventLog\\Application\\$ServiceName" in script
    assert "'win32service.pyd', 'servicemanager.pyd'" in script
    assert "EventMessageFile" in script and "TypesSupported" in script
    # uninstall must remove what install registers.
    assert "EventLog\\Application\\$ServiceName" in (build_dist.WINDOWS_INSTALLER_DIR / "uninstall.ps1").read_text()


def test_installer_suppresses_pip_script_location_warnings():
    """Scripts\\ in the private runtime is never on PATH; the advice is noise."""
    script = (build_dist.WINDOWS_INSTALLER_DIR / "install.ps1").read_text()
    installs = [l for l in script.splitlines() if "pip" in l and " install " in l and not l.lstrip().startswith("#")]
    assert installs
    for line in installs:
        assert "--no-warn-script-location" in line, line


# --- SBOM ---------------------------------------------------------------------


def _sbom_for(tmp_path, platform="linux_x86_64"):
    import json as _json
    payload = tmp_path / f"SmtpRelay-0.3.1-{platform}-cp315"
    wheels = payload / "wheels"
    wheels.mkdir(parents=True)
    make_wheel(wheels, "fastapi", "0.162.0", requires=["starlette>=0.40", "pydantic>=2"])
    make_wheel(wheels, "starlette", "1.10.0")
    make_wheel(wheels, "pydantic", "2.14.1", requires=[
        "pydantic_core==2.50.1", 'email-validator>=2.0; extra == "email"'])
    make_wheel(wheels, "pydantic_core", "2.50.1")
    make_wheel(wheels, "email_validator", "2.3.0")
    make_wheel(wheels, "uvicorn", "0.54.0")
    make_wheel(wheels, "pywin32", "312")  # present only to prove it is listed when bundled
    runtime = build_dist.RuntimeInfo(10, "python-build-standalone:20261026", "https://example.org/cpython.tar.gz", "ab" * 32)
    out = build_dist.write_sbom(
        payload, version="0.3.1", platform=platform, runtime_version="3.15.2",
        runtime=runtime, git_commit="deadbeef",
    )
    return payload, _json.loads(out.read_text())


def test_sbom_is_cyclonedx_with_one_component_per_wheel_plus_runtime(tmp_path):
    payload, bom = _sbom_for(tmp_path)

    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"
    assert bom["metadata"]["component"]["purl"] == "pkg:pypi/smtp-relay@0.3.1"
    props = {p["name"]: p["value"] for p in bom["metadata"]["component"]["properties"]}
    assert props["smtprelay:target"] == "linux_x86_64" and props["smtprelay:git_commit"] == "deadbeef"

    by_name = {c["name"]: c for c in bom["components"]}
    assert set(by_name) == {"fastapi", "starlette", "pydantic", "pydantic-core", "email-validator", "uvicorn", "pywin32", "cpython"}
    assert by_name["cpython"]["type"] == "platform"
    assert by_name["cpython"]["hashes"][0]["content"] == "ab" * 32
    assert (payload / build_dist.SBOM_FILENAME).is_file()


def test_sbom_hashes_match_the_wheel_files(tmp_path):
    import hashlib as _h
    payload, bom = _sbom_for(tmp_path)
    for component in bom["components"]:
        if component["type"] != "library":
            continue
        wheel = payload / "wheels" / next(p["value"] for p in component["properties"] if p["name"] == "smtprelay:wheel")
        assert component["hashes"][0]["content"] == _h.sha256(wheel.read_bytes()).hexdigest()
        assert component["purl"].startswith(f"pkg:pypi/{component['name']}@{component['version']}?file_name=")


def test_sbom_dependency_graph_follows_requires_dist_and_requested_extras(tmp_path):
    _, bom = _sbom_for(tmp_path)
    deps = {d["ref"]: d["dependsOn"] for d in bom["dependencies"]}
    ref = lambda name: next(c["bom-ref"] for c in bom["components"] if c["name"] == name)

    # The application depends on its declared direct dependencies and the runtime.
    app = deps["pkg:pypi/smtp-relay@0.3.1"]
    assert ref("fastapi") in app and ref("uvicorn") in app and ref("pydantic") in app and ref("cpython") in app
    assert set(deps[ref("fastapi")]) == {ref("starlette"), ref("pydantic")}
    # pydantic[email] is requested in pyproject, so the extra's dependency is live.
    assert set(deps[ref("pydantic")]) == {ref("pydantic-core"), ref("email-validator")}
    assert deps[ref("cpython")] == []


def test_sbom_license_extraction_prefers_pep639_then_classifier():
    assert build_dist._license_of("License-Expression: MIT\nClassifier: License :: OSI Approved :: BSD License\n") == {"expression": "MIT"}
    assert build_dist._license_of("Classifier: License :: OSI Approved :: Apache Software License\n") == {"license": {"name": "Apache Software License"}}
    assert build_dist._license_of("License: UNKNOWN\n") is None
    assert build_dist._license_of("License: PSF-2.0\n") == {"license": {"name": "PSF-2.0"}}
