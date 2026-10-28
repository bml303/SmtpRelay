"""Windows deployability: the service module, and the platform markers that let
the dependency set install on Windows at all.

The service module cannot be *imported* off Windows (it needs win32 modules as
base classes), but it must still compile, and its guard must tell the reader what
is actually wrong.
"""

from __future__ import annotations

import importlib
import importlib.util
import py_compile
import re
import sys
import tomllib
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SERVICE_MODULE = PROJECT_ROOT / "app" / "windows_service.py"


def test_service_module_compiles(tmp_path):
    """Catches syntax errors on any platform, including this Linux test host."""
    py_compile.compile(
        str(SERVICE_MODULE),
        cfile=str(tmp_path / "windows_service.pyc"),
        doraise=True,
    )


def test_service_class_string_is_an_importable_dotted_path():
    """Regression guard for SCM error 1053.

    ``python -m app.windows_service`` makes ``__name__ == "__main__"``, so
    pywin32's ``GetServiceClassString`` falls back to recording a *filesystem*
    path in the registry. ``pythonservice.exe`` then imports that file as a
    top-level module, the module's relative imports fail, and the process dies
    before ``SvcRun`` - so the SCM sees no status transition and reports 1053.
    """
    src = SERVICE_MODULE.read_text()
    match = re.search(r'^SERVICE_CLASS_STRING\s*=\s*["\']([^"\']+)["\']', src, re.M)
    assert match, "SERVICE_CLASS_STRING is not defined in windows_service.py"

    dotted = match.group(1)
    assert "/" not in dotted and "\\" not in dotted, (
        f"must be a dotted import path, not a filesystem path: {dotted}"
    )

    module_path, _, class_name = dotted.rpartition(".")
    assert module_path and class_name, f"expected 'module.Class', got {dotted!r}"

    # find_spec resolves the module without executing it, so this works even
    # though importing it would raise off Windows.
    assert importlib.util.find_spec(module_path) is not None, (
        f"{module_path} is not importable - the SCM could not load the service"
    )
    assert re.search(rf"^class {re.escape(class_name)}\b", src, re.M), (
        f"{class_name} is not defined in {module_path}"
    )


def test_handle_command_line_is_given_the_explicit_class_string():
    """Defining the constant is not enough - it must actually be passed.

    Omitting it silently reverts to pywin32's filesystem-path fallback.
    """
    assert "serviceClassString=SERVICE_CLASS_STRING" in SERVICE_MODULE.read_text()


@pytest.mark.skipif(sys.platform == "win32", reason="Windows is the supported platform here")
def test_importing_off_windows_fails_with_an_actionable_message():
    with pytest.raises(ImportError) as excinfo:
        importlib.import_module("app.windows_service")

    message = str(excinfo.value)
    assert "requires Windows" in message
    assert "pywin32" in message


def _pinned_entries() -> dict[str, str]:
    """Map normalized package name -> environment marker ("" when unmarked)."""
    entries: dict[str, str] = {}
    for line in (PROJECT_ROOT / "requirements.txt").read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        spec, _, marker = line.partition(";")
        name = spec.split("==")[0].strip().lower().replace("_", "-")
        entries[name] = marker.strip()
    return entries


#: Packages that exist only because of uvicorn's [standard] extra. None is used
#: by this relay, and PyYAML among them has no win_amd64 wheel for cp3.15 and no
#: win_arm64 wheel for cp3.11 - so pinning it silently turns a Windows install
#: into a source build requiring Visual Studio Build Tools for C++.
UVICORN_STANDARD_ONLY = {
    "httptools",
    "python-dotenv",
    "pyyaml",
    "uvloop",
    "watchfiles",
    "websockets",
}


def test_requirements_do_not_pull_the_uvicorn_standard_extra():
    """Regression guard for the MSVC Build Tools requirement on Windows."""
    present = sorted(UVICORN_STANDARD_ONLY & set(_pinned_entries()))

    assert not present, (
        f"these exist only via uvicorn[standard] and force a C/C++ compiler on "
        f"Windows: {present}"
    )


def test_pyproject_declares_plain_uvicorn():
    """The lockfile above only stays compiler-free if this declaration holds."""
    data = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text())

    uvicorn_reqs = [r for r in data["project"]["dependencies"] if r.startswith("uvicorn")]

    assert uvicorn_reqs, "uvicorn is not declared as a runtime dependency"
    for requirement in uvicorn_reqs:
        assert "[standard]" not in requirement, requirement


def test_pywin32_is_the_only_platform_specific_pin():
    """With plain uvicorn the set is cross-platform; only pywin32 needs a marker."""
    entries = _pinned_entries()

    assert "sys_platform == 'win32'" in entries["pywin32"]

    marked = {name for name, marker in entries.items() if marker}
    assert marked == {"pywin32"}, f"unexpected platform-marked pins: {sorted(marked)}"


def test_only_well_wheeled_packages_remain_compiled():
    """Everything else must be pure Python or have universal Windows wheels.

    pydantic-core and pywin32 are the only compiled packages left, and both
    publish wheels across win_amd64/win_arm64 for cp311-cp315.
    """
    known_compiled = {"pydantic-core", "pywin32"}
    entries = _pinned_entries()

    assert known_compiled <= set(entries), "expected compiled packages went missing"
    # httptools/PyYAML/watchfiles/websockets were the other compiled ones.
    assert not (UVICORN_STANDARD_ONLY & set(entries))


def test_pyproject_windows_extra_is_platform_guarded():
    """`pip install '.[dev,windows]'` must stay a no-op for pywin32 on Linux."""
    data = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text())
    extras = data["project"]["optional-dependencies"]

    assert "windows" in extras
    for requirement in extras["windows"]:
        assert "sys_platform == 'win32'" in requirement, requirement


def test_runtime_dependencies_contain_no_platform_specific_pins():
    """The core install must work on both platforms without markers."""
    data = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text())

    for requirement in data["project"]["dependencies"]:
        assert ";" not in requirement, f"unexpected marker in runtime deps: {requirement}"
