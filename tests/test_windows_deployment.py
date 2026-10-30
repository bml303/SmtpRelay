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


def _pinned_entries(path: Path = PROJECT_ROOT / "requirements.txt") -> dict[str, str]:
    """Map normalized package name -> environment marker ("" when unmarked)."""
    entries: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-r "):
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


#: Pins that exist only on Windows. `pip freeze` on Linux can never emit them,
#: so they are maintained by hand and guarded here. pywin32 is runtime (the
#: native service); colorama is pytest's and belongs to the dev set only.
WINDOWS_ONLY_RUNTIME_PINS = {"pywin32"}
WINDOWS_ONLY_DEV_PINS = {"colorama"}


def test_platform_specific_pins_are_exactly_the_windows_only_set():
    entries = _pinned_entries()
    for name in WINDOWS_ONLY_RUNTIME_PINS:
        assert name in entries, f"{name} is missing from requirements.txt"
        assert "sys_platform == 'win32'" in entries[name], f"{name}: {entries[name]}"

    dev = _pinned_entries(PROJECT_ROOT / "requirements-dev.txt")
    for name in WINDOWS_ONLY_DEV_PINS:
        assert name in dev, f"{name} is missing from requirements-dev.txt"
        assert "sys_platform == 'win32'" in dev[name]
        assert name not in entries, f"{name} is test-only and must not ship in payloads"


#: Packages that exist only for the test suite. Shipping them in a payload puts
#: their CVEs on the service's SBOM for no benefit.
TEST_ONLY = {"pytest", "httpx", "httpcore", "aiosmtpd", "pygments", "pluggy", "iniconfig", "atpublic"}


def test_runtime_requirements_exclude_the_test_suite():
    present = sorted(TEST_ONLY & set(_pinned_entries()))
    assert not present, f"test-only packages in requirements.txt: {present}"


def test_dev_requirements_include_the_runtime_set():
    text = (PROJECT_ROOT / "requirements-dev.txt").read_text()
    assert "-r requirements.txt" in text.splitlines()
    dev = _pinned_entries(PROJECT_ROOT / "requirements-dev.txt")
    assert "pytest" in dev and "aiosmtpd" in dev


def test_no_unexpected_platform_marked_pins():
    marked = {name for name, marker in _pinned_entries().items() if marker}
    assert marked == WINDOWS_ONLY_RUNTIME_PINS, f"unexpected platform-marked pins: {sorted(marked)}"


def test_only_well_wheeled_packages_remain_compiled():
    """Everything else must be pure Python or have universal Windows wheels.

    pydantic-core, pywin32, cffi and cryptography are the only compiled
    packages, and all publish wheels across win_amd64/win_arm64 for cp311-cp315
    (cryptography only up to 46.x on win_arm64, hence its pin).
    """
    known_compiled = {"pydantic-core", "pywin32", "cffi", "cryptography"}
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


def test_service_attribute_references_match_their_definitions():
    """``SvcDoRun`` never runs on the Linux test host, so a typo such as
    ``self._svc_display_name`` (no trailing underscore) for the pywin32
    ``_svc_display_name_`` attribute only surfaces as an AttributeError on the
    first start of the deployed service. Resolve every ``self.<attr>`` read in
    the service class against what the class actually defines or assigns.
    """
    import ast

    tree = ast.parse(SERVICE_MODULE.read_text())
    service_class = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "SmtpRelayService"
    )

    defined: set[str] = set()
    referenced: set[str] = set()
    for node in ast.walk(service_class):
        if isinstance(node, ast.FunctionDef):
            defined.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    defined.add(target.id)
                elif isinstance(target, ast.Attribute) and _is_self(target.value):
                    defined.add(target.attr)
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name):
                defined.add(node.target.id)
            elif isinstance(node.target, ast.Attribute) and _is_self(node.target.value):
                defined.add(node.target.attr)
        elif isinstance(node, ast.Attribute) and _is_self(node.value):
            referenced.add(node.attr)

    # Inherited from pywin32's ServiceFramework; not visible in this file.
    inherited = {"ssh", "ReportServiceStatus"}
    unresolved = referenced - defined - inherited
    assert not unresolved, (
        f"self.<attr> used but never defined in SmtpRelayService: {sorted(unresolved)}"
    )


def _is_self(node) -> bool:
    import ast

    return isinstance(node, ast.Name) and node.id == "self"
