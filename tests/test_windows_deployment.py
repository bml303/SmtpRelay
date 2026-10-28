"""Windows deployability: the service module, and the platform markers that let
the dependency set install on Windows at all.

The service module cannot be *imported* off Windows (it needs win32 modules as
base classes), but it must still compile, and its guard must tell the reader what
is actually wrong.
"""

from __future__ import annotations

import importlib
import py_compile
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


@pytest.mark.skipif(sys.platform == "win32", reason="Windows is the supported platform here")
def test_importing_off_windows_fails_with_an_actionable_message():
    with pytest.raises(ImportError) as excinfo:
        importlib.import_module("app.windows_service")

    message = str(excinfo.value)
    assert "requires Windows" in message
    assert "pywin32" in message


def test_requirements_guard_platform_specific_packages():
    """uvloop ships no Windows wheels, so it must not be pinned unconditionally."""
    entries: dict[str, str] = {}
    for line in (PROJECT_ROOT / "requirements.txt").read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        spec, _, marker = line.partition(";")
        name = spec.split("==")[0].strip().lower().replace("_", "-")
        entries[name] = marker.strip()

    assert "sys_platform != 'win32'" in entries["uvloop"]
    assert "sys_platform == 'win32'" in entries["pywin32"]


def test_every_pinned_package_is_installable_on_windows():
    """Nothing besides uvloop may be pinned without a Windows-compatible marker.

    Guards against re-introducing the flat `pip freeze` regression, where a
    Linux-only package silently made the lockfile uninstallable on Windows.
    """
    unix_only = {"uvloop"}
    offenders = []
    for line in (PROJECT_ROOT / "requirements.txt").read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        spec, _, marker = line.partition(";")
        name = spec.split("==")[0].strip().lower().replace("_", "-")
        if name in unix_only and "win32" not in marker:
            offenders.append(line)

    assert not offenders, f"Unix-only packages pinned without a marker: {offenders}"


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
