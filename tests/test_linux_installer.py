"""Static guards for the Linux (systemd) installer.

The scripts only run as root on a systemd host, so CI checks what can be read
from the files: that they parse, that the unit is hardened and runs the app as
an unprivileged user with an explicit config path, that secrets end up
root:<service> 0640, and that the installer never reaches for a system Python.
The end-to-end run lives in scripts/test_linux_installer.sh (podman + systemd).
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

import build_dist

LINUX = build_dist.LINUX_INSTALLER_DIR
INSTALL = LINUX / "install.sh"
UNINSTALL = LINUX / "uninstall.sh"
UNIT = LINUX / "smtp-relay.service"


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
@pytest.mark.parametrize("script", [INSTALL, UNINSTALL])
def test_scripts_parse(script):
    result = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("script", [INSTALL, UNINSTALL])
def test_scripts_are_executable_and_strict(script):
    assert script.stat().st_mode & 0o111, f"{script.name} is not executable"
    head = script.read_text().splitlines()[:40]
    assert head[0].startswith("#!/usr/bin/env bash")
    assert any(l.startswith("set -") and "u" in l and "pipefail" in l for l in head), (
        f"{script.name} must fail on unset variables and pipeline errors"
    )


def test_installer_refuses_without_root_or_systemd():
    script = INSTALL.read_text()
    assert "$EUID -eq 0" in script
    assert "/run/systemd/system" in script


def test_installer_uses_only_the_bundled_interpreter():
    script = INSTALL.read_text()
    code = "\n".join(l for l in script.splitlines() if not l.lstrip().startswith("#"))
    assert 'PY="$INSTALL_DIR/python/bin/python3"' in script
    for forbidden in ("python3 -m venv", "/usr/bin/python", "apt-get", "dnf ", "pip3 "):
        assert forbidden not in code, f"install.sh must not use a system Python: {forbidden!r}"
    assert "--no-index" in script and "--find-links" in script
    assert "--no-warn-script-location" in script


def test_installer_validates_payload_with_the_manifest_before_touching_the_host():
    script = INSTALL.read_text()
    assert "MANIFEST.json" in script
    assert "hashlib.sha256" in script
    assert 'm.get("family") != "linux"' in script
    # Validation precedes the first write to the host.
    assert script.index("hashlib.sha256") < script.index("useradd")


def test_installer_creates_a_locked_down_system_account():
    script = INSTALL.read_text()
    assert "useradd --system" in script
    assert "--no-create-home" in script
    assert "nologin" in script


def test_config_is_readable_by_root_and_the_service_only():
    script = INSTALL.read_text()
    assert 'install -d -m 0750 -o root -g "$SERVICE_USER" "$CONFIG_DIR"' in script
    assert re.search(r'install -m 0640 -o root -g "\$SERVICE_USER" .*config\.toml', script)
    # Never clobber an operator's edited config.
    assert 'if [[ -f "$CONFIG_DIR/config.toml" ]]' in script
    assert "left untouched" in script


def test_installer_renders_every_unit_token():
    script = INSTALL.read_text()
    unit = UNIT.read_text()
    tokens = set(re.findall(r"@[A-Z_]+@", unit))
    assert tokens == {"@INSTALL_DIR@", "@CONFIG_DIR@", "@USER@", "@GROUP@"}
    for token in tokens:
        assert f"s|{token}|" in script, f"install.sh does not substitute {token}"
    assert "systemctl daemon-reload" in script
    assert "systemctl enable" in script


def test_unit_runs_the_console_entry_point_unprivileged_with_an_explicit_config():
    unit = UNIT.read_text()
    assert "ExecStart=@INSTALL_DIR@/python/bin/python3 -m app" in unit
    assert "User=@USER@" in unit and "Group=@GROUP@" in unit
    assert "Environment=RELAY_CONFIG=@CONFIG_DIR@/config.toml" in unit
    assert "Restart=on-failure" in unit
    # exec: `systemctl start` fails if the sandbox or the exec fails, instead of
    # reporting "active" for a process that never reached python.
    assert "Type=exec" in unit
    # A config error exits 2; retrying it would just loop.
    assert "RestartPreventExitStatus=2" in unit
    assert "User=root" not in unit


@pytest.mark.parametrize(
    "directive",
    [
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "PrivateTmp=yes",
        "PrivateDevices=yes",
        "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes",
        "ProtectControlGroups=yes",
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
        "RestrictNamespaces=yes",
        "RestrictSUIDSGID=yes",
        "LockPersonality=yes",
        "SystemCallArchitectures=native",
        "SystemCallFilter=@system-service",
    ],
)
def test_unit_hardening_directive_present(directive):
    lines = {l.strip() for l in UNIT.read_text().splitlines()}
    assert directive in lines, f"missing {directive}"


def test_unit_does_not_deny_writable_executable_memory():
    """CPython and libffi need W^X exceptions; MemoryDenyWriteExecute would crash
    the interpreter in ways that look like random segfaults."""
    assert "MemoryDenyWriteExecute" not in UNIT.read_text()


def test_render_unit_leaves_no_tokens(tmp_path):
    text = build_dist.render_unit(
        UNIT, install_dir="/opt/x", config_dir="/etc/x", user="u", group="g"
    )
    assert "@INSTALL_DIR@" not in text and "@USER@" not in text
    assert "ExecStart=/opt/x/python/bin/python3 -m app" in text
    assert "Environment=RELAY_CONFIG=/etc/x/config.toml" in text


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="systemd-analyze not available")
def test_unit_passes_systemd_analyze_verify(capsys):
    build_dist.validate_systemd_unit(UNIT)
    assert "verified OK" in capsys.readouterr().out


def test_uninstaller_preserves_config_unless_asked():
    script = UNINSTALL.read_text()
    assert "--remove-config" in script
    assert "Preserved $CONFIG_DIR" in script
    assert "systemctl disable --now" in script
    assert "userdel" in script
