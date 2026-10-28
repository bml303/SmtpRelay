"""TOML loading, environment overrides, and configuration validation errors."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from app.config import (
    POSIX_CONFIG_DIRNAME,
    WINDOWS_CONFIG_DIRNAME,
    ConfigError,
    _candidate_paths,
    _system_config_dir,
    load_config,
)

MINIMAL = """
[smtp]
host = "mail.example.com"
port = 465

[policy]
sender = "relay@example.com"
allowed_domains = ["example.com"]
"""


def write_config(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(text)
    return path


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch):
    """Isolate each test from RELAY_* variables in the developer's shell."""
    for name in [key for key in os.environ if key.startswith("RELAY_")]:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _isolate_package_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Keep the repo's real config.toml out of the package-root search path.

    Without this, tests that assume "no config file exists" would silently find
    the developer's own config.toml.
    """
    monkeypatch.setattr("app.config.PACKAGE_ROOT", tmp_path / "install-root")


def test_loads_from_toml(tmp_path):
    config = load_config(write_config(tmp_path, MINIMAL))

    assert config.smtp.host == "mail.example.com"
    assert config.smtp.port == 465
    assert config.smtp.resolved_security == "tls"
    assert config.smtp.timeout == 30.0
    assert config.policy.sender == "relay@example.com"
    assert config.policy.allowed_domains == ["example.com"]
    assert config.api.host == "127.0.0.1"
    assert config.api.port == 8000
    assert config.api.max_recipients == 50
    assert config.policy.reject_base64 is True
    assert config.policy.allow_subdomains is False


def test_loads_every_section(tmp_path):
    path = write_config(
        tmp_path,
        """
[api]
host = "0.0.0.0"
port = 9000
token = "abc"
max_recipients = 10

[smtp]
host = "mail.example.com"
port = 587
security = "starttls"
username = "relay"
password = "pw"
timeout = 5.5
local_hostname = "relay.example.com"

[policy]
sender = "relay@example.com"
sender_name = "Notification Relay"
allowed_domains = ["example.com", "example.org"]
allow_subdomains = true
reject_base64 = false
""",
    )
    config = load_config(path)

    assert config.api.host == "0.0.0.0"
    assert config.api.port == 9000
    assert config.api.token == "abc"
    assert config.api.max_recipients == 10
    assert config.smtp.resolved_security == "starttls"
    assert config.smtp.username == "relay"
    assert config.smtp.password == "pw"
    assert config.smtp.timeout == 5.5
    assert config.smtp.local_hostname == "relay.example.com"
    assert config.policy.sender_name == "Notification Relay"
    assert config.policy.allow_subdomains is True
    assert config.policy.reject_base64 is False


def test_env_overrides_the_file(tmp_path, monkeypatch):
    monkeypatch.setenv("RELAY_SMTP_HOST", "override.example.com")
    monkeypatch.setenv("RELAY_SMTP_PORT", "2525")
    monkeypatch.setenv("RELAY_SMTP_PASSWORD", "from-env")
    monkeypatch.setenv("RELAY_ALLOWED_DOMAINS", "a.com, b.com ,c.com")
    monkeypatch.setenv("RELAY_ALLOW_SUBDOMAINS", "true")
    monkeypatch.setenv("RELAY_MAX_RECIPIENTS", "7")
    monkeypatch.setenv("RELAY_API_TOKEN", "tok")

    config = load_config(write_config(tmp_path, MINIMAL))

    assert config.smtp.host == "override.example.com"
    assert config.smtp.port == 2525
    assert config.smtp.password == "from-env"
    assert config.smtp.resolved_security == "starttls"
    assert config.policy.allowed_domains == ["a.com", "b.com", "c.com"]
    assert config.policy.allow_subdomains is True
    assert config.api.max_recipients == 7
    assert config.api.token == "tok"
    # Untouched values still come from the file.
    assert config.policy.sender == "relay@example.com"


def test_env_alone_is_sufficient(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("RELAY_SMTP_HOST", "mail.example.com")
    monkeypatch.setenv("RELAY_SENDER", "relay@example.com")

    config = load_config()

    assert config.smtp.host == "mail.example.com"
    assert config.policy.sender == "relay@example.com"


def test_falls_back_to_config_beside_the_package(tmp_path, monkeypatch):
    """The SCM starts a service in System32, so CWD cannot be the only search path."""
    install_root = tmp_path / "install-root"
    install_root.mkdir()
    (install_root / "config.toml").write_text(MINIMAL)
    monkeypatch.setattr("app.config.PACKAGE_ROOT", install_root)
    monkeypatch.chdir(tmp_path)  # no config.toml here

    assert load_config().smtp.host == "mail.example.com"


def test_working_directory_wins_over_the_package_root(tmp_path, monkeypatch):
    install_root = tmp_path / "install-root"
    workdir = tmp_path / "workdir"
    install_root.mkdir()
    workdir.mkdir()
    (install_root / "config.toml").write_text(MINIMAL)
    (workdir / "config.toml").write_text(
        MINIMAL.replace("mail.example.com", "workdir.example.com")
    )
    monkeypatch.setattr("app.config.PACKAGE_ROOT", install_root)
    monkeypatch.chdir(workdir)

    assert load_config().smtp.host == "workdir.example.com"


def test_posix_system_config_dir_is_under_etc(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")

    assert _system_config_dir() == Path("/etc") / POSIX_CONFIG_DIRNAME


def test_windows_system_config_dir_is_under_programdata(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("ProgramData", r"C:\ProgramData")

    result = _system_config_dir()

    # Compared by component: on this Linux host Path() cannot build a real
    # WindowsPath, so asserting the whole string would test pathlib, not us.
    assert result is not None
    assert result.name == WINDOWS_CONFIG_DIRNAME == "SmtpRelay"
    assert "ProgramData" in str(result.parent)


def test_windows_without_programdata_degrades_gracefully(monkeypatch):
    """A missing env var must not raise; the search just skips that candidate."""
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.delenv("ProgramData", raising=False)
    monkeypatch.delenv("PROGRAMDATA", raising=False)

    assert _system_config_dir() is None


def test_search_order_is_cwd_then_system_then_package_root(tmp_path, monkeypatch):
    workdir = tmp_path / "cwd"
    install_root = tmp_path / "site-packages"
    workdir.mkdir()
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("ProgramData", str(tmp_path / "ProgramData"))
    monkeypatch.setattr("app.config.PACKAGE_ROOT", install_root)
    monkeypatch.chdir(workdir)

    candidates, explicit = _candidate_paths(None)

    assert explicit is False
    assert candidates == [
        workdir / "config.toml",
        tmp_path / "ProgramData" / WINDOWS_CONFIG_DIRNAME / "config.toml",
        install_root / "config.toml",
    ]


def test_config_is_found_in_the_system_dir(tmp_path, monkeypatch):
    """The deployed-service case: CWD is System32-like, PACKAGE_ROOT is site-packages."""
    system_dir = tmp_path / "ProgramData" / WINDOWS_CONFIG_DIRNAME
    system_dir.mkdir(parents=True)
    (system_dir / "config.toml").write_text(MINIMAL)

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("ProgramData", str(tmp_path / "ProgramData"))
    monkeypatch.setattr("app.config.PACKAGE_ROOT", tmp_path / "site-packages")
    monkeypatch.chdir(tmp_path)

    assert load_config().smtp.host == "mail.example.com"


def test_system_dir_wins_over_the_package_root(tmp_path, monkeypatch):
    """ProgramData is the mutable config home; the install tree is read-only."""
    system_dir = tmp_path / "ProgramData" / WINDOWS_CONFIG_DIRNAME
    install_root = tmp_path / "site-packages"
    system_dir.mkdir(parents=True)
    install_root.mkdir()
    (system_dir / "config.toml").write_text(MINIMAL)
    (install_root / "config.toml").write_text(
        MINIMAL.replace("mail.example.com", "installroot.example.com")
    )

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("ProgramData", str(tmp_path / "ProgramData"))
    monkeypatch.setattr("app.config.PACKAGE_ROOT", install_root)
    monkeypatch.chdir(tmp_path)

    assert load_config().smtp.host == "mail.example.com"


def test_relay_config_overrides_the_system_dir(tmp_path, monkeypatch):
    system_dir = tmp_path / "ProgramData" / WINDOWS_CONFIG_DIRNAME
    system_dir.mkdir(parents=True)
    (system_dir / "config.toml").write_text(MINIMAL)
    explicit = tmp_path / "explicit.toml"
    explicit.write_text(MINIMAL.replace("mail.example.com", "explicit.example.com"))

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("ProgramData", str(tmp_path / "ProgramData"))
    monkeypatch.setenv("RELAY_CONFIG", str(explicit))

    assert load_config().smtp.host == "explicit.example.com"


def test_error_lists_every_searched_path(tmp_path, monkeypatch):
    """A missing config must say where it looked, not just that something is unset."""
    install_root = tmp_path / "install-root"
    monkeypatch.setattr("app.config.PACKAGE_ROOT", install_root)
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ConfigError) as excinfo:
        load_config()

    message = str(excinfo.value)
    assert "No config file was found" in message
    assert str(tmp_path / "config.toml") in message
    assert str(install_root / "config.toml") in message


def test_relay_config_env_var_selects_the_file(tmp_path, monkeypatch):
    path = tmp_path / "custom.toml"
    path.write_text(MINIMAL)
    monkeypatch.setenv("RELAY_CONFIG", str(path))

    assert load_config().smtp.host == "mail.example.com"


def test_relay_config_env_var_pointing_nowhere_is_an_error(tmp_path, monkeypatch):
    monkeypatch.setenv("RELAY_CONFIG", str(tmp_path / "absent.toml"))

    with pytest.raises(ConfigError, match="not found"):
        load_config()


def test_explicit_missing_path_is_an_error(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.toml")


def test_missing_required_fields_are_reported(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ConfigError) as excinfo:
        load_config()

    message = str(excinfo.value)
    assert "smtp" in message
    assert "policy" in message


def test_invalid_toml_is_reported(tmp_path):
    path = write_config(tmp_path, "[smtp\nhost = ")

    with pytest.raises(ConfigError, match="not valid TOML"):
        load_config(path)


def test_unknown_section_is_rejected(tmp_path):
    path = write_config(tmp_path, MINIMAL + '\n[sntp]\nhost = "x"\n')

    with pytest.raises(ConfigError):
        load_config(path)


def test_unknown_key_is_rejected(tmp_path):
    path = write_config(tmp_path, MINIMAL.replace("port = 465", "port = 465\nportx = 1"))

    with pytest.raises(ConfigError):
        load_config(path)


def test_out_of_range_port_is_rejected(tmp_path):
    path = write_config(tmp_path, MINIMAL.replace("port = 465", "port = 99999"))

    with pytest.raises(ConfigError):
        load_config(path)


def test_unknown_security_mode_is_rejected(tmp_path):
    path = write_config(
        tmp_path, MINIMAL.replace("port = 465", 'port = 465\nsecurity = "opportunistic"')
    )

    with pytest.raises(ConfigError):
        load_config(path)


def test_invalid_sender_is_rejected(tmp_path):
    path = write_config(tmp_path, MINIMAL.replace("relay@example.com", "not-an-email"))

    with pytest.raises(ConfigError):
        load_config(path)
