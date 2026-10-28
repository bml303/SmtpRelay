"""Network-exposure policy.

A non-loopback ``api.host`` must come with both TLS and client authentication,
otherwise the service is a cleartext open relay. Enforced in ``AppConfig`` rather
than the installer so no entry point can bypass it.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.config import (
    LOOPBACK_HOSTS,
    ApiConfig,
    AppConfig,
    ConfigError,
    PolicyConfig,
    SmtpConfig,
    load_config,
)

CERT = Path("/etc/ssl/certs/relay.crt")
KEY = Path("/etc/ssl/private/relay.key")
CA = Path("/etc/ssl/certs/client-ca.pem")

MINIMAL_TOML = '[smtp]\nhost = "mail.example.com"\n\n[policy]\nsender = "relay@example.com"\n'


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch):
    """Isolate each test from RELAY_* variables in the developer's shell."""
    for name in [key for key in os.environ if key.startswith("RELAY_")]:
        monkeypatch.delenv(name, raising=False)


def build(api: ApiConfig) -> AppConfig:
    return AppConfig(
        api=api,
        smtp=SmtpConfig(host="mail.example.com", port=587),
        policy=PolicyConfig(sender="relay@example.com", allowed_domains=["example.com"]),
    )


@pytest.mark.parametrize("host", sorted(LOOPBACK_HOSTS))
def test_loopback_needs_neither_tls_nor_auth(host):
    """The default posture: unreachable from the network, so nothing to protect."""
    assert build(ApiConfig(host=host)).api.host == host


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.20", "relay.example.com"])
def test_exposed_without_tls_is_rejected(host):
    with pytest.raises(ValidationError) as excinfo:
        build(ApiConfig(host=host))

    assert "cleartext" in str(excinfo.value)


def test_exposed_with_tls_but_no_auth_is_rejected():
    """TLS alone still leaves an open relay: anyone on the network can submit mail."""
    with pytest.raises(ValidationError) as excinfo:
        build(ApiConfig(host="0.0.0.0", ssl_certfile=CERT, ssl_keyfile=KEY))

    assert "relay mail through it" in str(excinfo.value)


def test_exposed_with_tls_and_token_is_accepted():
    config = build(
        ApiConfig(host="0.0.0.0", ssl_certfile=CERT, ssl_keyfile=KEY, token="s3cret")
    )

    assert config.api.tls_enabled is True


def test_exposed_with_tls_and_required_mtls_is_accepted():
    """Certificate-based auth is an alternative to the bearer token."""
    config = build(
        ApiConfig(
            host="0.0.0.0",
            ssl_certfile=CERT,
            ssl_keyfile=KEY,
            ssl_ca_certs=CA,
            ssl_cert_reqs="required",
        )
    )

    assert config.api.ssl_cert_reqs == "required"


def test_optional_mtls_does_not_count_as_authentication():
    """Under CERT_OPTIONAL a client may simply present no certificate."""
    with pytest.raises(ValidationError) as excinfo:
        build(
            ApiConfig(
                host="0.0.0.0",
                ssl_certfile=CERT,
                ssl_keyfile=KEY,
                ssl_ca_certs=CA,
                ssl_cert_reqs="optional",
            )
        )

    assert "relay mail through it" in str(excinfo.value)


def test_both_problems_are_reported_together():
    """One message naming both faults beats fixing them one round trip at a time."""
    with pytest.raises(ValidationError) as excinfo:
        build(ApiConfig(host="0.0.0.0"))

    message = str(excinfo.value)
    assert "cleartext" in message
    assert "relay mail through it" in message
    assert "127.0.0.1" in message


def test_load_config_surfaces_it_as_a_config_error(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text('[api]\nhost = "0.0.0.0"\n\n' + MINIMAL_TOML)

    with pytest.raises(ConfigError) as excinfo:
        load_config(path)

    assert "reachable from the network" in str(excinfo.value)


def test_env_override_cannot_expose_a_cleartext_relay(tmp_path, monkeypatch):
    """RELAY_API_HOST is an override, not a way around the policy."""
    path = tmp_path / "config.toml"
    path.write_text(MINIMAL_TOML)
    monkeypatch.setenv("RELAY_API_HOST", "0.0.0.0")

    with pytest.raises(ConfigError) as excinfo:
        load_config(path)

    assert "reachable from the network" in str(excinfo.value)


def test_token_alone_without_tls_is_still_rejected(tmp_path):
    """A bearer token sent in cleartext is worse than none - it leaks the secret."""
    with pytest.raises(ValidationError) as excinfo:
        build(ApiConfig(host="0.0.0.0", token="s3cret"))

    assert "cleartext" in str(excinfo.value)
