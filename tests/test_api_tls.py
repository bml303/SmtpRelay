"""Inbound API TLS: config plumbing, uvicorn wiring, and a live HTTPS round trip.

The live tests need ``openssl`` to mint a throwaway certificate; they skip
cleanly where that is unavailable so the suite stays portable.
"""

from __future__ import annotations

import inspect
import os
import shutil
import socket
import ssl
import subprocess
import threading
import time
from email.message import EmailMessage
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
import uvicorn
from pydantic import ValidationError

from app.config import (
    SSL_VERIFY_MODES,
    ApiConfig,
    AppConfig,
    ConfigError,
    PolicyConfig,
    SmtpConfig,
    load_config,
)
from app.main import create_app

requires_openssl = pytest.mark.skipif(
    shutil.which("openssl") is None, reason="openssl is needed to mint a test certificate"
)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


TLS_TOML = """
[api]
ssl_certfile = "/etc/ssl/certs/relay.crt"
ssl_keyfile = "/etc/ssl/private/relay.key"
ssl_ca_certs = "/etc/ssl/certs/client-ca.pem"
ssl_cert_reqs = "required"

[smtp]
host = "mail.example.com"

[policy]
sender = "relay@example.com"
"""

#: Minimal valid base config, so env-override tests have something to override.
BASE_TOML = """
[smtp]
host = "file.example.com"

[policy]
sender = "file@example.com"
"""


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch):
    """Isolate each test from RELAY_* variables in the developer's shell."""
    for name in [key for key in os.environ if key.startswith("RELAY_")]:
        monkeypatch.delenv(name, raising=False)


# --- configuration ---------------------------------------------------------


def test_tls_is_off_by_default():
    api = ApiConfig()

    assert api.tls_enabled is False
    assert api.scheme == "http"
    assert api.uvicorn_ssl_kwargs() == {}


def test_tls_loads_from_toml(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(TLS_TOML)

    config = load_config(path)

    assert config.api.tls_enabled is True
    assert config.api.scheme == "https"
    assert config.api.ssl_certfile == Path("/etc/ssl/certs/relay.crt")
    assert config.api.ssl_keyfile == Path("/etc/ssl/private/relay.key")
    assert config.api.ssl_ca_certs == Path("/etc/ssl/certs/client-ca.pem")
    assert config.api.ssl_cert_reqs == "required"


def test_tls_env_overrides(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    path.write_text(BASE_TOML)
    monkeypatch.setenv("RELAY_API_SSL_CERTFILE", "/env/cert.pem")
    monkeypatch.setenv("RELAY_API_SSL_KEYFILE", "/env/key.pem")
    monkeypatch.setenv("RELAY_API_SSL_KEYFILE_PASSWORD", "passphrase")
    monkeypatch.setenv("RELAY_API_SSL_CERT_REQS", "optional")

    config = load_config(path)

    assert config.api.ssl_certfile == Path("/env/cert.pem")
    assert config.api.ssl_keyfile == Path("/env/key.pem")
    assert config.api.ssl_keyfile_password == "passphrase"
    assert config.api.ssl_cert_reqs == "optional"
    # Values the environment did not mention still come from the file.
    assert config.smtp.host == "file.example.com"
    assert config.policy.sender == "file@example.com"


def test_keyfile_without_certfile_is_rejected(tmp_path):
    """A half-configured TLS setup must fail at startup, not inside uvicorn."""
    path = tmp_path / "config.toml"
    path.write_text(TLS_TOML.replace('ssl_certfile = "/etc/ssl/certs/relay.crt"\n', ""))

    with pytest.raises(ConfigError) as excinfo:
        load_config(path)

    assert "ssl_certfile is required" in str(excinfo.value)


def test_unknown_verify_mode_is_rejected():
    with pytest.raises(ValidationError):
        ApiConfig(ssl_certfile=Path("c.pem"), ssl_cert_reqs="strict")


def test_ssl_kwargs_map_verify_mode_to_the_int_uvicorn_wants(tmp_path):
    """uvicorn takes ssl_cert_reqs as an ssl.VerifyMode int, not a string."""
    api = ApiConfig(
        ssl_certfile=tmp_path / "cert.pem",
        ssl_ca_certs=tmp_path / "ca.pem",
        ssl_cert_reqs="required",
    )

    kwargs = api.uvicorn_ssl_kwargs()

    assert kwargs["ssl_cert_reqs"] == ssl.CERT_REQUIRED
    assert isinstance(kwargs["ssl_cert_reqs"], int)
    assert SSL_VERIFY_MODES == {
        "none": ssl.CERT_NONE,
        "optional": ssl.CERT_OPTIONAL,
        "required": ssl.CERT_REQUIRED,
    }


def test_ssl_kwargs_omit_unset_options(tmp_path):
    api = ApiConfig(ssl_certfile=tmp_path / "cert.pem", ssl_keyfile=tmp_path / "key.pem")

    assert api.uvicorn_ssl_kwargs() == {
        "ssl_certfile": str(tmp_path / "cert.pem"),
        "ssl_keyfile": str(tmp_path / "key.pem"),
    }


def test_ssl_kwargs_bind_to_the_real_uvicorn_config(tmp_path):
    """Bind against the real uvicorn.Config, not a double.

    This is the guard whose absence let ``rcpt_to=`` (instead of ``to_addrs=``)
    pass every mocked test and then 500 against a live server.
    """
    api = ApiConfig(
        ssl_certfile=tmp_path / "cert.pem",
        ssl_keyfile=tmp_path / "key.pem",
        ssl_keyfile_password="pw",
        ssl_ca_certs=tmp_path / "ca.pem",
        ssl_cert_reqs="required",
    )

    inspect.signature(uvicorn.Config.__init__).bind(
        None,
        object(),
        host="127.0.0.1",
        port=8000,
        log_config=None,
        **api.uvicorn_ssl_kwargs(),
    )


# --- live HTTPS ------------------------------------------------------------


def mint_self_signed_cert(directory: Path) -> tuple[Path, Path]:
    cert = directory / "cert.pem"
    key = directory / "key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key), "-out", str(cert),
            "-days", "1", "-nodes", "-subj", "/CN=127.0.0.1",
            "-addext", "subjectAltName=IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


class StubRelay:
    """Stands in for SmtpRelay so the HTTPS tests need no mailhost."""

    def __init__(self) -> None:
        self.sent: list[tuple[EmailMessage, str, list[str]]] = []

    def send(self, message: EmailMessage, *, sender: str, recipients: list[str]) -> str:
        self.sent.append((message, sender, list(recipients)))
        return str(message["Message-ID"])


@pytest.fixture
def https_server(tmp_path, monkeypatch):
    """A real uvicorn server speaking TLS on an ephemeral port.

    Only reached from ``@requires_openssl`` tests, so no mark is needed here
    (pytest forbids marks on fixtures).
    """
    cert, key = mint_self_signed_cert(tmp_path)
    stub = StubRelay()
    monkeypatch.setattr("app.main.SmtpRelay", lambda _config: stub)

    port = free_port()
    api = ApiConfig(host="127.0.0.1", port=port, ssl_certfile=cert, ssl_keyfile=key)
    settings = AppConfig(
        api=api,
        smtp=SmtpConfig(host="mail.example.com", port=587),
        policy=PolicyConfig(sender="relay@example.com", allowed_domains=["example.com"]),
    )

    server = uvicorn.Server(
        uvicorn.Config(
            create_app(settings),
            host=api.host,
            port=port,
            log_config=None,
            **api.uvicorn_ssl_kwargs(),
        )
    )
    thread = threading.Thread(target=server.run, name="uvicorn-tls", daemon=True)
    thread.start()

    deadline = time.time() + 20
    while not server.started and time.time() < deadline:
        if not thread.is_alive():
            break
        time.sleep(0.05)
    assert server.started, "uvicorn did not finish starting the TLS listener"

    try:
        # httpx deprecates verify=<str>; build the context the documented way.
        verify_ctx = ssl.create_default_context(cafile=str(cert))
        yield SimpleNamespace(
            server=server, port=port, cert=cert, relay=stub, verify_ctx=verify_ctx
        )
    finally:
        server.should_exit = True
        thread.join(timeout=20)


@requires_openssl
def test_https_health_round_trip(https_server):
    with httpx.Client(verify=https_server.verify_ctx) as client:
        response = client.get(f"https://127.0.0.1:{https_server.port}/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@requires_openssl
def test_https_post_is_relayed(https_server):
    with httpx.Client(verify=https_server.verify_ctx) as client:
        response = client.post(
            f"https://127.0.0.1:{https_server.port}/mail",
            json={
                "recipients": ["alice@example.com"],
                "subject": "Over TLS",
                "body": "This request arrived over HTTPS.",
            },
        )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "sent"
    assert len(https_server.relay.sent) == 1
    assert https_server.relay.sent[0][2] == ["alice@example.com"]


@requires_openssl
def test_https_policy_is_still_enforced(https_server):
    with httpx.Client(verify=https_server.verify_ctx) as client:
        response = client.post(
            f"https://127.0.0.1:{https_server.port}/mail",
            json={
                "recipients": ["eve@evil.com"],
                "subject": "Nope",
                "body": "Should be rejected.",
            },
        )

    assert response.status_code == 400
    assert response.json()["code"] == "domain_not_allowed"
    assert https_server.relay.sent == []


@requires_openssl
def test_plaintext_http_is_refused_on_the_tls_port(https_server):
    """Proves TLS is actually enforced, not merely offered alongside HTTP."""
    with httpx.Client() as client:
        with pytest.raises(httpx.TransportError):
            client.get(f"http://127.0.0.1:{https_server.port}/health")


@requires_openssl
def test_untrusted_certificate_is_refused_by_a_verifying_client(https_server):
    """The server presents a self-signed cert; a verifying client must reject it."""
    with httpx.Client(verify=True) as client:
        with pytest.raises(httpx.TransportError):
            client.get(f"https://127.0.0.1:{https_server.port}/health")
