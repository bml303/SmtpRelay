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
from contextlib import contextmanager
from email.message import EmailMessage
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
import uvicorn
from pydantic import ValidationError
from uvicorn.config import create_ssl_context

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
    monkeypatch.setenv("RELAY_API_SSL_CA_CERTS", "/env/ca.pem")
    monkeypatch.setenv("RELAY_API_SSL_CERT_REQS", "optional")

    config = load_config(path)

    assert config.api.ssl_certfile == Path("/env/cert.pem")
    assert config.api.ssl_keyfile == Path("/env/key.pem")
    assert config.api.ssl_keyfile_password == "passphrase"
    assert config.api.ssl_ca_certs == Path("/env/ca.pem")
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


def test_ca_certs_without_cert_reqs_is_rejected(tmp_path):
    """Would leave verify_mode at CERT_NONE: mTLS configured but silently inert."""
    with pytest.raises(ValidationError) as excinfo:
        ApiConfig(ssl_certfile=tmp_path / "c.pem", ssl_ca_certs=tmp_path / "ca.pem")

    assert "never request a client certificate" in str(excinfo.value)


def test_cert_reqs_without_ca_certs_is_rejected(tmp_path):
    """Would verify clients against an empty trust store, rejecting everyone."""
    for mode in ("optional", "required"):
        with pytest.raises(ValidationError) as excinfo:
            ApiConfig(
                ssl_certfile=tmp_path / "c.pem",
                ssl_ca_certs=None,
                ssl_cert_reqs=mode,
            )
        assert "requires api.ssl_ca_certs" in str(excinfo.value)


def test_explicit_cert_reqs_none_needs_no_ca_bundle(tmp_path):
    """An explicit opt-out is coherent, unlike an accidental one."""
    api = ApiConfig(ssl_certfile=tmp_path / "c.pem", ssl_cert_reqs="none")

    assert api.uvicorn_ssl_kwargs()["ssl_cert_reqs"] == ssl.CERT_NONE


def test_coherent_mtls_config_is_accepted(tmp_path):
    api = ApiConfig(
        ssl_certfile=tmp_path / "c.pem",
        ssl_keyfile=tmp_path / "k.pem",
        ssl_ca_certs=tmp_path / "ca.pem",
        ssl_cert_reqs="required",
    )

    assert api.uvicorn_ssl_kwargs()["ssl_cert_reqs"] == ssl.CERT_REQUIRED


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


# --- live HTTPS / mTLS -----------------------------------------------------


def _openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True, capture_output=True)


#: Python 3.13 enables VERIFY_X509_STRICT in create_default_context(), so a CA
#: that signs other certificates must carry keyUsage=keyCertSign. `openssl req
#: -x509` adds basicConstraints=CA:TRUE by default but not keyUsage.
CA_EXTENSIONS = [
    "-addext", "basicConstraints=critical,CA:TRUE",
    "-addext", "keyUsage=critical,keyCertSign,cRLSign",
]

SERVER_EXT = (
    "subjectAltName=IP:127.0.0.1,DNS:localhost\n"
    "extendedKeyUsage=serverAuth\n"
    "keyUsage=critical,digitalSignature,keyEncipherment\n"
    "basicConstraints=critical,CA:FALSE\n"
)

CLIENT_EXT = (
    "extendedKeyUsage=clientAuth\n"
    "keyUsage=critical,digitalSignature\n"
    "basicConstraints=critical,CA:FALSE\n"
)


def mint_self_signed_cert(directory: Path) -> tuple[Path, Path]:
    cert = directory / "cert.pem"
    key = directory / "key.pem"
    _openssl(
        "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", str(key), "-out", str(cert),
        "-days", "1", "-nodes", "-subj", "/CN=127.0.0.1",
        "-addext", "subjectAltName=IP:127.0.0.1",
    )
    return cert, key


def _sign(directory: Path, name: str, *, subject: str, ext: str) -> tuple[Path, Path]:
    """Issue ``name``-cert.pem signed by the CA already present in ``directory``."""
    key = directory / f"{name}-key.pem"
    cert = directory / f"{name}-cert.pem"
    csr = directory / f"{name}.csr"
    extfile = directory / f"{name}.ext"
    _openssl(
        "req", "-newkey", "rsa:2048", "-keyout", str(key), "-out", str(csr),
        "-nodes", "-subj", subject,
    )
    extfile.write_text(ext)
    _openssl(
        "x509", "-req", "-in", str(csr),
        "-CA", str(directory / "ca-cert.pem"), "-CAkey", str(directory / "ca-key.pem"),
        "-CAcreateserial", "-out", str(cert), "-days", "1", "-extfile", str(extfile),
    )
    return cert, key


def _mint_ca(directory: Path, *, name: str, subject: str) -> tuple[Path, Path]:
    cert = directory / f"{name}-cert.pem" if name != "ca" else directory / "ca-cert.pem"
    key = directory / f"{name}-key.pem" if name != "ca" else directory / "ca-key.pem"
    _openssl(
        "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", str(key), "-out", str(cert),
        "-days", "1", "-nodes", "-subj", subject,
        *CA_EXTENSIONS,
    )
    return cert, key


def mint_pki(directory: Path) -> SimpleNamespace:
    """A CA, a server cert, a client cert, and a rogue CA with its own client cert.

    The rogue CA is well-formed on purpose: its client certificate must be
    rejected because the issuer is untrusted, not because the cert is malformed.
    """
    ca_cert, ca_key = _mint_ca(directory, name="ca", subject="/CN=Relay Test CA")

    server_cert, server_key = _sign(
        directory, "server", subject="/CN=127.0.0.1", ext=SERVER_EXT
    )
    client_cert, client_key = _sign(
        directory, "client", subject="/CN=relay-client", ext=CLIENT_EXT
    )

    rogue_ca_cert, rogue_ca_key = _mint_ca(
        directory, name="rogue-ca", subject="/CN=Rogue CA"
    )
    rogue_key = directory / "rogue-client-key.pem"
    rogue_cert = directory / "rogue-client-cert.pem"
    rogue_csr = directory / "rogue-client.csr"
    rogue_ext = directory / "rogue-client.ext"
    _openssl(
        "req", "-newkey", "rsa:2048", "-keyout", str(rogue_key), "-out", str(rogue_csr),
        "-nodes", "-subj", "/CN=rogue-client",
    )
    rogue_ext.write_text(CLIENT_EXT)
    _openssl(
        "x509", "-req", "-in", str(rogue_csr),
        "-CA", str(rogue_ca_cert), "-CAkey", str(rogue_ca_key), "-CAcreateserial",
        "-out", str(rogue_cert), "-days", "1", "-extfile", str(rogue_ext),
    )

    return SimpleNamespace(
        ca=ca_cert,
        server_cert=server_cert, server_key=server_key,
        client_cert=client_cert, client_key=client_key,
        rogue_cert=rogue_cert, rogue_key=rogue_key,
    )


class StubRelay:
    """Stands in for SmtpRelay so the TLS tests need no mailhost."""

    def __init__(self) -> None:
        self.sent: list[tuple[EmailMessage, str, list[str]]] = []

    def send(self, message: EmailMessage, *, sender: str, recipients: list[str]) -> str:
        self.sent.append((message, sender, list(recipients)))
        return str(message["Message-ID"])


def build_settings(api: ApiConfig) -> AppConfig:
    return AppConfig(
        api=api,
        smtp=SmtpConfig(host="mail.example.com", port=587),
        policy=PolicyConfig(sender="relay@example.com", allowed_domains=["example.com"]),
    )


@contextmanager
def running_tls_server(settings: AppConfig):
    """Start a real uvicorn TLS listener and stop it again on exit."""
    api = settings.api
    server = uvicorn.Server(
        uvicorn.Config(
            create_app(settings),
            host=api.host,
            port=api.port,
            # Keep uvicorn from installing its own handlers over the test config.
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
        yield server
    finally:
        server.should_exit = True
        thread.join(timeout=20)


def client_identity(pki: SimpleNamespace, *, rogue: bool = False) -> ssl.SSLContext:
    """An httpx-ready client context trusting the CA and presenting a client cert.

    httpx deprecates ``verify=<str>``, so callers pass an SSLContext.
    """
    ctx = ssl.create_default_context(cafile=str(pki.ca))
    cert, key = (pki.rogue_cert, pki.rogue_key) if rogue else (pki.client_cert, pki.client_key)
    ctx.load_cert_chain(str(cert), str(key))
    return ctx


def server_only_trust(pki: SimpleNamespace) -> ssl.SSLContext:
    """A client context that trusts the server but presents no identity."""
    return ssl.create_default_context(cafile=str(pki.ca))


@pytest.fixture
def https_server(tmp_path, monkeypatch):
    """Server-side TLS only, no client certificates.

    Only reached from ``@requires_openssl`` tests, so no mark is needed here
    (pytest forbids marks on fixtures).
    """
    cert, key = mint_self_signed_cert(tmp_path)
    stub = StubRelay()
    monkeypatch.setattr("app.main.SmtpRelay", lambda _config: stub)

    port = free_port()
    api = ApiConfig(host="127.0.0.1", port=port, ssl_certfile=cert, ssl_keyfile=key)

    with running_tls_server(build_settings(api)):
        yield SimpleNamespace(
            port=port,
            cert=cert,
            relay=stub,
            verify_ctx=ssl.create_default_context(cafile=str(cert)),
        )


def _mtls_fixture(tmp_path, monkeypatch, cert_reqs: str) -> SimpleNamespace:
    pki = mint_pki(tmp_path)
    stub = StubRelay()
    monkeypatch.setattr("app.main.SmtpRelay", lambda _config: stub)

    port = free_port()
    api = ApiConfig(
        host="127.0.0.1",
        port=port,
        ssl_certfile=pki.server_cert,
        ssl_keyfile=pki.server_key,
        ssl_ca_certs=pki.ca,
        ssl_cert_reqs=cert_reqs,
    )
    return SimpleNamespace(port=port, pki=pki, relay=stub, settings=build_settings(api))


@pytest.fixture
def mtls_server(tmp_path, monkeypatch):
    """Server-side TLS with client certificates required."""
    context = _mtls_fixture(tmp_path, monkeypatch, "required")
    with running_tls_server(context.settings):
        yield context


@pytest.fixture
def optional_mtls_server(tmp_path, monkeypatch):
    """Server-side TLS with client certificates requested but not required."""
    context = _mtls_fixture(tmp_path, monkeypatch, "optional")
    with running_tls_server(context.settings):
        yield context


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


# --- mutual TLS ------------------------------------------------------------


@requires_openssl
def test_mtls_accepts_a_client_certificate_from_the_trusted_ca(mtls_server):
    with httpx.Client(verify=client_identity(mtls_server.pki)) as client:
        response = client.get(f"https://127.0.0.1:{mtls_server.port}/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@requires_openssl
def test_mtls_rejects_a_client_without_a_certificate(mtls_server):
    """A client that trusts the server but presents no identity must be refused."""
    with httpx.Client(verify=server_only_trust(mtls_server.pki)) as client:
        with pytest.raises(httpx.TransportError):
            client.get(f"https://127.0.0.1:{mtls_server.port}/health")

    assert mtls_server.relay.sent == []


@requires_openssl
def test_mtls_rejects_a_client_certificate_from_an_untrusted_ca(mtls_server):
    """The security-critical case: a valid-looking cert signed by the wrong CA."""
    with httpx.Client(verify=client_identity(mtls_server.pki, rogue=True)) as client:
        with pytest.raises(httpx.TransportError):
            client.get(f"https://127.0.0.1:{mtls_server.port}/health")

    assert mtls_server.relay.sent == []


@requires_openssl
def test_mtls_post_is_relayed_for_an_allowed_domain(mtls_server):
    """Proves the request reached FastAPI, not merely that the handshake passed."""
    with httpx.Client(verify=client_identity(mtls_server.pki)) as client:
        response = client.post(
            f"https://127.0.0.1:{mtls_server.port}/mail",
            json={
                "recipients": ["alice@example.com"],
                "subject": "Over mTLS",
                "body": "Delivered after a mutual-TLS handshake.",
            },
        )

    assert response.status_code == 200, response.text
    assert len(mtls_server.relay.sent) == 1
    assert mtls_server.relay.sent[0][2] == ["alice@example.com"]


@requires_openssl
def test_mtls_post_still_enforces_the_domain_allowlist(mtls_server):
    """mTLS authenticates the client; the allowlist still governs the content."""
    with httpx.Client(verify=client_identity(mtls_server.pki)) as client:
        response = client.post(
            f"https://127.0.0.1:{mtls_server.port}/mail",
            json={
                "recipients": ["eve@evil.com"],
                "subject": "Nope",
                "body": "Post-handshake policy check.",
            },
        )

    assert response.status_code == 400
    assert response.json()["code"] == "domain_not_allowed"
    assert mtls_server.relay.sent == []


@requires_openssl
def test_cert_reqs_optional_allows_clients_without_a_certificate(optional_mtls_server):
    """The behavioural difference between "optional" and "required"."""
    with httpx.Client(verify=server_only_trust(optional_mtls_server.pki)) as client:
        response = client.get(f"https://127.0.0.1:{optional_mtls_server.port}/health")

    assert response.status_code == 200


@requires_openssl
def test_cert_reqs_optional_still_accepts_a_valid_client_cert(optional_mtls_server):
    with httpx.Client(verify=client_identity(optional_mtls_server.pki)) as client:
        response = client.get(f"https://127.0.0.1:{optional_mtls_server.port}/health")

    assert response.status_code == 200


@requires_openssl
def test_uvicorn_builds_a_context_that_requests_and_can_verify_clients(tmp_path):
    """Assert against uvicorn's real context builder, not a model of it.

    uvicorn sets ``verify_mode`` unconditionally but calls
    ``load_verify_locations`` only when ``ca_certs`` is given. That asymmetry is
    exactly why ApiConfig rejects the two incoherent combinations; this test
    pins the behaviour the validator is protecting against.
    """
    pki = mint_pki(tmp_path)
    api = ApiConfig(
        ssl_certfile=pki.server_cert,
        ssl_keyfile=pki.server_key,
        ssl_ca_certs=pki.ca,
        ssl_cert_reqs="required",
    )
    kwargs = api.uvicorn_ssl_kwargs()

    ctx = create_ssl_context(
        certfile=kwargs["ssl_certfile"],
        keyfile=kwargs.get("ssl_keyfile"),
        password=kwargs.get("ssl_keyfile_password"),
        ssl_version=ssl.PROTOCOL_TLS_SERVER,
        cert_reqs=kwargs.get("ssl_cert_reqs", ssl.CERT_NONE),
        ca_certs=kwargs.get("ssl_ca_certs"),
        ciphers=kwargs.get("ssl_ciphers"),
    )

    assert ctx.verify_mode is ssl.CERT_REQUIRED
    assert len(ctx.get_ca_certs()) == 1


def test_omitting_cert_reqs_would_leave_verification_off(tmp_path):
    """Documents the trap the coherence validator exists to prevent.

    uvicorn defaults ``ssl_cert_reqs`` to CERT_NONE, so a CA bundle passed
    without it loads trust anchors that are never used.
    """
    kwargs = ApiConfig(ssl_certfile=tmp_path / "c.pem").uvicorn_ssl_kwargs()

    assert "ssl_cert_reqs" not in kwargs
    assert kwargs.get("ssl_cert_reqs", ssl.CERT_NONE) == ssl.CERT_NONE
