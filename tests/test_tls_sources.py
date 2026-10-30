"""Certificate sources beyond PEM files: PKCS#12 and the Windows certificate store.

The Windows store cannot be exercised on the Linux test host, so its CryptoAPI
surface (``win32crypt`` / ``win32cryptcon`` / ``pywintypes``) is replaced by a
fake that behaves like the real store: it enumerates DER certificates and
exports the selected one as a password-protected PKCS#12 blob. Everything after
the export - decoding, the temporary PEM files, the OpenSSL context - is the
real code path, and the handshake test proves the key actually works.
"""

from __future__ import annotations

import datetime as dt
import os
import socket
import ssl
import sys
import threading
import types
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from pydantic import ValidationError

import app.tls as tls
from app.config import ApiConfig, AppConfig, ConfigError, PolicyConfig, SmtpConfig, load_config

MINIMAL_TOML = '[smtp]\nhost = "mail.example.com"\n\n[policy]\nsender = "relay@example.com"\n'


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch):
    for name in [key for key in os.environ if key.startswith("RELAY_")]:
        monkeypatch.delenv(name, raising=False)


# ------------------------------------------------------------------ fixtures


class Material:
    """A self-signed server certificate for ``localhost`` plus a stand-in CA chain entry."""

    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = dt.datetime.now(dt.timezone.utc)
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(self.key, hashes.SHA256())
        )
        # A second, unrelated self-signed certificate plays the "chain".
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Example Issuing CA")])
        self.extra = (
            x509.CertificateBuilder()
            .subject_name(other_name)
            .issuer_name(other_name)
            .public_key(other_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=1))
            .sign(other_key, hashes.SHA256())
        )

    @property
    def der(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.DER)

    @property
    def pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    @property
    def thumbprint(self) -> str:
        import hashlib

        return hashlib.sha1(self.der).hexdigest().upper()

    def pfx(self, password: str | None, *, with_key: bool = True, with_chain: bool = True) -> bytes:
        encryption = (
            serialization.BestAvailableEncryption(password.encode())
            if password
            else serialization.NoEncryption()
        )
        return pkcs12.serialize_key_and_certificates(
            b"smtp-relay",
            self.key if with_key else None,
            self.cert,
            [self.extra] if with_chain else None,
            encryption,
        )


@pytest.fixture(scope="module")
def material() -> Material:
    return Material()


def build(api: ApiConfig) -> AppConfig:
    return AppConfig(
        api=api,
        smtp=SmtpConfig(host="mail.example.com"),
        policy=PolicyConfig(sender="relay@example.com"),
    )


def handshake(context: ssl.SSLContext, trust_pem: bytes) -> dict:
    """Serve one TLS handshake with ``context``; return the certificate the client saw."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    errors: list[BaseException] = []

    def serve() -> None:
        try:
            conn, _ = listener.accept()
            with context.wrap_socket(conn, server_side=True) as tls_conn:
                tls_conn.recv(1)
        except BaseException as exc:  # pragma: no cover - surfaced via `errors`
            errors.append(exc)

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    client = ssl.create_default_context(cadata=trust_pem.decode())
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with client.wrap_socket(raw, server_hostname="localhost") as tls_sock:
            peer = tls_sock.getpeercert()
            tls_sock.sendall(b"x")
    worker.join(timeout=5)
    listener.close()
    assert not errors, errors
    return peer


# ------------------------------------------------------------- PKCS#12 file


def test_pfx_source_serves_a_working_certificate(tmp_path, material):
    pfx = tmp_path / "relay.pfx"
    pfx.write_bytes(material.pfx("hunter2"))
    api = ApiConfig(ssl_pfxfile=pfx, ssl_pfx_password="hunter2")

    context = tls.build_ssl_context(api)
    peer = handshake(context, material.pem)

    assert ("commonName", "localhost") in [item for rdn in peer["subject"] for item in rdn]


def test_pfx_without_passphrase_is_accepted(tmp_path, material):
    pfx = tmp_path / "relay.pfx"
    pfx.write_bytes(material.pfx(None))

    context, info = tls.context_from_pkcs12(pfx.read_bytes(), None)

    assert isinstance(context, ssl.SSLContext)
    assert info.subject == "CN=localhost"
    assert info.thumbprint == material.thumbprint
    assert info.chain_length == 1


def test_wrong_passphrase_is_a_readable_error(tmp_path, material):
    with pytest.raises(tls.TlsError) as excinfo:
        tls.context_from_pkcs12(material.pfx("right"), "wrong", source="relay.pfx")
    assert "relay.pfx" in str(excinfo.value)
    assert "passphrase" in str(excinfo.value).lower()


def test_pfx_without_a_private_key_is_rejected(material):
    with pytest.raises(tls.TlsError, match="no private key"):
        tls.context_from_pkcs12(material.pfx("pw", with_key=False), "pw")


def test_missing_pfx_file_is_reported_with_its_path(tmp_path):
    api = ApiConfig(ssl_pfxfile=tmp_path / "nope.pfx")
    with pytest.raises(tls.TlsError, match="nope.pfx"):
        tls.build_ssl_context(api)


def test_temporary_pem_files_do_not_outlive_the_context(tmp_path, material, monkeypatch):
    """The decrypted key is on disk only while OpenSSL reads it."""
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    import tempfile

    tempfile.tempdir = None  # make tempfile re-read TMPDIR
    try:
        tls.context_from_pkcs12(material.pfx("pw"), "pw")
    finally:
        tempfile.tempdir = None
    assert not list(tmp_path.glob("smtp-relay-tls-*")), "temporary key directory left behind"


def test_temporary_key_file_is_encrypted_and_private(tmp_path, material, monkeypatch):
    """Even during its short life the key file is PEM-encrypted under a one-time passphrase."""
    seen: dict[str, bytes] = {}
    real_write = tls._write_private

    def spy(path: Path, data: bytes) -> Path:
        seen[path.name] = data
        result = real_write(path, data)
        if os.name == "posix":
            assert (path.stat().st_mode & 0o777) == 0o600
        return result

    monkeypatch.setattr(tls, "_write_private", spy)
    tls.context_from_pkcs12(material.pfx("pw"), "pw")

    assert b"ENCRYPTED PRIVATE KEY" in seen["key.pem"]
    assert b"BEGIN PRIVATE KEY" not in seen["key.pem"]
    assert seen["chain.pem"].count(b"BEGIN CERTIFICATE") == 2  # leaf + chain entry


def test_pfx_source_honours_mtls_settings(tmp_path, material):
    pfx = tmp_path / "relay.pfx"
    pfx.write_bytes(material.pfx("pw"))
    ca = tmp_path / "clients.pem"
    ca.write_bytes(material.extra.public_bytes(serialization.Encoding.PEM))
    api = ApiConfig(
        ssl_pfxfile=pfx, ssl_pfx_password="pw", ssl_ca_certs=ca, ssl_cert_reqs="required"
    )

    context = tls.build_ssl_context(api)

    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.cert_store_stats()["x509"] >= 1, "client CA bundle not loaded"


# -------------------------------------------------------- uvicorn hand-over


def test_pfx_source_is_handed_to_uvicorn_as_a_ready_context(tmp_path, material):
    pfx = tmp_path / "relay.pfx"
    pfx.write_bytes(material.pfx("pw"))
    api = ApiConfig(ssl_pfxfile=pfx, ssl_pfx_password="pw")

    kwargs = api.uvicorn_ssl_kwargs()

    assert set(kwargs) == {"ssl_context_factory"}, kwargs
    # uvicorn's calling convention: factory(config, default_factory).
    factory = kwargs["ssl_context_factory"]
    context = factory(object(), lambda: None)
    assert isinstance(context, ssl.SSLContext)
    assert factory(object(), lambda: None) is context, "built once, at startup"


def test_context_factory_matches_uvicorns_calling_convention(tmp_path, material):
    """Drive the real uvicorn Config.load(), which is what the first end-to-end run
    tripped over: a zero-argument factory raised TypeError there."""
    import uvicorn

    pfx = tmp_path / "relay.pfx"
    pfx.write_bytes(material.pfx("pw"))
    api = ApiConfig(ssl_pfxfile=pfx, ssl_pfx_password="pw")

    async def asgi(scope, receive, send):  # pragma: no cover - never served
        pass

    # A callable app, so load() does not import anything or read a config file.
    config = uvicorn.Config(asgi, **api.uvicorn_ssl_kwargs())
    config.load()

    assert isinstance(config.ssl, ssl.SSLContext)
    assert config.is_ssl


def test_pem_source_is_still_passed_as_file_paths(tmp_path):
    api = ApiConfig(ssl_certfile=tmp_path / "c.pem", ssl_keyfile=tmp_path / "k.pem")
    kwargs = api.uvicorn_ssl_kwargs()
    assert "ssl_context_factory" not in kwargs
    assert kwargs["ssl_certfile"].endswith("c.pem")


def test_bad_pfx_surfaces_as_a_config_error_at_startup(tmp_path, material):
    """The entry points catch ConfigError; a TlsError must not leak past them."""
    pfx = tmp_path / "relay.pfx"
    pfx.write_bytes(material.pfx("right"))
    api = ApiConfig(ssl_pfxfile=pfx, ssl_pfx_password="wrong")

    with pytest.raises(ConfigError, match="passphrase"):
        api.uvicorn_ssl_kwargs()


def test_entry_points_build_the_context_inside_their_config_error_guard():
    """Both ``python -m app`` and the service must call ``uvicorn_ssl_kwargs()``
    inside the ``try`` that handles ``ConfigError``, otherwise a bad PFX is a
    traceback (CLI) or a dead worker thread behind a RUNNING service."""
    import ast

    root = Path(__file__).resolve().parents[1]
    for module in ("app/__main__.py", "app/windows_service.py"):
        tree = ast.parse((root / module).read_text())
        guarded = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Try):
                continue
            handles_config_error = any(
                isinstance(h.type, ast.Name) and h.type.id == "ConfigError" for h in node.handlers
            )
            if handles_config_error and "uvicorn_ssl_kwargs" in ast.unparse(node.body):
                guarded = True
        assert guarded, f"{module}: uvicorn_ssl_kwargs() is not under the ConfigError guard"


# ---------------------------------------------------------- Windows store


class FakeWinError(Exception):
    """Shape of ``pywintypes.error``: ``(winerror, funcname, message)``."""


class FakeCertContext:
    def __init__(self, der: bytes, key=None, exportable: bool = True) -> None:
        self.CertEncoded = der
        self.key = key
        self.exportable = exportable


class FakeStore:
    def __init__(self, contexts: list[FakeCertContext], material: Material) -> None:
        self.contexts = list(contexts)
        self.material = material
        self.closed = False

    def CertEnumCertificatesInStore(self):
        return list(self.contexts)

    def CertAddCertificateContextToStore(self, ctx, disposition):
        assert disposition == 4  # CERT_STORE_ADD_ALWAYS
        self.contexts.append(ctx)

    def PFXExportCertStoreEx(self, password, flags):
        assert flags & 0x4, "EXPORT_PRIVATE_KEYS must be requested"
        ctx = self.contexts[0]
        if ctx.key is None:
            raise FakeWinError(-2146893802, "PFXExportCertStoreEx", "Key does not exist.")
        if not ctx.exportable:
            raise FakeWinError(-2146893813, "PFXExportCertStoreEx", "Key not valid for use in specified state.")
        cert = x509.load_der_x509_certificate(ctx.CertEncoded)
        return pkcs12.serialize_key_and_certificates(
            b"exported", ctx.key, cert, None, serialization.BestAvailableEncryption(password.encode())
        )

    def CertCloseStore(self, flags):
        self.closed = True


@pytest.fixture
def fake_store(monkeypatch, material):
    """Install fake pywin32 modules; return the system store so tests can populate it."""
    system = FakeStore([], material)
    opened: list[FakeStore] = []

    def open_store(provider, encoding, prov, flags, para):
        if provider == 10:  # CERT_STORE_PROV_SYSTEM
            assert para == "MY" and flags & 0x8000, "store must be opened read-only"
            opened.append(system)
            return system
        assert provider == 2  # CERT_STORE_PROV_MEMORY
        memory = FakeStore([], material)
        opened.append(memory)
        return memory

    win32crypt = types.ModuleType("win32crypt")
    win32crypt.CertOpenStore = open_store
    con = types.ModuleType("win32cryptcon")
    con.CERT_STORE_PROV_SYSTEM = 10
    con.CERT_STORE_PROV_MEMORY = 2
    con.CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x20000
    con.CERT_STORE_READONLY_FLAG = 0x8000
    con.CERT_STORE_OPEN_EXISTING_FLAG = 0x4000
    con.CERT_STORE_ADD_ALWAYS = 4
    con.EXPORT_PRIVATE_KEYS = 0x4
    con.REPORT_NO_PRIVATE_KEY = 0x1
    con.REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY = 0x2
    pywintypes = types.ModuleType("pywintypes")
    pywintypes.error = FakeWinError
    monkeypatch.setitem(sys.modules, "win32crypt", win32crypt)
    monkeypatch.setitem(sys.modules, "win32cryptcon", con)
    monkeypatch.setitem(sys.modules, "pywintypes", pywintypes)
    monkeypatch.setattr(tls, "windows_store_available", lambda: True)
    system.opened = opened
    return system


def test_store_source_exports_the_matching_certificate_and_serves_it(fake_store, material):
    fake_store.contexts.append(FakeCertContext(material.extra.public_bytes(serialization.Encoding.DER)))
    fake_store.contexts.append(FakeCertContext(material.der, material.key))
    api = ApiConfig(ssl_cert_thumbprint=material.thumbprint.lower())

    context = tls.build_ssl_context(api)
    peer = handshake(context, material.pem)

    assert ("commonName", "localhost") in [item for rdn in peer["subject"] for item in rdn]
    assert all(store.closed for store in fake_store.opened), "store handles leaked"


def test_store_source_accepts_thumbprints_as_certlm_shows_them(fake_store, material):
    fake_store.contexts.append(FakeCertContext(material.der, material.key))
    spaced = " ".join(material.thumbprint[i : i + 2] for i in range(0, 40, 2)).lower()

    api = ApiConfig(ssl_cert_thumbprint=spaced)

    assert api.ssl_cert_thumbprint == material.thumbprint
    assert isinstance(tls.build_ssl_context(api), ssl.SSLContext)


def test_missing_certificate_names_the_store_and_the_installer(fake_store, material):
    api = ApiConfig(ssl_cert_thumbprint=material.thumbprint)
    with pytest.raises(tls.TlsError) as excinfo:
        tls.build_ssl_context(api)
    message = str(excinfo.value)
    assert material.thumbprint in message
    assert "LocalMachine\\MY" in message
    assert "-PfxPath" in message


def test_non_exportable_key_explains_the_way_out(fake_store, material):
    fake_store.contexts.append(FakeCertContext(material.der, material.key, exportable=False))
    api = ApiConfig(ssl_cert_thumbprint=material.thumbprint)

    with pytest.raises(tls.TlsError) as excinfo:
        tls.build_ssl_context(api)
    message = str(excinfo.value)
    assert "exportable" in message
    assert "0x8009000B" in message, "the CryptoAPI error code must be visible"
    assert "behind_tls_proxy" in message, "the non-exportable route must be named"


def test_certificate_without_key_in_store_is_rejected(fake_store, material):
    fake_store.contexts.append(FakeCertContext(material.der, key=None))
    with pytest.raises(tls.TlsError, match="private key"):
        tls.build_ssl_context(ApiConfig(ssl_cert_thumbprint=material.thumbprint))


def test_store_source_is_refused_off_windows(monkeypatch, material):
    monkeypatch.setattr(tls, "windows_store_available", lambda: sys.platform == "win32")
    if sys.platform == "win32":  # pragma: no cover - the real thing
        pytest.skip("runs on the Linux test host only")
    with pytest.raises(ValidationError, match="only available on Windows"):
        ApiConfig(ssl_cert_thumbprint=material.thumbprint)


# ------------------------------------------------------------ validators


@pytest.mark.parametrize("bad", ["abc", "zz" * 20, "0123456789" * 3, ""])
def test_malformed_thumbprints_are_rejected(monkeypatch, bad):
    monkeypatch.setattr(tls, "windows_store_available", lambda: True)
    with pytest.raises(ValidationError, match="40 hexadecimal digits"):
        ApiConfig(ssl_cert_thumbprint=bad)


def test_two_certificate_sources_are_rejected(tmp_path, monkeypatch, material):
    monkeypatch.setattr(tls, "windows_store_available", lambda: True)
    with pytest.raises(ValidationError, match="choose one certificate source"):
        ApiConfig(ssl_certfile=tmp_path / "c.pem", ssl_pfxfile=tmp_path / "c.pfx")
    with pytest.raises(ValidationError, match="choose one certificate source"):
        ApiConfig(ssl_pfxfile=tmp_path / "c.pfx", ssl_cert_thumbprint=material.thumbprint)


def test_pfx_password_without_pfxfile_is_dangling(tmp_path):
    with pytest.raises(ValidationError, match="ssl_pfxfile is required"):
        ApiConfig(ssl_pfx_password="pw")
    # ...and PEM-only options still demand the PEM source, not the PFX one.
    with pytest.raises(ValidationError, match="ssl_certfile is required"):
        ApiConfig(ssl_pfxfile=tmp_path / "c.pfx", ssl_keyfile=tmp_path / "k.pem")


def test_mtls_options_combine_with_any_source(tmp_path):
    api = ApiConfig(ssl_pfxfile=tmp_path / "c.pfx", ssl_ca_certs=tmp_path / "ca.pem", ssl_cert_reqs="required")
    assert api.verify_mode == ssl.CERT_REQUIRED
    with pytest.raises(ValidationError, match="certificate source .* is required"):
        ApiConfig(ssl_ca_certs=tmp_path / "ca.pem", ssl_cert_reqs="required")


def test_pfx_source_satisfies_the_network_exposure_rule(tmp_path):
    config = build(ApiConfig(host="0.0.0.0", ssl_pfxfile=tmp_path / "c.pfx", token="s3cret"))
    assert config.api.tls_enabled is True
    assert config.api.scheme == "https"


def test_store_source_satisfies_the_network_exposure_rule(monkeypatch, material):
    monkeypatch.setattr(tls, "windows_store_available", lambda: True)
    config = build(ApiConfig(host="0.0.0.0", ssl_cert_thumbprint=material.thumbprint, token="s3cret"))
    assert config.api.tls_enabled is True


def test_cleartext_rejection_names_every_source():
    with pytest.raises(ValidationError) as excinfo:
        build(ApiConfig(host="0.0.0.0", token="s3cret"))
    message = str(excinfo.value)
    for key in ("api.ssl_certfile", "api.ssl_pfxfile", "api.ssl_cert_thumbprint"):
        assert key in message


def test_behind_proxy_excludes_the_pfx_source_too(tmp_path):
    with pytest.raises(ValidationError, match="ssl_pfxfile"):
        ApiConfig(host="0.0.0.0", behind_tls_proxy=True, ssl_pfxfile=tmp_path / "c.pfx", token="t")


def test_pfx_keys_come_from_the_environment(tmp_path, monkeypatch, material):
    path = tmp_path / "config.toml"
    path.write_text(MINIMAL_TOML)
    monkeypatch.setenv("RELAY_API_SSL_PFXFILE", str(tmp_path / "env.pfx"))
    monkeypatch.setenv("RELAY_API_SSL_PFX_PASSWORD", "from-env")

    config = load_config(path)

    assert config.api.ssl_pfxfile == tmp_path / "env.pfx"
    assert config.api.ssl_pfx_password == "from-env"


def test_thumbprint_comes_from_the_environment(tmp_path, monkeypatch, material):
    monkeypatch.setattr(tls, "windows_store_available", lambda: True)
    path = tmp_path / "config.toml"
    path.write_text(MINIMAL_TOML)
    monkeypatch.setenv("RELAY_API_SSL_CERT_THUMBPRINT", material.thumbprint.lower())

    config = load_config(path)

    assert config.api.ssl_cert_thumbprint == material.thumbprint
