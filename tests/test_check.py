"""``python -m app --check``: the probes against real SMTP servers and real certificates.

The mailhost side runs on aiosmtpd, so the checks are exercised against the
genuine wire behaviour (EHLO extensions, AUTH replies, STARTTLS) rather than
against assumptions about it.
"""

from __future__ import annotations

import datetime as dt
import socket
import ssl
import warnings
from pathlib import Path

import pytest
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app import __main__ as entry
from app.check import CheckResult, exit_code, render, run_checks
from app.config import ApiConfig, AppConfig, ConfigError, PolicyConfig, SmtpConfig

PASSWORD = "s3cret-never-printed"


# ------------------------------------------------------------------ helpers


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def by_name(results: list[CheckResult]) -> dict[str, CheckResult]:
    return {result.name: result for result in results}


def settings(port: int, *, security: str = "none", sender: str = "relay@example.com", **smtp) -> AppConfig:
    return AppConfig(
        api=ApiConfig(),
        smtp=SmtpConfig(host="127.0.0.1", port=port, security=security, timeout=5.0, **smtp),
        policy=PolicyConfig(sender=sender, allowed_domains=["example.com"]),
    )


def self_signed(tmp_path: Path, *, days: int = 365, name: str = "localhost") -> tuple[Path, Path]:
    """Write a self-signed certificate (SAN localhost + 127.0.0.1) and key as PEM."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=400))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / f"cert-{days}.pem"
    key_path = tmp_path / f"key-{days}.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


class Sink:
    async def handle_DATA(self, server, session, envelope):
        return "250 OK"


class RefusesSender(Sink):
    """What iCloud does when the From address is not the account's."""

    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        return "550 5.7.0 From address is not one of your addresses"


def authenticator(server, session, envelope, mechanism, data):
    ok = isinstance(data, LoginPassword) and data.login == b"relay" and data.password == PASSWORD.encode()
    # handled=False: let aiosmtpd send the 235/535 reply. With the default
    # (True) a failed login gets no reply at all and the client waits forever.
    return AuthResult(success=ok, handled=False)


def start(handler, **kwargs) -> Controller:
    port = free_port()
    with warnings.catch_warnings():
        # aiosmtpd warns about AUTH without TLS; that is exactly the point here.
        warnings.simplefilter("ignore")
        controller = Controller(handler, hostname="127.0.0.1", port=port, **kwargs)
        controller.start()
    return controller


@pytest.fixture
def plain_server():
    controller = start(Sink())
    yield controller.port
    controller.stop()


@pytest.fixture
def auth_server():
    controller = start(Sink(), auth_required=True, auth_require_tls=False, authenticator=authenticator)
    yield controller.port
    controller.stop()


@pytest.fixture
def starttls_server(tmp_path):
    cert, key = self_signed(tmp_path)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    controller = start(Sink(), tls_context=context)
    yield controller.port, cert
    controller.stop()


# ------------------------------------------------------------ smtp probes


def test_plain_sink_passes_without_credentials(plain_server):
    results = by_name(run_checks(settings(plain_server)))

    assert results["smtp.dns"].status == "ok"
    assert results["smtp.session"].status == "ok"
    assert "cleartext" in results["smtp.session"].detail
    assert results["smtp.auth"].status == "skip"
    assert results["smtp.sender"].status == "ok"
    assert exit_code(list(results.values())) == 0


def test_good_credentials_authenticate_and_offer_the_sender(auth_server):
    results = by_name(run_checks(settings(auth_server, username="relay", password=PASSWORD)))

    assert "AUTH" in results["smtp.session"].detail
    assert results["smtp.auth"] == CheckResult("smtp.auth", "ok", "authenticated as relay")
    assert results["smtp.sender"].status == "ok"


def test_wrong_password_fails_auth_and_skips_the_sender_probe(auth_server):
    results = by_name(run_checks(settings(auth_server, username="relay", password="wrong")))

    assert results["smtp.auth"].status == "fail"
    assert "535" in results["smtp.auth"].detail
    assert "relay" in results["smtp.auth"].detail
    assert "wrong" not in results["smtp.auth"].detail
    assert results["smtp.sender"].status == "skip"
    assert exit_code(list(results.values())) == 1


def test_missing_username_is_flagged_when_the_mailhost_offers_auth(auth_server):
    """Today's field problem: credentials half-configured, mailhost says 'access denied'."""
    results = by_name(run_checks(settings(auth_server)))

    assert results["smtp.auth"].status == "warn"
    assert "smtp.username is not set" in results["smtp.auth"].detail
    assert results["smtp.sender"].status == "fail"
    assert "530" in results["smtp.sender"].detail


def test_sender_refused_by_the_mailhost_is_a_failure():
    controller = start(RefusesSender())
    try:
        results = by_name(run_checks(settings(controller.port)))
    finally:
        controller.stop()

    assert results["smtp.sender"].status == "fail"
    assert "550 5.7.0 From address is not one of your addresses" in results["smtp.sender"].detail


def test_implicit_tls_against_a_plaintext_port_names_the_likely_fix(plain_server):
    results = by_name(run_checks(settings(plain_server, security="tls")))

    assert results["smtp.session"].status == "fail"
    assert 'security = "starttls"' in results["smtp.session"].detail
    assert "smtp.auth" not in results


def test_starttls_against_a_host_without_it_is_explained(plain_server):
    results = by_name(run_checks(settings(plain_server, security="starttls")))

    assert results["smtp.session"].status == "fail"
    assert "does not offer STARTTLS" in results["smtp.session"].detail


def test_starttls_session_verifies_the_server_certificate(starttls_server):
    port, cert = starttls_server
    results = by_name(run_checks(settings(port, security="starttls", ca_file=cert)))

    assert results["smtp.session"].status == "ok", results["smtp.session"].detail
    assert "STARTTLS, TLSv1" in results["smtp.session"].detail
    assert "server certificate verified" in results["smtp.session"].detail
    assert results["smtp.sender"].status == "ok"


def test_untrusted_server_certificate_points_at_ca_file(starttls_server):
    port, _cert = starttls_server
    results = by_name(run_checks(settings(port, security="starttls")))

    assert results["smtp.session"].status == "fail"
    assert "not trusted" in results["smtp.session"].detail
    assert "smtp.ca_file" in results["smtp.session"].detail


def test_cleartext_session_warns_when_starttls_is_offered(starttls_server):
    port, _cert = starttls_server
    results = by_name(run_checks(settings(port, security="none")))

    assert results["smtp.session"].status == "ok"
    assert results["smtp.tls"].status == "warn"
    assert 'security = "starttls"' in results["smtp.tls"].detail


def test_unresolvable_mailhost_stops_after_dns():
    config = AppConfig(
        smtp=SmtpConfig(host="nonexistent.invalid", port=25, timeout=5.0),
        policy=PolicyConfig(sender="relay@example.com", allowed_domains=["example.com"]),
    )

    results = by_name(run_checks(config))

    assert results["smtp.dns"].status == "fail"
    assert "nonexistent.invalid" in results["smtp.dns"].detail
    assert results["smtp.session"].status == "skip"


def test_closed_port_is_a_session_failure():
    results = by_name(run_checks(settings(free_port())))

    assert results["smtp.session"].status == "fail"
    assert "refused" in results["smtp.session"].detail.lower()


def test_no_smtp_skips_the_mailhost_entirely(plain_server):
    results = by_name(run_checks(settings(plain_server), smtp=False))

    assert results["smtp"].status == "skip"
    assert not any(name.startswith("smtp.") for name in results)


# ---------------------------------------------------------- offline probes


def test_loopback_api_without_tls_is_a_skip():
    results = by_name(run_checks(settings(1), smtp=False))

    assert results["api"].status == "ok"
    assert "loopback only" in results["api"].detail
    assert results["api.tls"].status == "skip"


def test_network_api_reports_how_clients_authenticate(tmp_path):
    cert, key = self_signed(tmp_path)
    config = AppConfig(
        api=ApiConfig(host="0.0.0.0", token="t", ssl_certfile=cert, ssl_keyfile=key),
        smtp=SmtpConfig(host="mail.example.com"),
        policy=PolicyConfig(sender="relay@example.com", allowed_domains=["example.com"]),
    )

    results = by_name(run_checks(config, smtp=False))

    assert "reachable from the network" in results["api"].detail
    assert "bearer token" in results["api"].detail
    assert results["api.tls"].status == "ok"
    assert f"PEM file {cert}" in results["api.tls"].detail
    assert "CN=localhost" in results["api.tls"].detail
    assert "valid for 36" in results["api.tls"].detail


def test_mutual_tls_reports_the_loaded_client_ca_bundle(tmp_path):
    cert, key = self_signed(tmp_path)
    config = AppConfig(
        api=ApiConfig(
            host="0.0.0.0",
            ssl_certfile=cert,
            ssl_keyfile=key,
            ssl_ca_certs=cert,
            ssl_cert_reqs="required",
        ),
        smtp=SmtpConfig(host="mail.example.com"),
        policy=PolicyConfig(sender="relay@example.com", allowed_domains=["example.com"]),
    )

    results = by_name(run_checks(config, smtp=False))

    assert "client certificate (mutual TLS)" in results["api"].detail
    assert results["api.tls"].status == "ok"
    assert "client certificates required, 1 CA certificate(s) loaded" in results["api.tls"].detail


@pytest.mark.parametrize(
    ("days", "status", "phrase"),
    [(10, "warn", "expires in 9 day(s)"), (-3, "fail", "EXPIRED")],
)
def test_certificate_expiry_is_graded(tmp_path, days, status, phrase):
    cert, key = self_signed(tmp_path, days=days)
    config = AppConfig(
        api=ApiConfig(ssl_certfile=cert, ssl_keyfile=key),
        smtp=SmtpConfig(host="mail.example.com"),
        policy=PolicyConfig(sender="relay@example.com", allowed_domains=["example.com"]),
    )

    result = by_name(run_checks(config, smtp=False))["api.tls"]

    assert result.status == status
    assert phrase in result.detail


def test_pfx_source_is_loaded_and_described(tmp_path):
    from cryptography.hazmat.primitives.serialization import pkcs12

    cert, key = self_signed(tmp_path)
    pfx = tmp_path / "server.pfx"
    pfx.write_bytes(
        pkcs12.serialize_key_and_certificates(
            b"relay",
            serialization.load_pem_private_key(key.read_bytes(), None),
            x509.load_pem_x509_certificate(cert.read_bytes()),
            None,
            serialization.BestAvailableEncryption(b"pfx-pass"),
        )
    )
    config = AppConfig(
        api=ApiConfig(ssl_pfxfile=pfx, ssl_pfx_password="pfx-pass"),
        smtp=SmtpConfig(host="mail.example.com"),
        policy=PolicyConfig(sender="relay@example.com", allowed_domains=["example.com"]),
    )

    result = by_name(run_checks(config, smtp=False))["api.tls"]

    assert result.status == "ok"
    assert f"PKCS#12 file {pfx}" in result.detail
    assert "pfx-pass" not in result.detail


def test_unloadable_certificate_is_a_failure(tmp_path):
    cert, _key = self_signed(tmp_path)
    config = AppConfig(
        api=ApiConfig(ssl_certfile=cert, ssl_keyfile=tmp_path / "missing.pem"),
        smtp=SmtpConfig(host="mail.example.com"),
        policy=PolicyConfig(sender="relay@example.com", allowed_domains=["example.com"]),
    )

    result = by_name(run_checks(config, smtp=False))["api.tls"]

    assert result.status == "fail"
    assert "OpenSSL rejected" in result.detail or "cannot read" in result.detail


def test_empty_allowlist_warns():
    config = AppConfig(smtp=SmtpConfig(host="mail.example.com"), policy=PolicyConfig(sender="relay@example.com"))

    result = by_name(run_checks(config, smtp=False))["policy"]

    assert result.status == "warn"
    assert "allowed_domains is empty" in result.detail


def test_sender_outside_the_account_domain_warns():
    config = settings(1, sender="noreply@softbase.example", username="relay@icloud.example", password="x")

    results = by_name(run_checks(config, smtp=False))

    assert results["policy.sender"].status == "warn"
    assert "icloud.example" in results["policy.sender"].detail


def test_sender_in_the_account_domain_does_not_warn():
    config = settings(1, sender="relay@icloud.example", username="relay@icloud.example", password="x")

    assert "policy.sender" not in by_name(run_checks(config, smtp=False))


def test_env_overrides_are_named(monkeypatch):
    monkeypatch.setenv("RELAY_SMTP_PASSWORD", PASSWORD)

    result = by_name(run_checks(settings(1, username="relay"), smtp=False))["config"]

    assert "RELAY_SMTP_PASSWORD" in result.detail
    assert PASSWORD not in result.detail


# ------------------------------------------------------------- rendering


def test_render_lists_every_result_and_a_summary():
    results = [
        CheckResult("config", "ok", "here"),
        CheckResult("smtp.auth", "warn", "hm"),
        CheckResult("smtp.sender", "fail", "no"),
        CheckResult("api.tls", "skip", "off"),
    ]

    text = render(results)

    assert text.splitlines()[0].startswith("smtp-relay ")
    assert "  WARN  smtp.auth    hm" in text
    assert "  FAIL  smtp.sender  no" in text
    assert text.splitlines()[-1] == "Result: 1 ok, 1 warning(s), 1 failed, 1 skipped"


def test_exit_code_is_one_only_for_failures():
    assert exit_code([CheckResult("a", "ok", ""), CheckResult("b", "warn", ""), CheckResult("c", "skip", "")]) == 0
    assert exit_code([CheckResult("a", "ok", ""), CheckResult("b", "fail", "")]) == 1


# ------------------------------------------------------------------- CLI


def write_config(tmp_path: Path, port: int, **smtp_lines: str) -> Path:
    extra = "".join(f"{key} = {value}\n" for key, value in smtp_lines.items())
    path = tmp_path / "config.toml"
    path.write_text(
        f'[smtp]\nhost = "127.0.0.1"\nport = {port}\nsecurity = "none"\ntimeout = 5.0\n{extra}'
        '\n[policy]\nsender = "relay@example.com"\nallowed_domains = ["example.com"]\n'
    )
    return path


def test_cli_check_without_smtp_exits_zero(tmp_path, capsys):
    config = write_config(tmp_path, 1)

    assert entry.main(["--check", "--no-smtp", "--config", str(config)]) == 0

    out = capsys.readouterr().out
    assert str(config) in out
    assert "skip  smtp " in out
    assert out.rstrip().endswith("0 failed, 2 skipped")


def test_cli_check_reports_failures_with_exit_one(tmp_path, capsys):
    config = write_config(tmp_path, free_port())

    assert entry.main(["--check", "--config", str(config)]) == 1

    assert "FAIL  smtp.session" in capsys.readouterr().out


def test_cli_check_never_prints_the_password(tmp_path, auth_server, capsys):
    config = write_config(tmp_path, auth_server, username='"relay"', password=f'"{PASSWORD}"')

    assert entry.main(["--check", "--config", str(config)]) == 0

    captured = capsys.readouterr()
    assert "authenticated as relay" in captured.out
    assert PASSWORD not in captured.out + captured.err


def test_cli_unloadable_config_exits_two(tmp_path, capsys):
    config = tmp_path / "config.toml"
    config.write_text('[smtp]\nhost = "mail.example.com"\npassword = "lonely"\n[policy]\nsender = "r@example.com"\n')

    assert entry.main(["--check", "--config", str(config)]) == 2

    err = capsys.readouterr().err
    assert "smtp.password is set but smtp.username is not" in err
    assert "lonely" not in err.split("Set smtp.username")[0]


def test_no_smtp_without_check_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as excinfo:
        entry.main(["--no-smtp"])

    assert excinfo.value.code == 2
    assert "--no-smtp only applies together with --check" in capsys.readouterr().err


def test_help_documents_the_check_mode(capsys):
    with pytest.raises(SystemExit) as excinfo:
        entry.main(["--help"])

    assert excinfo.value.code == 0
    assert "nothing is sent" in capsys.readouterr().out
