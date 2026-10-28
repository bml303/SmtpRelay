"""SMTP negotiation paths and error translation, with smtplib replaced by a fake."""

from __future__ import annotations

import inspect
import smtplib
import ssl
from email.utils import parseaddr

import pytest
from pydantic import ValidationError

from app.config import SmtpConfig
from app.relay import RelayError, SmtpRelay, build_message


class FakeSMTP:
    """Records the calls a real ``smtplib.SMTP`` would receive."""

    def __init__(self, host, port, timeout=None, local_hostname=None, context=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.local_hostname = local_hostname
        self.context = context
        self.events: list[str] = ["connect"]
        self.sent: list[tuple[object, str, list[str]]] = []
        self.closed = False

    def ehlo(self):
        self.events.append("ehlo")

    def starttls(self, context=None):
        self.events.append("starttls")
        self.context = context

    def login(self, user, password):
        self.events.append(f"login:{user}:{password}")

    def send_message(self, msg, from_addr=None, to_addrs=None, mail_options=(), rcpt_options=()):
        self.events.append("send_message")
        self.sent.append((msg, from_addr, list(to_addrs or [])))

    def quit(self):
        self.events.append("quit")

    def close(self):
        self.closed = True


class FakeSMTP_SSL(FakeSMTP):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.events[0] = "connect:ssl"


@pytest.fixture
def fake_smtplib(monkeypatch: pytest.MonkeyPatch) -> list[FakeSMTP]:
    """Patch smtplib.SMTP / SMTP_SSL; returns every connection created."""
    created: list[FakeSMTP] = []

    def factory(cls):
        def build(*args, **kwargs):
            instance = cls(*args, **kwargs)
            created.append(instance)
            return instance

        return build

    monkeypatch.setattr(smtplib, "SMTP", factory(FakeSMTP))
    monkeypatch.setattr(smtplib, "SMTP_SSL", factory(FakeSMTP_SSL))
    return created


def test_relay_calls_match_the_real_smtplib_signatures():
    """Bind every call SmtpRelay makes against the real smtplib API.

    FakeSMTP can only encode what we believe smtplib looks like; this checks the
    belief against the library itself, so a wrong keyword argument fails here
    rather than surfacing as a 500 in production.
    """
    config = SmtpConfig(
        host="mail.example.com",
        port=587,
        username="relay",
        password="pw",
        timeout=5.0,
        local_hostname="relay.local",
    )
    message = make_message()

    # Plain and implicit-TLS connections.
    inspect.signature(smtplib.SMTP.__init__).bind(
        None, config.host, config.port,
        timeout=config.timeout, local_hostname=config.local_hostname,
    )
    inspect.signature(smtplib.SMTP_SSL.__init__).bind(
        None, config.host, config.port,
        context=None, timeout=config.timeout, local_hostname=config.local_hostname,
    )

    # The transaction itself.
    inspect.signature(smtplib.SMTP.ehlo).bind(None)
    inspect.signature(smtplib.SMTP.starttls).bind(None, context=None)
    inspect.signature(smtplib.SMTP.login).bind(None, config.username, config.password)
    inspect.signature(smtplib.SMTP.send_message).bind(
        None, message, from_addr=config.host, to_addrs=["alice@example.com"]
    )
    inspect.signature(smtplib.SMTP.quit).bind(None)
    inspect.signature(smtplib.SMTP.close).bind(None)


def test_fake_smtp_send_message_signature_matches_smtplib():
    """Keep FakeSMTP.send_message aligned with the method it stands in for."""
    real = inspect.signature(smtplib.SMTP.send_message).parameters
    fake = inspect.signature(FakeSMTP.send_message).parameters

    assert list(fake) == list(real)


def make_message(**overrides) -> object:
    kwargs = {
        "sender": "relay@example.com",
        "recipients": ["alice@example.com"],
        "subject": "Deploy finished",
        "body": "Build 1234 deployed.",
    }
    kwargs.update(overrides)
    return build_message(**kwargs)


def send(relay: SmtpRelay, message, *, recipients=None) -> str:
    return relay.send(
        message, sender="relay@example.com", recipients=recipients or ["alice@example.com"]
    )


# --- security mode resolution ---------------------------------------------


@pytest.mark.parametrize(
    ("port", "expected"),
    [(465, "tls"), (587, "starttls"), (25, "none"), (2525, "starttls")],
)
def test_security_is_inferred_from_the_port(port, expected):
    assert SmtpConfig(host="h", port=port).resolved_security == expected


def test_explicit_security_overrides_the_port():
    assert SmtpConfig(host="h", port=465, security="starttls").resolved_security == "starttls"
    assert SmtpConfig(host="h", port=587, security="none").resolved_security == "none"


def test_port_must_be_in_range():
    with pytest.raises(ValidationError):
        SmtpConfig(host="h", port=70000)
    with pytest.raises(ValidationError):
        SmtpConfig(host="h", port=0)


def test_timeout_must_be_positive():
    with pytest.raises(ValidationError):
        SmtpConfig(host="h", timeout=0)


# --- negotiation paths -----------------------------------------------------


def test_starttls_negotiates_before_sending(fake_smtplib):
    relay = SmtpRelay(
        SmtpConfig(host="mail.example.com", port=587, username="relay", password="pw")
    )
    message = make_message()

    message_id = send(relay, message)

    client = fake_smtplib[0]
    assert client.events == [
        "connect",
        "ehlo",
        "starttls",
        "ehlo",
        "login:relay:pw",
        "send_message",
        "quit",
    ]
    assert isinstance(client.context, ssl.SSLContext)
    assert client.sent[0][1] == "relay@example.com"
    assert client.sent[0][2] == ["alice@example.com"]
    assert client.closed
    assert message_id == message["Message-ID"]


def test_implicit_tls_connects_with_smtp_ssl_and_never_calls_starttls(fake_smtplib):
    relay = SmtpRelay(SmtpConfig(host="mail.example.com", port=465))

    send(relay, make_message())

    client = fake_smtplib[0]
    assert isinstance(client, FakeSMTP_SSL)
    assert client.port == 465
    assert client.events == ["connect:ssl", "send_message", "quit"]
    assert isinstance(client.context, ssl.SSLContext)


def test_security_none_skips_tls_entirely(fake_smtplib):
    relay = SmtpRelay(SmtpConfig(host="localhost", port=2525, security="none"))

    send(relay, make_message())

    assert fake_smtplib[0].events == ["connect", "send_message", "quit"]


def test_login_is_skipped_without_a_username(fake_smtplib):
    relay = SmtpRelay(SmtpConfig(host="h", port=587))

    send(relay, make_message())

    assert not any(event.startswith("login") for event in fake_smtplib[0].events)


def test_login_sends_an_empty_password_when_only_a_username_is_set(fake_smtplib):
    relay = SmtpRelay(SmtpConfig(host="h", port=587, username="relay"))

    send(relay, make_message())

    assert "login:relay:" in fake_smtplib[0].events


def test_timeout_and_local_hostname_are_passed_through(fake_smtplib):
    relay = SmtpRelay(
        SmtpConfig(
            host="h", port=2525, security="none", timeout=5.0, local_hostname="relay.local"
        )
    )

    send(relay, make_message())

    client = fake_smtplib[0]
    assert client.timeout == 5.0
    assert client.local_hostname == "relay.local"


def test_custom_ca_file_is_used_for_the_ssl_context(monkeypatch, tmp_path):
    captured: list[ssl.SSLContext] = []
    real_create = ssl.create_default_context

    def spy(cafile=None):
        captured.append(cafile)
        return real_create()

    monkeypatch.setattr("app.relay.ssl.create_default_context", spy)
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTP_SSL)

    ca_bundle = tmp_path / "internal-ca.pem"
    ca_bundle.write_text("")
    relay = SmtpRelay(SmtpConfig(host="h", port=465, ca_file=ca_bundle))

    send(relay, make_message())

    assert captured == [str(ca_bundle)]


# --- error translation -----------------------------------------------------


def test_smtp_response_error_carries_the_status_code(monkeypatch):
    class Refusing(FakeSMTP):
        def send_message(self, *args, **kwargs):
            raise smtplib.SMTPDataError(550, b"Message content rejected")

    monkeypatch.setattr(smtplib, "SMTP", Refusing)
    relay = SmtpRelay(SmtpConfig(host="mail.example.com", port=2525, security="none"))

    with pytest.raises(RelayError) as excinfo:
        send(relay, make_message())

    assert excinfo.value.smtp_code == 550
    assert "550" in excinfo.value.detail
    assert "Message content rejected" in excinfo.value.detail


def test_sender_refused_carries_the_status_code(monkeypatch):
    class Refusing(FakeSMTP):
        def send_message(self, *args, **kwargs):
            raise smtplib.SMTPSenderRefused(553, b"Sender address rejected", "relay@example.com")

    monkeypatch.setattr(smtplib, "SMTP", Refusing)
    relay = SmtpRelay(SmtpConfig(host="h", port=2525, security="none"))

    with pytest.raises(RelayError) as excinfo:
        send(relay, make_message())

    assert excinfo.value.smtp_code == 553


def test_protocol_error_without_a_status_code(monkeypatch):
    class NoTls(FakeSMTP):
        def starttls(self, context=None):
            raise smtplib.SMTPNotSupportedError("STARTTLS extension not supported by host")

    monkeypatch.setattr(smtplib, "SMTP", NoTls)
    relay = SmtpRelay(SmtpConfig(host="h", port=587))

    with pytest.raises(RelayError) as excinfo:
        send(relay, make_message())

    assert excinfo.value.smtp_code is None
    assert "STARTTLS" in excinfo.value.detail


def test_unreachable_host_becomes_relay_error(monkeypatch):
    def explode(*args, **kwargs):
        raise OSError("Connection refused")

    monkeypatch.setattr(smtplib, "SMTP", explode)
    relay = SmtpRelay(SmtpConfig(host="mail.example.com", port=2525, security="none"))

    with pytest.raises(RelayError) as excinfo:
        send(relay, make_message())

    assert excinfo.value.smtp_code is None
    assert "mail.example.com:2525" in excinfo.value.detail
    assert "Connection refused" in excinfo.value.detail


def test_socket_timeout_becomes_relay_error(monkeypatch):
    def timeout(*args, **kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr(smtplib, "SMTP", timeout)
    relay = SmtpRelay(SmtpConfig(host="h", port=2525, security="none"))

    with pytest.raises(RelayError) as excinfo:
        send(relay, make_message())

    assert "timed out" in excinfo.value.detail


def test_connection_is_closed_even_when_sending_fails(monkeypatch):
    created: list[FakeSMTP] = []

    class Exploding(FakeSMTP):
        def send_message(self, *args, **kwargs):
            raise smtplib.SMTPDataError(550, b"nope")

    def build(*args, **kwargs):
        instance = Exploding(*args, **kwargs)
        created.append(instance)
        return instance

    monkeypatch.setattr(smtplib, "SMTP", build)
    relay = SmtpRelay(SmtpConfig(host="h", port=2525, security="none"))

    with pytest.raises(RelayError):
        send(relay, make_message())

    assert created[0].closed


# --- message construction --------------------------------------------------


def test_build_message_sets_headers():
    message = build_message(
        sender="relay@example.com",
        sender_name="Notification Relay",
        recipients=["a@example.com", "b@example.org"],
        subject="Deploy finished",
        body="Build 1234 succeeded.",
    )

    assert parseaddr(message["From"]) == ("Notification Relay", "relay@example.com")
    assert message["To"] == "a@example.com, b@example.org"
    assert message["Subject"] == "Deploy finished"
    assert message["Date"]
    assert message["Message-ID"].endswith("@example.com>")
    assert message.get_content_type() == "text/plain"
    assert message.get_content().strip() == "Build 1234 succeeded."


def test_build_message_without_a_display_name():
    message = build_message(
        sender="relay@example.com",
        recipients=["a@example.com"],
        subject="S",
        body="B",
    )

    assert message["From"] == "relay@example.com"


def test_build_message_generates_distinct_message_ids():
    first = build_message(sender="r@example.com", recipients=["a@example.com"], subject="S", body="B")
    second = build_message(sender="r@example.com", recipients=["a@example.com"], subject="S", body="B")

    assert first["Message-ID"] != second["Message-ID"]


def test_non_ascii_is_encoded_for_transport():
    message = build_message(
        sender="relay@example.com",
        recipients=["a@example.com"],
        subject="Ärger mit Umlauten",
        body="Viele Grüße aus München",
    )

    serialized = message.as_string().lower()
    # Subject is RFC 2047 encoded and the body gets a transfer encoding on the wire.
    assert "=?utf-8?" in serialized
    # The in-memory model still exposes the original text.
    assert message.get_content().strip() == "Viele Grüße aus München"
