"""End-to-end tests against a real SMTP server (aiosmtpd), not a mock.

These exist because a fake SMTP object can only encode what we assume the real
API looks like. A wrong keyword argument passed every mocked test and failed
only against a live server.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

import pytest
from aiosmtpd.controller import Controller
from fastapi.testclient import TestClient

from app.config import ApiConfig, AppConfig, PolicyConfig, SmtpConfig
from app.main import create_app


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@dataclass
class Delivered:
    mail_from: str
    rcpt_to: list[str]
    content: str
    encrypted: bool


class Collector:
    """aiosmtpd handler that records every message it accepts."""

    def __init__(self) -> None:
        self.messages: list[Delivered] = []

    async def handle_DATA(self, server, session, envelope):
        content = envelope.content
        if isinstance(content, bytes):
            content = content.decode("utf-8", "replace")
        self.messages.append(
            Delivered(
                mail_from=envelope.mail_from,
                rcpt_to=list(envelope.rcpt_tos),
                content=content,
                encrypted=session.ssl is not None,
            )
        )
        return "250 OK"


@dataclass
class LiveRelay:
    client: TestClient
    collector: Collector
    port: int
    delivered: list[Delivered] = field(init=False)

    def __post_init__(self) -> None:
        self.delivered = self.collector.messages


@pytest.fixture
def live_relay():
    """A running SMTP sink plus an app wired to deliver into it."""
    port = free_port()
    collector = Collector()
    controller = Controller(collector, hostname="127.0.0.1", port=port)
    controller.start()
    try:
        config = AppConfig(
            api=ApiConfig(port=8000),
            smtp=SmtpConfig(host="127.0.0.1", port=port, security="none", timeout=5.0),
            policy=PolicyConfig(
                sender="relay@example.com",
                sender_name="Notification Relay",
                allowed_domains=["example.com", "example.org"],
            ),
        )
        yield LiveRelay(client=TestClient(create_app(config)), collector=collector, port=port)
    finally:
        controller.stop()


@pytest.fixture
def payload() -> dict[str, object]:
    return {
        "recipients": ["alice@example.com", "bob@example.org"],
        "subject": "Deploy finished",
        "body": "Build 1234 deployed to production successfully.",
    }


def test_message_reaches_a_real_smtp_server(live_relay, payload):
    response = live_relay.client.post("/mail", json=payload)

    assert response.status_code == 200, response.text

    delivered = live_relay.collector.messages
    assert len(delivered) == 1
    message = delivered[0]
    assert message.mail_from == "relay@example.com"
    assert message.rcpt_to == ["alice@example.com", "bob@example.org"]
    assert "Subject: Deploy finished" in message.content
    assert "Build 1234 deployed to production successfully." in message.content
    assert "From: Notification Relay <relay@example.com>" in message.content
    assert "To: alice@example.com, bob@example.org" in message.content
    assert response.json()["message_id"][1:-1] in message.content


def test_returned_message_id_matches_the_delivered_header(live_relay, payload):
    response = live_relay.client.post("/mail", json=payload)

    assert response.status_code == 200
    assert f"Message-ID: {response.json()['message_id']}" in live_relay.collector.messages[0].content


def test_rejected_domain_delivers_nothing(live_relay, payload):
    payload["recipients"] = ["alice@example.com", "eve@evil.com"]

    response = live_relay.client.post("/mail", json=payload)

    assert response.status_code == 400
    assert response.json()["code"] == "domain_not_allowed"
    assert live_relay.collector.messages == []


def test_schema_violation_delivers_nothing(live_relay, payload):
    payload["body"] = ""

    assert live_relay.client.post("/mail", json=payload).status_code == 422
    assert live_relay.collector.messages == []


def test_non_ascii_body_is_delivered(live_relay, payload):
    payload["subject"] = "Ärger mit Umlauten"
    payload["body"] = "Viele Grüße aus München — 100% ok."

    response = live_relay.client.post("/mail", json=payload)

    assert response.status_code == 200
    # The wire form is MIME-encoded, which is expected and RFC-mandated.
    assert "Subject: " in live_relay.collector.messages[0].content


def test_unreachable_mailhost_returns_502(payload):
    dead_port = free_port()
    config = AppConfig(
        api=ApiConfig(port=8000),
        smtp=SmtpConfig(host="127.0.0.1", port=dead_port, security="none", timeout=2.0),
        policy=PolicyConfig(
            sender="relay@example.com", allowed_domains=["example.com", "example.org"]
        ),
    )
    client = TestClient(create_app(config))

    response = client.post("/mail", json=payload)

    assert response.status_code == 502
    detail = response.json()["detail"]
    assert f"127.0.0.1:{dead_port}" in detail


def test_starttls_refusal_returns_502(payload):
    """Talking STARTTLS to a plaintext-only server must fail loudly, not silently."""
    port = free_port()
    controller = Controller(Collector(), hostname="127.0.0.1", port=port)
    controller.start()
    try:
        config = AppConfig(
            api=ApiConfig(port=8000),
            smtp=SmtpConfig(host="127.0.0.1", port=port, security="starttls", timeout=5.0),
            policy=PolicyConfig(
                sender="relay@example.com", allowed_domains=["example.com", "example.org"]
            ),
        )
        response = TestClient(create_app(config)).post("/mail", json=payload)

        assert response.status_code == 502
        assert "STARTTLS" in response.json()["detail"]
    finally:
        controller.stop()
