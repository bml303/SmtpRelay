"""Shared fixtures: an in-memory config plus a stand-in relay that records sends."""

from __future__ import annotations

from collections.abc import Callable
from email.message import EmailMessage

import pytest
from fastapi.testclient import TestClient

from app.config import ApiConfig, AppConfig, PolicyConfig, SmtpConfig
from app.main import create_app
from app.relay import RelayError


class RecordingRelay:
    """Duck-typed replacement for :class:`app.relay.SmtpRelay`."""

    def __init__(self, *, error: RelayError | None = None) -> None:
        self.sent: list[tuple[EmailMessage, str, list[str]]] = []
        self._error = error

    def send(self, message: EmailMessage, *, sender: str, recipients: list[str]) -> str:
        if self._error is not None:
            raise self._error
        self.sent.append((message, sender, list(recipients)))
        return str(message["Message-ID"])


@pytest.fixture
def app_config() -> AppConfig:
    return AppConfig(
        api=ApiConfig(port=8000, max_recipients=3),
        smtp=SmtpConfig(
            host="mail.example.com", port=587, username="relay", password="secret"
        ),
        policy=PolicyConfig(
            sender="relay@example.com",
            allowed_domains=["example.com", "example.org"],
        ),
    )


@pytest.fixture
def make_client(
    monkeypatch: pytest.MonkeyPatch, app_config: AppConfig
) -> Callable[..., tuple[TestClient, RecordingRelay]]:
    """Build a TestClient whose relay is replaced by a recorder."""

    def _make(
        *, config: AppConfig | None = None, relay_error: RelayError | None = None
    ) -> tuple[TestClient, RecordingRelay]:
        recorder = RecordingRelay(error=relay_error)
        monkeypatch.setattr("app.main.SmtpRelay", lambda _config: recorder)
        return TestClient(create_app(config or app_config)), recorder

    return _make


@pytest.fixture
def client_and_relay(make_client) -> tuple[TestClient, RecordingRelay]:
    return make_client()


@pytest.fixture
def client(client_and_relay) -> TestClient:
    return client_and_relay[0]


@pytest.fixture
def relay(client_and_relay) -> RecordingRelay:
    return client_and_relay[1]


@pytest.fixture
def payload() -> dict[str, object]:
    return {
        "recipients": ["alice@example.com", "bob@example.org"],
        "subject": "Deploy finished",
        "body": "Build 1234 deployed to production successfully.",
    }
