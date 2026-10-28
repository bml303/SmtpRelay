"""HTTP-level behaviour of POST /mail: schema (422), policy (400), relay (502)."""

from __future__ import annotations

import base64

from app.relay import RelayError


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_valid_request_is_relayed(client, relay, payload):
    response = client.post("/mail", json=payload)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "sent"
    assert body["recipients"] == payload["recipients"]
    assert body["message_id"].endswith("@example.com>")

    assert len(relay.sent) == 1
    message, sender, recipients = relay.sent[0]
    assert sender == "relay@example.com"
    assert recipients == payload["recipients"]
    assert message["Subject"] == "Deploy finished"
    assert message["To"] == "alice@example.com, bob@example.org"
    assert message["From"] == "relay@example.com"
    assert message.get_content_type() == "text/plain"
    assert message.get_content().strip() == payload["body"]


# --- schema violations: 422 -------------------------------------------------


def test_unknown_field_is_rejected(client, relay, payload):
    payload["carbon_copy"] = "someone@example.com"

    assert client.post("/mail", json=payload).status_code == 422
    assert relay.sent == []


def test_missing_fields_are_rejected(client, relay):
    for incomplete in ({}, {"recipients": ["a@example.com"]}, {"subject": "x"}, {"body": "y"}):
        assert client.post("/mail", json=incomplete).status_code == 422
    assert relay.sent == []


def test_invalid_email_is_rejected(client, relay, payload):
    payload["recipients"] = ["not-an-email"]

    assert client.post("/mail", json=payload).status_code == 422
    assert relay.sent == []


def test_empty_recipient_list_is_rejected(client, relay, payload):
    payload["recipients"] = []

    assert client.post("/mail", json=payload).status_code == 422
    assert relay.sent == []


def test_empty_subject_and_body_are_rejected(client, relay, payload):
    payload["subject"] = ""
    assert client.post("/mail", json=payload).status_code == 422

    payload = {**payload, "subject": "Deploy finished", "body": ""}
    assert client.post("/mail", json=payload).status_code == 422
    assert relay.sent == []


def test_malformed_json_is_rejected(client, relay):
    response = client.post(
        "/mail",
        content=b'{"recipients": ["a@example.com"], "subject":',
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 422
    assert relay.sent == []


# --- policy violations: 400 ------------------------------------------------


def test_domain_outside_allowlist_is_rejected(client, relay, payload):
    payload["recipients"] = ["alice@example.com", "eve@evil.com", "mallory@bad.org"]

    response = client.post("/mail", json=payload)

    assert response.status_code == 400
    body = response.json()
    assert body["code"] == "domain_not_allowed"
    assert body["rejected_domains"] == ["evil.com", "bad.org"]
    assert "evil.com" in body["detail"]
    assert relay.sent == []


def test_one_bad_domain_rejects_the_whole_request(client, relay, payload):
    """No partial delivery: the POST is atomic."""
    payload["recipients"] = ["alice@example.com", "eve@evil.com"]

    assert client.post("/mail", json=payload).status_code == 400
    assert relay.sent == []


def test_duplicate_recipients_are_deduplicated(client, relay, payload):
    payload["recipients"] = ["alice@example.com", "alice@example.com", "bob@example.org"]

    response = client.post("/mail", json=payload)

    assert response.status_code == 200
    assert response.json()["recipients"] == ["alice@example.com", "bob@example.org"]
    assert relay.sent[0][2] == ["alice@example.com", "bob@example.org"]


def test_recipient_cap_is_enforced(client, relay, payload):
    # app_config sets max_recipients = 3
    payload["recipients"] = [f"user{i}@example.com" for i in range(4)]

    response = client.post("/mail", json=payload)

    assert response.status_code == 400
    assert response.json()["code"] == "too_many_recipients"
    assert relay.sent == []


def test_base64_body_is_rejected(client, relay, payload):
    payload["body"] = base64.b64encode(b"a binary blob that must not be relayed").decode()

    response = client.post("/mail", json=payload)

    assert response.status_code == 400
    assert response.json()["code"] == "base64_not_allowed"
    assert "body" in response.json()["detail"]
    assert relay.sent == []


def test_base64_subject_is_rejected(client, relay, payload):
    payload["subject"] = base64.b64encode(b"a fairly long encoded subject").decode()

    response = client.post("/mail", json=payload)

    assert response.status_code == 400
    assert response.json()["code"] == "base64_not_allowed"
    assert relay.sent == []


def test_plain_text_with_unusual_characters_is_accepted(client, relay, payload):
    payload["body"] = "Umlaute: äöüß — em dash, 100% fine.\nSecond line."
    payload["subject"] = "Ärger mit Umlauten"

    assert client.post("/mail", json=payload).status_code == 200
    assert relay.sent[0][0].get_content().startswith("Umlaute: äöüß")


def test_base64_check_can_be_disabled(make_client, app_config, payload):
    relaxed = app_config.model_copy(deep=True)
    relaxed.policy.reject_base64 = False
    client, relay = make_client(config=relaxed)
    payload["body"] = base64.b64encode(b"a binary blob that must not be relayed").decode()

    assert client.post("/mail", json=payload).status_code == 200
    assert len(relay.sent) == 1


def test_subdomains_allowed_when_enabled(make_client, app_config, payload):
    loose = app_config.model_copy(deep=True)
    loose.policy.allow_subdomains = True
    client, relay = make_client(config=loose)
    payload["recipients"] = ["alice@mail.example.com"]

    assert client.post("/mail", json=payload).status_code == 200
    assert relay.sent[0][2] == ["alice@mail.example.com"]


# --- relay failures: 502 ---------------------------------------------------


def test_relay_failure_returns_502(make_client, payload):
    client, relay = make_client(
        relay_error=RelayError(
            "Could not reach mailhost mail.example.com:587 over starttls: Connection refused"
        )
    )

    response = client.post("/mail", json=payload)

    assert response.status_code == 502
    assert "Could not reach mailhost" in response.json()["detail"]
    assert relay.sent == []


# --- authentication --------------------------------------------------------


def test_bearer_token_is_enforced_when_configured(make_client, app_config, payload):
    secured = app_config.model_copy(deep=True)
    secured.api.token = "s3cret"
    client, relay = make_client(config=secured)

    assert client.post("/mail", json=payload).status_code == 401
    assert (
        client.post("/mail", json=payload, headers={"Authorization": "Bearer wrong"}).status_code
        == 401
    )
    assert relay.sent == []

    accepted = client.post("/mail", json=payload, headers={"Authorization": "Bearer s3cret"})
    assert accepted.status_code == 200
    assert len(relay.sent) == 1


def test_no_token_required_when_unset(client, payload):
    assert client.post("/mail", json=payload).status_code == 200


def test_openapi_schema_is_published(client):
    response = client.get("/openapi.json")

    assert response.status_code == 200
    assert "/mail" in response.json()["paths"]
