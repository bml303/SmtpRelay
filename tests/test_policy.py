"""Recipient allowlist, base64 heuristic, and the combined policy gate."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

import pytest

from app.policy import (
    PolicyViolation,
    RecipientPolicy,
    enforce_request_policy,
    looks_like_base64,
    normalize_recipients,
)


@dataclass
class Request:
    """Duck-typed stand-in for MailRequest."""

    recipients: list[str] = field(default_factory=list)
    subject: str = "Deploy finished"
    body: str = "Build 1234 deployed to production successfully."


# --- domain allowlist ------------------------------------------------------


def test_exact_domain_match():
    policy = RecipientPolicy.from_iterable(["example.com"])

    assert policy.is_allowed("a@example.com")
    assert not policy.is_allowed("a@mail.example.com")
    assert not policy.is_allowed("a@notexample.com")
    assert not policy.is_allowed("a@example.org")


def test_match_is_case_insensitive():
    policy = RecipientPolicy.from_iterable(["Example.COM"])

    assert policy.is_allowed("a@EXAMPLE.com")
    assert policy.is_allowed("a@example.com")


def test_entries_are_normalized():
    policy = RecipientPolicy.from_iterable(["  @Example.com.  ", "example.org", "", "   "])

    assert policy.allowed_domains == frozenset({"example.com", "example.org"})


def test_subdomains_only_when_enabled():
    strict = RecipientPolicy.from_iterable(["example.com"], allow_subdomains=False)
    loose = RecipientPolicy.from_iterable(["example.com"], allow_subdomains=True)

    assert not strict.is_allowed("a@mail.example.com")
    assert loose.is_allowed("a@mail.example.com")
    assert loose.is_allowed("a@deep.mail.example.com")
    assert loose.is_allowed("a@example.com")
    # The dot boundary must still prevent suffix confusion.
    assert not loose.is_allowed("a@notexample.com")


def test_empty_allowlist_rejects_everything():
    policy = RecipientPolicy.from_iterable([])

    assert not policy.is_allowed("a@example.com")
    assert policy.rejected_domains(["a@example.com"]) == ["example.com"]


def test_rejected_domains_are_deduplicated_in_first_seen_order():
    policy = RecipientPolicy.from_iterable(["example.com"])

    assert policy.rejected_domains(
        ["a@bad.org", "b@example.com", "c@bad.org", "d@worse.net"]
    ) == ["bad.org", "worse.net"]


def test_normalize_recipients_dedupes_case_insensitively_preserving_first_spelling():
    assert normalize_recipients(["A@X.com", "a@x.com", "b@x.com"]) == ["A@X.com", "b@x.com"]
    assert normalize_recipients([]) == []


# --- base64 heuristic ------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        base64.b64encode(b"some encoded payload text").decode(),
        base64.b64encode(bytes(range(32))).decode(),
        base64.b64encode(b"x" * 40).decode(),
        base64.b64encode(b"\x00\x01\x02binary\x03data\x04here").decode(),
    ],
)
def test_looks_like_base64_positives(value):
    assert looks_like_base64(value)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "Hello, this is a plain text body.",
        "Short",
        "Line one\nLine two\nLine three",
        "Deploy finished",
        "a" * 23,  # just below the length floor
        "not base64! at all -- punctuation",
        "====",  # padding only, no payload characters
    ],
)
def test_looks_like_base64_negatives(value):
    assert not looks_like_base64(value)


def test_surrounding_whitespace_does_not_defeat_detection():
    encoded = base64.b64encode(b"some encoded payload text").decode()

    assert looks_like_base64(f"  {encoded}\n")


# --- combined gate ---------------------------------------------------------


def test_enforce_returns_normalized_recipients():
    policy = RecipientPolicy.from_iterable(["example.com"])
    request = Request(recipients=["a@example.com", "A@example.com", "b@example.com"])

    assert enforce_request_policy(request, policy=policy) == ["a@example.com", "b@example.com"]


def test_enforce_rejects_disallowed_domain():
    policy = RecipientPolicy.from_iterable(["example.com"])
    request = Request(recipients=["a@example.com", "e@evil.com"])

    with pytest.raises(PolicyViolation) as excinfo:
        enforce_request_policy(request, policy=policy)

    assert excinfo.value.code == "domain_not_allowed"
    assert excinfo.value.rejected_domains == ["evil.com"]


def test_enforce_rejects_base64_body():
    policy = RecipientPolicy.from_iterable(["example.com"])
    request = Request(
        recipients=["a@example.com"], body=base64.b64encode(b"x" * 40).decode()
    )

    with pytest.raises(PolicyViolation) as excinfo:
        enforce_request_policy(request, policy=policy, reject_base64=True)

    assert excinfo.value.code == "base64_not_allowed"


def test_enforce_allows_base64_when_the_check_is_disabled():
    policy = RecipientPolicy.from_iterable(["example.com"])
    request = Request(
        recipients=["a@example.com"], body=base64.b64encode(b"x" * 40).decode()
    )

    assert enforce_request_policy(request, policy=policy, reject_base64=False) == [
        "a@example.com"
    ]


def test_enforce_rejects_too_many_recipients():
    policy = RecipientPolicy.from_iterable(["example.com"])
    request = Request(recipients=[f"u{i}@example.com" for i in range(6)])

    with pytest.raises(PolicyViolation) as excinfo:
        enforce_request_policy(request, policy=policy, max_recipients=5)

    assert excinfo.value.code == "too_many_recipients"


def test_enforce_counts_recipients_after_deduplication():
    policy = RecipientPolicy.from_iterable(["example.com"])
    request = Request(recipients=["a@example.com"] * 10)

    assert enforce_request_policy(request, policy=policy, max_recipients=5) == ["a@example.com"]
