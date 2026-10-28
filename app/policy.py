"""Content policy: recipient allowlist, base64 rejection, recipient cap.

Everything here raises :class:`PolicyViolation`, which the API maps to HTTP 400.
These are rules about *permitted content*, kept separate from the Pydantic
schema, which is about *well-formed content* (HTTP 422).
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

#: Fields scanned for base64 payloads. Recipients are already EmailStr-validated.
BASE64_CHECKED_FIELDS = ("subject", "body")

_STRICT_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")

#: Below this length too much ordinary text would match by coincidence.
_MIN_BASE64_LEN = 24


class PolicyViolation(Exception):
    """A structurally valid request that breaks relay policy."""

    def __init__(
        self,
        detail: str,
        *,
        code: str,
        rejected_domains: list[str] | None = None,
    ) -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code
        self.rejected_domains = rejected_domains or []


def looks_like_base64(value: str) -> bool:
    """Heuristic: is this a base64 blob rather than human-readable text?

    Requires a plausible length, strict alphabet, correct padding, and a clean
    decode. Ordinary prose fails fast because it contains spaces and
    punctuation, which are outside the base64 alphabet.
    """
    candidate = value.strip()
    if len(candidate) < _MIN_BASE64_LEN or len(candidate) % 4 != 0:
        return False
    if not _STRICT_BASE64_RE.match(candidate):
        return False
    try:
        base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError):
        return False
    return True


def find_base64_fields(values: Mapping[str, str]) -> list[str]:
    return [name for name in BASE64_CHECKED_FIELDS if looks_like_base64(values.get(name, ""))]


def normalize_recipients(addresses: Iterable[str]) -> list[str]:
    """Drop duplicates so one address is not delivered to twice.

    Case of the original address is preserved for display; identity is compared
    case-insensitively, matching how mail domains are treated.
    """
    seen: set[str] = set()
    unique: list[str] = []
    for address in addresses:
        key = address.lower()
        if key not in seen:
            seen.add(key)
            unique.append(address)
    return unique


def _domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower()


@dataclass(frozen=True)
class RecipientPolicy:
    """Allowlist of recipient domains."""

    allowed_domains: frozenset[str]
    allow_subdomains: bool = False

    @classmethod
    def from_iterable(
        cls,
        domains: Iterable[str],
        *,
        allow_subdomains: bool = False,
    ) -> RecipientPolicy:
        normalized = frozenset(
            domain.strip().lower().removeprefix("@").rstrip(".")
            for domain in domains
            if domain.strip()
        )
        return cls(allowed_domains=normalized, allow_subdomains=allow_subdomains)

    def is_allowed(self, address: str) -> bool:
        domain = _domain_of(address)
        if domain in self.allowed_domains:
            return True
        if self.allow_subdomains:
            return any(domain.endswith(f".{allowed}") for allowed in self.allowed_domains)
        return False

    def rejected_domains(self, addresses: Iterable[str]) -> list[str]:
        """Domains that are not allowed, deduplicated, in first-seen order."""
        rejected: list[str] = []
        for address in addresses:
            domain = _domain_of(address)
            if not self.is_allowed(address) and domain not in rejected:
                rejected.append(domain)
        return rejected


def enforce_request_policy(
    request: object,
    *,
    policy: RecipientPolicy,
    reject_base64: bool = True,
    max_recipients: int = 50,
) -> list[str]:
    """Validate a parsed request against policy; return normalized recipients.

    ``request`` is duck-typed on ``recipients``, ``subject`` and ``body`` so the
    checks stay testable without constructing Pydantic models.
    """
    recipients = normalize_recipients(getattr(request, "recipients"))

    if len(recipients) > max_recipients:
        raise PolicyViolation(
            f"Too many recipients: {len(recipients)} exceeds the limit of {max_recipients}.",
            code="too_many_recipients",
        )

    rejected = policy.rejected_domains(recipients)
    if rejected:
        raise PolicyViolation(
            "Recipient domain not in allowlist: " + ", ".join(rejected),
            code="domain_not_allowed",
            rejected_domains=rejected,
        )

    if reject_base64:
        encoded = find_base64_fields(
            {"subject": getattr(request, "subject"), "body": getattr(request, "body")}
        )
        if encoded:
            raise PolicyViolation(
                "Base64-encoded data is not allowed; send plain UTF-8 text in: "
                + ", ".join(encoded),
                code="base64_not_allowed",
            )

    return recipients
