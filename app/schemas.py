"""Request and response models.

Structural validation lives here and produces HTTP 422. Content policy
(allowlist, base64 rejection, recipient cap) lives in :mod:`app.policy` and
produces HTTP 400, so "malformed" and "not permitted" stay distinguishable.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class MailRequest(BaseModel):
    """A message to relay. Plain UTF-8 text only; no base64 payloads."""

    model_config = ConfigDict(extra="forbid")

    recipients: list[EmailStr] = Field(
        min_length=1,
        description="Destination addresses. Every domain must appear in the allowlist.",
    )
    subject: str = Field(min_length=1, max_length=998, description="Message subject.")
    body: str = Field(min_length=1, description="Plain-text message body.")


class MailAccepted(BaseModel):
    status: str = "sent"
    message_id: str = Field(description="Message-ID assigned to the delivered message.")
    recipients: list[EmailStr] = Field(description="Recipients the message was delivered to.")


class ErrorResponse(BaseModel):
    detail: str
    code: str | None = None
    rejected_domains: list[str] | None = None
