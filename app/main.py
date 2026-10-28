"""FastAPI application exposing ``POST /mail``."""

from __future__ import annotations

import logging
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from . import __version__
from .config import AppConfig, load_config
from .policy import PolicyViolation, RecipientPolicy, enforce_request_policy
from .relay import RelayError, SmtpRelay, build_message
from .schemas import MailAccepted, MailRequest

logger = logging.getLogger("smtp_relay")


def create_app(config: AppConfig | None = None) -> FastAPI:
    """Build the application. Pass ``config`` to skip loading from disk (tests)."""
    settings = config if config is not None else load_config()

    relay = SmtpRelay(settings.smtp)
    policy = RecipientPolicy.from_iterable(
        settings.policy.allowed_domains,
        allow_subdomains=settings.policy.allow_subdomains,
    )
    expected_token = settings.api.token

    if not policy.allowed_domains:
        logger.warning(
            "policy.allowed_domains is empty - every request will be rejected with 400."
        )

    def require_token(authorization: str | None = Header(default=None)) -> None:
        if expected_token is None:
            return
        if authorization is None or not secrets.compare_digest(
            authorization, f"Bearer {expected_token}"
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="A valid bearer token is required.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    app = FastAPI(
        title="SMTP Relay",
        version=__version__,
        summary="Accepts JSON over REST and relays it as mail through a configurable SMTP mailhost.",
    )
    app.state.settings = settings

    @app.exception_handler(PolicyViolation)
    async def policy_violation_handler(request: Request, exc: PolicyViolation) -> JSONResponse:
        payload: dict[str, object] = {"detail": exc.detail, "code": exc.code}
        if exc.rejected_domains:
            payload["rejected_domains"] = exc.rejected_domains
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=payload)

    @app.get("/health", tags=["ops"], summary="Liveness probe.")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    # Declared `def`, not `async def`: smtplib blocks, so FastAPI dispatches this
    # to a threadpool instead of stalling the event loop.
    @app.post(
        "/mail",
        response_model=MailAccepted,
        dependencies=[Depends(require_token)],
        tags=["mail"],
        summary="Relay a message to the configured mailhost.",
        responses={
            400: {"description": "Policy violation: domain not allowlisted, base64 payload, or too many recipients."},
            401: {"description": "Missing or invalid bearer token."},
            422: {"description": "Request body does not match the schema."},
            502: {"description": "The mailhost refused or was unreachable."},
        },
    )
    def post_mail(request: MailRequest) -> MailAccepted:
        recipients = enforce_request_policy(
            request,
            policy=policy,
            reject_base64=settings.policy.reject_base64,
            max_recipients=settings.api.max_recipients,
        )
        message = build_message(
            sender=str(settings.policy.sender),
            sender_name=settings.policy.sender_name,
            recipients=recipients,
            subject=request.subject,
            body=request.body,
        )
        try:
            message_id = relay.send(
                message,
                sender=str(settings.policy.sender),
                recipients=recipients,
            )
        except RelayError as exc:
            logger.error("Relay to %s failed: %s", settings.smtp.endpoint, exc.detail)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY, detail=exc.detail
            ) from exc

        logger.info("Relayed %s to %d recipient(s)", message_id, len(recipients))
        return MailAccepted(message_id=message_id, recipients=recipients)

    return app
