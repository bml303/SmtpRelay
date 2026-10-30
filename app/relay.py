"""SMTP delivery: build the MIME message and hand it to the configured mailhost.

Uses the blocking ``smtplib``, so the endpoint that calls this is declared
``def`` (not ``async def``) and FastAPI runs it in a threadpool.
"""

from __future__ import annotations

import smtplib
import ssl
from collections.abc import Sequence
from contextlib import suppress
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

from .config import SmtpConfig


class RelayError(Exception):
    """The message could not be handed to the mailhost."""

    def __init__(self, detail: str, *, smtp_code: int | None = None) -> None:
        super().__init__(detail)
        self.detail = detail
        self.smtp_code = smtp_code


def build_message(
    *,
    sender: str,
    recipients: Sequence[str],
    subject: str,
    body: str,
    sender_name: str | None = None,
) -> EmailMessage:
    """Build a plain-text ``text/plain`` message.

    Note on encoding: ``set_content`` lets the email library choose the
    Content-Transfer-Encoding for the MIME part on the wire, which is
    ``base64`` for non-ASCII text. That is RFC 2045 transport encoding and is
    unrelated to the API-level rule that request bodies carry plain text.
    """
    message = EmailMessage()
    message["From"] = formataddr((sender_name, sender)) if sender_name else sender
    message["To"] = ", ".join(recipients)
    message["Subject"] = subject
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid(domain=sender.rsplit("@", 1)[-1])
    message.set_content(body)
    return message


class SmtpRelay:
    def __init__(self, config: SmtpConfig) -> None:
        self._config = config

    def _ssl_context(self) -> ssl.SSLContext:
        ca_file = self._config.ca_file
        return ssl.create_default_context(cafile=str(ca_file) if ca_file else None)

    def _connect(self) -> smtplib.SMTP:
        config = self._config
        if config.resolved_security == "tls":
            return smtplib.SMTP_SSL(
                config.host,
                config.port,
                context=self._ssl_context(),
                timeout=config.timeout,
                local_hostname=config.local_hostname,
            )
        return smtplib.SMTP(
            config.host,
            config.port,
            timeout=config.timeout,
            local_hostname=config.local_hostname,
        )

    def open_session(self) -> smtplib.SMTP:
        """Connect and negotiate the configured transport security.

        Returns a client that has completed EHLO (and STARTTLS, where
        configured) but has not authenticated. Shared with the ``--check``
        probe so that it tests exactly the handshake delivery uses.
        """
        client = self._connect()
        try:
            if self._config.resolved_security == "starttls":
                client.ehlo()
                client.starttls(context=self._ssl_context())
                client.ehlo()
        except BaseException:
            with suppress(smtplib.SMTPException, OSError):
                client.close()
            raise
        return client

    def send(self, message: EmailMessage, *, sender: str, recipients: Sequence[str]) -> str:
        """Deliver ``message`` and return its Message-ID."""
        config = self._config
        security = config.resolved_security
        client: smtplib.SMTP | None = None
        try:
            client = self.open_session()
            if config.username:
                client.login(config.username, config.password or "")
            client.send_message(message, from_addr=sender, to_addrs=list(recipients))
            return str(message["Message-ID"])
        except smtplib.SMTPResponseException as exc:
            error = exc.smtp_error
            if isinstance(error, bytes):
                error = error.decode("utf-8", "replace")
            raise RelayError(
                f"Mailhost rejected the message: {exc.smtp_code} {error}",
                smtp_code=exc.smtp_code,
            ) from exc
        except smtplib.SMTPException as exc:
            raise RelayError(f"SMTP error while talking to {config.endpoint}: {exc}") from exc
        except OSError as exc:
            raise RelayError(
                f"Could not reach mailhost {config.endpoint} over {security}: {exc}"
            ) from exc
        finally:
            if client is not None:
                with suppress(smtplib.SMTPException, OSError):
                    client.quit()
                with suppress(Exception):
                    client.close()
