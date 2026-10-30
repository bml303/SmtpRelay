"""``python -m app --check``: test the configuration against the real world.

The model validators in :mod:`app.config` catch what can be known from the
values alone. This module covers what cannot: whether the certificate material
actually loads, whether the mailhost is reachable, speaks the configured TLS
mode, accepts the credentials, and accepts the sender address. No mail is
sent - the SMTP session ends with RSET and QUIT after MAIL FROM.

Each probe yields a :class:`CheckResult`; :func:`render` prints them and
:func:`exit_code` maps them onto a process status. Secrets never appear in the
output.
"""

from __future__ import annotations

import smtplib
import socket
import ssl
import sys
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal, TextIO

from . import __version__
from .config import (
    LOOPBACK_HOSTS,
    ApiConfig,
    AppConfig,
    ConfigError,
    SmtpConfig,
    active_env_overrides,
    load_config,
)
from .relay import SmtpRelay

Status = Literal["ok", "warn", "fail", "skip"]

#: Below this many days left on the API certificate the check warns.
EXPIRY_WARNING_DAYS = 30


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: Status
    detail: str


def run_checks(settings: AppConfig, *, smtp: bool = True) -> list[CheckResult]:
    """Run every probe and return the results in display order."""
    results = [
        check_config(settings),
        check_api(settings.api),
        check_api_tls(settings.api),
        *check_policy(settings),
    ]
    if smtp:
        results.extend(check_smtp(settings))
    else:
        results.append(
            CheckResult("smtp", "skip", f"mailhost {settings.smtp.endpoint} not contacted (--no-smtp)")
        )
    return results


# ------------------------------------------------------------------ offline


def check_config(settings: AppConfig) -> CheckResult:
    overrides = active_env_overrides()
    detail = settings.source
    if overrides:
        detail += " (overridden from the environment: " + ", ".join(overrides) + ")"
    return CheckResult("config", "ok", detail)


def check_api(api: ApiConfig) -> CheckResult:
    listen = f"{api.scheme}://{api.host}:{api.port}"
    if api.host in LOOPBACK_HOSTS:
        auth = "bearer token required" if api.token else "no authentication"
        return CheckResult("api", "ok", f"{listen}, loopback only, {auth}")

    how = []
    if api.token:
        how.append("bearer token")
    if api.ssl_cert_reqs == "required":
        how.append("client certificate (mutual TLS)")
    transport = (
        "TLS terminated by a reverse proxy (api.behind_tls_proxy)"
        if api.behind_tls_proxy
        else "TLS served by this process"
    )
    # AppConfig has already refused anything without TLS and authentication.
    return CheckResult(
        "api",
        "ok",
        f"{listen}, reachable from the network, {transport}, clients authenticate with "
        + " or ".join(how),
    )


def check_api_tls(api: ApiConfig) -> CheckResult:
    if not api.tls_enabled:
        return CheckResult("api.tls", "skip", "no certificate source configured; API serves plain HTTP")

    from .tls import TlsError, load_server_context

    try:
        context, info = load_server_context(api)
    except TlsError as exc:
        return CheckResult("api.tls", "fail", str(exc))

    days = info.days_left()
    detail = f"{info.source}: subject {info.subject}, thumbprint {info.thumbprint}"
    status: Status = "ok"
    if days is None:
        pass
    elif days < 0:
        status = "fail"
        detail += f", EXPIRED {-days} day(s) ago ({info.not_after})"
    elif days < EXPIRY_WARNING_DAYS:
        status = "warn"
        detail += f", expires in {days} day(s) ({info.not_after})"
    else:
        detail += f", valid for {days} more days (until {info.not_after})"
    if info.chain_length:
        detail += f", {info.chain_length} chain certificate(s)"
    if api.ssl_ca_certs is not None:
        loaded = context.cert_store_stats().get("x509", 0)
        detail += (
            f"; client certificates {api.ssl_cert_reqs}, "
            f"{loaded} CA certificate(s) loaded from {api.ssl_ca_certs}"
        )
        if loaded == 0:
            status = "fail"
            detail += " - no client could validate"
    return CheckResult("api.tls", status, detail)


def check_policy(settings: AppConfig) -> list[CheckResult]:
    policy = settings.policy
    results: list[CheckResult] = []
    sender = policy.sender
    domains = policy.allowed_domains
    if domains:
        scope = ", ".join(domains) + (" and their subdomains" if policy.allow_subdomains else "")
        results.append(CheckResult("policy", "ok", f"sender {sender}; recipients allowed at {scope}"))
    else:
        results.append(
            CheckResult(
                "policy",
                "warn",
                f"sender {sender}; policy.allowed_domains is empty, so every request is "
                "rejected with domain_not_allowed",
            )
        )

    username = settings.smtp.username or ""
    if "@" in username:
        account_domain = username.rsplit("@", 1)[1].lower()
        sender_domain = sender.rsplit("@", 1)[1].lower()
        if account_domain != sender_domain:
            results.append(
                CheckResult(
                    "policy.sender",
                    "warn",
                    f"policy.sender {sender} is not in the domain of smtp.username "
                    f"({account_domain}); iCloud, Gmail and Microsoft 365 only accept a From "
                    "address owned by the authenticated account (the MAIL FROM probe below "
                    "shows whether this mailhost does)",
                )
            )
    return results


# ------------------------------------------------------------------- online


def check_smtp(settings: AppConfig) -> list[CheckResult]:
    """Resolve, connect, negotiate TLS, authenticate and offer the sender."""
    config = settings.smtp
    results: list[CheckResult] = []

    try:
        infos = socket.getaddrinfo(config.host, config.port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        results.append(CheckResult("smtp.dns", "fail", f"{config.host} does not resolve: {exc}"))
        results.append(CheckResult("smtp.session", "skip", "not attempted"))
        return results
    addresses = list(dict.fromkeys(info[4][0] for info in infos))
    results.append(CheckResult("smtp.dns", "ok", f"{config.host} resolves to " + ", ".join(addresses)))

    client: smtplib.SMTP | None = None
    try:
        try:
            client = SmtpRelay(config).open_session()
        except (smtplib.SMTPException, OSError) as exc:
            results.append(CheckResult("smtp.session", "fail", _explain_session_failure(config, exc)))
            return results

        # open_session() sends EHLO only where STARTTLS needs it; the relay's
        # send_message() does so itself later. The probes below talk to the
        # server directly, so make sure the greeting - and with it the
        # advertised extensions - has happened.
        try:
            client.ehlo_or_helo_if_needed()
        except (smtplib.SMTPException, OSError) as exc:
            results.append(CheckResult("smtp.session", "fail", f"{config.endpoint}: EHLO failed: {exc}"))
            return results
        results.append(CheckResult("smtp.session", "ok", _describe_session(config, client)))
        if config.resolved_security == "none" and client.has_extn("starttls"):
            results.append(
                CheckResult(
                    "smtp.tls",
                    "warn",
                    f"{config.endpoint} offers STARTTLS but the session is cleartext "
                    f'(smtp.security = "none"); set security = "starttls" so credentials '
                    "and mail do not cross the network unencrypted",
                )
            )

        authenticated = True
        if config.username:
            try:
                client.login(config.username, config.password or "")
                results.append(CheckResult("smtp.auth", "ok", f"authenticated as {config.username}"))
            except smtplib.SMTPAuthenticationError as exc:
                authenticated = False
                results.append(
                    CheckResult(
                        "smtp.auth",
                        "fail",
                        f"{config.endpoint} rejected the credentials for {config.username}: "
                        f"{exc.smtp_code} {_text(exc.smtp_error)}",
                    )
                )
            except smtplib.SMTPException as exc:
                authenticated = False
                results.append(
                    CheckResult(
                        "smtp.auth",
                        "fail",
                        f"cannot authenticate against {config.endpoint}: {exc} "
                        "(does the mailhost offer AUTH on this port and security mode?)",
                    )
                )
        elif client.has_extn("auth"):
            results.append(
                CheckResult(
                    "smtp.auth",
                    "warn",
                    f"{config.endpoint} offers AUTH but smtp.username is not set; submission "
                    "servers usually refuse unauthenticated mail (iCloud, for one, answers "
                    '554 "Client host rejected")',
                )
            )
        else:
            results.append(
                CheckResult("smtp.auth", "skip", "no credentials configured and the mailhost offers no AUTH")
            )

        if not authenticated:
            results.append(CheckResult("smtp.sender", "skip", "not attempted after the authentication failure"))
            return results

        sender = settings.policy.sender
        try:
            code, message = client.mail(sender)
        except smtplib.SMTPException as exc:
            results.append(CheckResult("smtp.sender", "fail", f"MAIL FROM:<{sender}> failed: {exc}"))
            return results
        finally:
            with suppress(smtplib.SMTPException, OSError):
                client.rset()
        if code == 250:
            results.append(CheckResult("smtp.sender", "ok", f"{config.endpoint} accepts MAIL FROM:<{sender}>"))
        else:
            results.append(
                CheckResult(
                    "smtp.sender",
                    "fail",
                    f"{config.endpoint} rejected MAIL FROM:<{sender}>: {code} {_text(message)}",
                )
            )
        return results
    finally:
        if client is not None:
            with suppress(smtplib.SMTPException, OSError):
                client.quit()


def _describe_session(config: SmtpConfig, client: smtplib.SMTP) -> str:
    sock = client.sock
    if isinstance(sock, ssl.SSLSocket):
        cipher = sock.cipher()
        suite = cipher[0] if cipher else "unknown cipher"
        mode = "implicit TLS" if config.resolved_security == "tls" else "STARTTLS"
        transport = f"{mode}, {sock.version()} {suite}, server certificate verified"
    else:
        transport = "cleartext"
    features = []
    if client.has_extn("auth"):
        features.append("AUTH " + client.esmtp_features["auth"].strip())
    if client.has_extn("size"):
        features.append("SIZE " + client.esmtp_features["size"].strip())
    if client.has_extn("starttls"):
        features.append("STARTTLS")
    offered = "; offers " + ", ".join(features) if features else ""
    return f"connected to {config.endpoint} over {transport}{offered}"


def _explain_session_failure(config: SmtpConfig, exc: BaseException) -> str:
    endpoint = config.endpoint
    security = config.resolved_security
    if isinstance(exc, ssl.SSLCertVerificationError):
        return (
            f"{endpoint}: the server certificate is not trusted ({exc.verify_message}); "
            "for an internal CA set smtp.ca_file to its bundle"
        )
    if isinstance(exc, ssl.SSLError):
        hint = (
            f'implicit TLS was attempted but the port answered in plaintext; port {config.port} '
            'probably expects STARTTLS (smtp.security = "starttls")'
            if security == "tls"
            else "TLS handshake failed"
        )
        return f"{endpoint}: {hint}: {exc}"
    if isinstance(exc, smtplib.SMTPNotSupportedError):
        return (
            f'{endpoint} does not offer STARTTLS, but smtp.security = "{security}" needs it; '
            'use port 465 with security = "tls", or security = "none" for a cleartext-only host'
        )
    if isinstance(exc, (TimeoutError, socket.timeout)):
        hint = (
            f'; if {config.port} is an implicit-TLS port (465), set smtp.security = "tls"'
            if security != "tls"
            else ""
        )
        return f"{endpoint}: no answer within {config.timeout:g}s{hint}"
    if isinstance(exc, smtplib.SMTPServerDisconnected):
        return f"{endpoint} closed the connection during the handshake: {exc}"
    if isinstance(exc, smtplib.SMTPException):
        return f"{endpoint}: {exc}"
    return f"{endpoint}: {exc}"


def _text(value: bytes | str | None) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value or "")


# ------------------------------------------------------------------- output

_LABELS = {"ok": "ok  ", "warn": "WARN", "fail": "FAIL", "skip": "skip"}


def render(results: Sequence[CheckResult]) -> str:
    width = max((len(result.name) for result in results), default=0)
    lines = [f"smtp-relay {__version__} configuration check"]
    for result in results:
        lines.append(f"  {_LABELS[result.status]}  {result.name.ljust(width)}  {result.detail}")
    counts = {status: sum(1 for r in results if r.status == status) for status in _LABELS}
    summary = f"{counts['ok']} ok, {counts['warn']} warning(s), {counts['fail']} failed"
    if counts["skip"]:
        summary += f", {counts['skip']} skipped"
    lines.append(f"Result: {summary}")
    return "\n".join(lines)


def exit_code(results: Sequence[CheckResult]) -> int:
    return 1 if any(result.status == "fail" for result in results) else 0


def main(config_path: str | None = None, *, smtp: bool = True, out: TextIO | None = None) -> int:
    """Entry point behind ``python -m app --check``; returns the process status.

    0: nothing failed (warnings may be present); 1: at least one probe failed;
    2: the configuration itself does not load.
    """
    try:
        settings = load_config(config_path)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    results = run_checks(settings, smtp=smtp)
    print(render(results), file=out or sys.stdout)
    return exit_code(results)
