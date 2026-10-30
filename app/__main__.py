"""Entry point: ``python -m app``."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence

import uvicorn

from .config import ConfigError, load_config
from .logging_setup import configure_stderr_logging
from .main import create_app


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app",
        description="REST-to-SMTP relay. Without options, serves the API.",
    )
    parser.add_argument(
        "-c",
        "--config",
        metavar="PATH",
        help="configuration file (default: $RELAY_CONFIG, then config.toml in the "
        "working directory, the system config directory, or beside the package)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="do not serve: validate the configuration, load the API certificate, "
        "hold a dry SMTP session with the mailhost (connect, TLS, AUTH, MAIL FROM, "
        "then RSET and QUIT - nothing is sent) and exit 0/1/2 for "
        "passed/failed/unloadable configuration",
    )
    parser.add_argument(
        "--no-smtp",
        action="store_true",
        help="with --check: do not contact the mailhost",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.no_smtp and not args.check:
        build_parser().error("--no-smtp only applies together with --check")
    if args.check:
        from .check import main as check

        return check(args.config, smtp=not args.no_smtp)

    configure_stderr_logging()
    try:
        settings = load_config(args.config)
        # Decodes a PKCS#12 / certificate-store source now, so a bad passphrase
        # or a missing key is a config error here, not a traceback in uvicorn.
        ssl_kwargs = settings.api.uvicorn_ssl_kwargs()
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    logger = logging.getLogger("smtp_relay")
    logger.info(
        "Listening on %s://%s:%s, relaying via %s (%s)",
        settings.api.scheme,
        settings.api.host,
        settings.api.port,
        settings.smtp.endpoint,
        settings.smtp.resolved_security,
    )
    uvicorn.run(
        create_app(settings),
        host=settings.api.host,
        port=settings.api.port,
        **ssl_kwargs,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
