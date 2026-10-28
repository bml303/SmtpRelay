"""Entry point: ``python -m app``."""

from __future__ import annotations

import logging
import sys

import uvicorn

from .config import ConfigError, load_config
from .logging_setup import configure_stderr_logging
from .main import create_app


def main() -> int:
    configure_stderr_logging()
    try:
        settings = load_config()
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    logging.getLogger("smtp_relay").info(
        "Relaying via %s (%s)", settings.smtp.endpoint, settings.smtp.resolved_security
    )
    uvicorn.run(create_app(settings), host=settings.api.host, port=settings.api.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
