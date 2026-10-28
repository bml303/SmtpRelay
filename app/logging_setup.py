"""Logging configuration, platform-aware.

Foreground runs (``python -m app``) log to stderr. The Windows service logs to
the Application event log instead, because a service has no console and anything
written to stderr is silently discarded.
"""

from __future__ import annotations

import logging
import sys

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"

#: Source name registered in the Windows Application event log.
EVENT_LOG_SOURCE = "SmtpRelay"


def configure_stderr_logging(level: int = logging.INFO) -> None:
    """Log to stderr, for foreground and container use.

    ``force=True`` makes this deterministic: plain ``basicConfig`` silently does
    nothing when the root logger already has a handler, which would leave the
    process logging through whatever someone else installed.
    """
    logging.basicConfig(level=level, format=LOG_FORMAT, stream=sys.stderr, force=True)


def configure_event_log_logging(
    level: int = logging.INFO, source: str = EVENT_LOG_SOURCE
) -> None:
    """Route all logging to the Windows Application event log.

    Requires pywin32. Registering the event source needs administrative rights,
    which installing the service already demands.

    uvicorn must be started with ``log_config=None``; otherwise it installs its
    own handlers and its records never reach the event log.
    """
    if sys.platform != "win32":
        raise RuntimeError(
            f"Windows Event Log logging requires Windows; this interpreter is on {sys.platform!r}."
        )

    # Imported here so the module stays importable on non-Windows platforms.
    from logging.handlers import NTEventLogHandler

    root = logging.getLogger()
    root.setLevel(level)
    for handler in list(root.handlers):
        handler.close()
        root.removeHandler(handler)
    root.addHandler(NTEventLogHandler(source))
