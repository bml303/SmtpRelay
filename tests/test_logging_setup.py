"""Logging setup, including the platform guard on the Event Log path."""

from __future__ import annotations

import logging
import sys

import pytest

from app.logging_setup import (
    EVENT_LOG_SOURCE,
    configure_event_log_logging,
    configure_stderr_logging,
)


@pytest.fixture
def clean_root():
    """Give each test an empty root logger and restore it afterwards."""
    root = logging.getLogger()
    saved_level = root.level
    saved_handlers = list(root.handlers)
    for handler in saved_handlers:
        root.removeHandler(handler)
    try:
        yield root
    finally:
        for handler in list(root.handlers):
            root.removeHandler(handler)
        for handler in saved_handlers:
            root.addHandler(handler)
        root.setLevel(saved_level)


def _stderr_handlers(root: logging.Logger) -> list[logging.StreamHandler]:
    return [
        handler
        for handler in root.handlers
        if isinstance(handler, logging.StreamHandler)
        and getattr(handler, "stream", None) is sys.stderr
    ]


def test_stderr_logging_targets_stderr_with_the_expected_format(clean_root):
    configure_stderr_logging(level=logging.DEBUG)

    assert clean_root.level == logging.DEBUG
    handlers = _stderr_handlers(clean_root)
    assert handlers, f"expected a stderr StreamHandler, got {clean_root.handlers}"

    record = logging.LogRecord("smtp_relay", logging.INFO, __file__, 1, "hello", (), None)
    assert handlers[0].format(record).endswith("INFO smtp_relay: hello")


@pytest.mark.skipif(sys.platform == "win32", reason="Event Log is the supported path on Windows")
def test_event_log_logging_refuses_off_windows(clean_root):
    """Must fail loudly rather than silently discarding every log line."""
    before = list(clean_root.handlers)

    with pytest.raises(RuntimeError, match="requires Windows"):
        configure_event_log_logging()

    # The guard trips before any handler is touched, so nothing is half-configured.
    assert clean_root.handlers == before


def test_event_log_source_name_is_stable():
    """Changing the source would orphan events already written under the old name."""
    assert EVENT_LOG_SOURCE == "SmtpRelay"
