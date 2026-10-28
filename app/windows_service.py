"""Native Windows service wrapper for the SMTP relay (requires pywin32).

Manage from an **elevated** prompt, using the interpreter of the environment the
relay is installed into (a venv's ``Scripts\\python.exe``, not the system one):

    python -m app.windows_service install
    python -m app.windows_service start
    python -m app.windows_service stop
    python -m app.windows_service restart
    python -m app.windows_service remove

Debug in a console instead of under the Service Control Manager:

    python -m app.windows_service debug

This module imports win32 modules at import time, so it can only be *imported* on
Windows. It compiles anywhere; ``tests/test_windows_service.py`` checks that.

Configuration is found the same way as for ``python -m app``: ``RELAY_CONFIG`` if
set, else ``config.toml`` in the working directory, else ``config.toml`` beside
the ``app`` package. The last of those is what makes the service work, since the
SCM starts it with the working directory set to ``C:\\Windows\\System32``.
"""

from __future__ import annotations

import sys

if sys.platform != "win32":
    raise ImportError(
        "app.windows_service requires Windows and pywin32; "
        f"this interpreter is running on {sys.platform!r}."
    )

import logging
import threading

import servicemanager
import uvicorn
import win32event
import win32service
import win32serviceutil

from .config import ConfigError, load_config
from .logging_setup import configure_event_log_logging, configure_stderr_logging
from .main import create_app

#: How long to let uvicorn drain connections after a stop request.
SHUTDOWN_TIMEOUT_SECONDS = 30

#: Registry ``PythonClass`` value: an importable dotted path, never a file path.
#:
#: This must be passed explicitly. Running ``python -m app.windows_service``
#: executes the module as ``__main__``, so pywin32's ``GetServiceClassString``
#: takes its fallback branch and records ``C:\...\app\windows_service.SmtpRelayService``
#: - a filesystem path. ``pythonservice.exe`` then imports that file as a
#: top-level module, the relative imports below (``from .config import ...``)
#: raise ``ImportError: attempted relative import with no known parent package``,
#: and the process dies before ``SvcRun``. The SCM never receives a status
#: transition and reports error 1053, "The service did not respond to the start
#: or control request in a timely fashion".
SERVICE_CLASS_STRING = "app.windows_service.SmtpRelayService"

log = logging.getLogger("smtp_relay")


class SmtpRelayService(win32serviceutil.ServiceFramework):
    """Runs the FastAPI app under uvicorn, inside a worker thread.

    The service's own thread must stay free to answer SCM control requests, so
    the blocking ``Server.run()`` loop lives in a separate thread and is stopped
    by setting uvicorn's ``should_exit`` flag.
    """

    _svc_name_ = "SmtpRelay"
    _svc_display_name_ = "SMTP Relay"
    _svc_description_ = (
        "Accepts JSON over REST and relays it as mail through the configured SMTP mailhost."
    )

    def __init__(self, args) -> None:
        win32serviceutil.ServiceFramework.__init__(self, args)
        self._stop_requested = win32event.CreateEvent(None, 0, 0, None)
        self._server: uvicorn.Server | None = None

    def SvcStop(self) -> None:
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        log.info("Stop requested, draining in-flight requests")
        if self._server is not None:
            # uvicorn polls this flag between requests and shuts down gracefully.
            self._server.should_exit = True
        win32event.SetEvent(self._stop_requested)

    def SvcDoRun(self) -> None:
        # `ssh` is the service status handle from RegisterServiceCtrlHandler,
        # assigned in ServiceFramework.__init__ before SvcRun calls this. It is
        # None exactly when running under `debug`, which is the same signal
        # pywin32's own ReportServiceStatus uses (`if self.ssh is None:
        # # Debugging!`).
        #
        # Do not detect debug mode from sys.argv: the non-frozen path runs
        # `pythonservice.exe -debug <name>`, so argv holds "-debug" rather than
        # "debug" and an equality test silently misses. Debug mode must log to
        # the console - writing to the Event Log there would hide the very
        # errors debug mode exists to reveal.
        if self.ssh is None:
            configure_stderr_logging()
        else:
            configure_event_log_logging()
        servicemanager.LogInfoMsg(f"{self._svc_display_name} starting")

        try:
            settings = load_config()
        except ConfigError as exc:
            # Returning (rather than raising) reports a clean stop; the reason is
            # in the event log, which is where an operator will look.
            log.critical("Startup aborted, invalid configuration: %s", exc)
            servicemanager.LogErrorMsg(
                f"{self._svc_display_name} configuration error: {exc}"
            )
            return

        server = uvicorn.Server(
            uvicorn.Config(
                create_app(settings),
                host=settings.api.host,
                port=settings.api.port,
                # Keep uvicorn from replacing the event log handler installed above.
                log_config=None,
                **settings.api.uvicorn_ssl_kwargs(),
            )
        )
        self._server = server

        worker = threading.Thread(target=server.run, name="uvicorn", daemon=True)
        worker.start()

        log.info(
            "Listening on %s://%s:%s, relaying via %s (%s)",
            settings.api.scheme,
            settings.api.host,
            settings.api.port,
            settings.smtp.endpoint,
            settings.smtp.resolved_security,
        )
        servicemanager.LogInfoMsg(
            f"{self._svc_display_name} listening on "
            f"{settings.api.scheme}://{settings.api.host}:{settings.api.port}, mailhost "
            f"{settings.smtp.endpoint} ({settings.smtp.resolved_security})"
        )

        win32event.WaitForSingleObject(self._stop_requested, win32event.INFINITE)
        worker.join(timeout=SHUTDOWN_TIMEOUT_SECONDS)
        if worker.is_alive():
            log.warning("HTTP server did not stop within %ss", SHUTDOWN_TIMEOUT_SECONDS)

        servicemanager.LogInfoMsg(f"{self._svc_display_name} stopped")


def main() -> None:
    if len(sys.argv) == 1:
        # Launched by the SCM via pythonservice.exe, with no arguments.
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(SmtpRelayService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(
            SmtpRelayService, serviceClassString=SERVICE_CLASS_STRING
        )


if __name__ == "__main__":
    main()
