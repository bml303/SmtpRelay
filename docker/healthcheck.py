"""Container HEALTHCHECK: GET /health through whatever the app is configured for.

Loads the same configuration the service did, so a non-default port or TLS set
via ``config.toml`` is honoured rather than guessed from the environment. The
process's own certificate is not verified: this probes liveness from inside the
container, where the hostname never matches the certificate's SAN.

Known limit: under ``ssl_cert_reqs = "required"`` the handshake needs a client
certificate this probe does not have, so disable the HEALTHCHECK for that setup.
"""

from __future__ import annotations

import ssl
import sys
import urllib.error
import urllib.request

from app.config import ConfigError, load_config

#: Wildcard binds are not connectable; probe loopback instead.
WILDCARD_HOSTS = {"0.0.0.0", "::", ""}


def main() -> int:
    try:
        settings = load_config()
    except ConfigError as exc:
        print(f"unhealthy: configuration no longer loads: {exc}", file=sys.stderr)
        return 1

    host = "127.0.0.1" if settings.api.host in WILDCARD_HOSTS else settings.api.host
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    url = f"{settings.api.scheme}://{host}:{settings.api.port}/health"

    context = ssl._create_unverified_context() if settings.api.tls_enabled else None
    try:
        with urllib.request.urlopen(url, timeout=4, context=context) as response:
            if response.status != 200:
                print(f"unhealthy: {url} returned {response.status}", file=sys.stderr)
                return 1
    except (urllib.error.URLError, OSError) as exc:
        print(f"unhealthy: {url}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
