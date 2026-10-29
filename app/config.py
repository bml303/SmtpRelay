"""Configuration: a TOML file with environment-variable overrides.

Env vars always win over the file, so secrets (``RELAY_SMTP_PASSWORD``,
``RELAY_API_TOKEN``) never have to be written to disk.
"""

from __future__ import annotations

import copy
import os
import ssl
import sys
import tomllib
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, ValidationError, model_validator

SecurityMode = Literal["starttls", "tls", "none"]

CONFIG_ENV_VAR = "RELAY_CONFIG"
DEFAULT_CONFIG_PATH = Path("config.toml")

#: Directory holding the ``app`` package, i.e. the deployment/install root.
PACKAGE_ROOT = Path(__file__).resolve().parent.parent

#: Machine-wide config directory name, following each platform's convention.
#: Windows uses the service name as registered with the SCM; POSIX uses the
#: conventional lowercase-hyphenated form.
WINDOWS_CONFIG_DIRNAME = "SmtpRelay"
POSIX_CONFIG_DIRNAME = "smtp-relay"

#: Security mode assumed per port when ``smtp.security`` is not set explicitly.
PORT_DEFAULTS: dict[int, SecurityMode] = {465: "tls", 587: "starttls", 25: "none"}


class ConfigError(RuntimeError):
    """Raised when configuration cannot be read or fails validation."""


class SmtpConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = Field(min_length=1)
    port: int = Field(default=587, ge=1, le=65535)
    #: ``None`` means "infer from the port" (465 -> tls, 587 -> starttls, 25 -> none).
    security: SecurityMode | None = None
    username: str | None = None
    password: str | None = None
    timeout: float = Field(default=30.0, gt=0)
    ca_file: Path | None = None
    #: Name used in EHLO/HELO. Defaults to the local FQDN when omitted.
    local_hostname: str | None = None

    @property
    def resolved_security(self) -> SecurityMode:
        if self.security is not None:
            return self.security
        return PORT_DEFAULTS.get(self.port, "starttls")

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"


#: uvicorn takes ``ssl_cert_reqs`` as an int (``ssl.VerifyMode``), not a string,
#: so the readable config value is mapped before being passed on.
SSL_VERIFY_MODES: dict[str, int] = {
    "none": ssl.CERT_NONE,
    "optional": ssl.CERT_OPTIONAL,
    "required": ssl.CERT_REQUIRED,
}

SslVerifyMode = Literal["none", "optional", "required"]


class ApiConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)
    #: When set, every request must carry ``Authorization: Bearer <token>``.
    token: str | None = None
    max_recipients: int = Field(default=50, gt=0)

    #: Inbound TLS. Off until ``ssl_certfile`` is set, at which point uvicorn
    #: serves HTTPS. The default loopback bind means it is normally not needed.
    ssl_certfile: Path | None = None
    ssl_keyfile: Path | None = None
    ssl_keyfile_password: str | None = None
    #: Client CA bundle, for mutual TLS. Pair with ``ssl_cert_reqs``.
    ssl_ca_certs: Path | None = None
    ssl_cert_reqs: SslVerifyMode | None = None

    #: Declares that a reverse proxy or ingress on a private network terminates
    #: TLS in front of this process - the usual container deployment, where the
    #: app must bind 0.0.0.0 to be reachable at all. It waives only the TLS half
    #: of the network-exposure rule in :class:`AppConfig`; authentication is
    #: still required, because a proxy does nothing to stop whoever can reach it
    #: from relaying mail. Mutually exclusive with ``ssl_certfile``: TLS is
    #: terminated in exactly one place.
    behind_tls_proxy: bool = False

    @model_validator(mode="after")
    def _tls_is_terminated_in_one_place(self) -> "ApiConfig":
        if self.behind_tls_proxy and self.ssl_certfile is not None:
            raise ValueError(
                "api.behind_tls_proxy = true says a reverse proxy terminates TLS, "
                "but api.ssl_certfile makes this process terminate it as well. "
                "Behind a proxy leave the api.ssl_* keys unset; to serve TLS from "
                "this process, drop behind_tls_proxy."
            )
        return self

    @model_validator(mode="after")
    def _require_certfile_for_tls(self) -> "ApiConfig":
        """Reject a half-configured TLS setup at startup, not inside uvicorn."""
        if self.ssl_certfile is not None:
            return self
        others = {
            "ssl_keyfile": self.ssl_keyfile,
            "ssl_keyfile_password": self.ssl_keyfile_password,
            "ssl_ca_certs": self.ssl_ca_certs,
            "ssl_cert_reqs": self.ssl_cert_reqs,
        }
        dangling = sorted(name for name, value in others.items() if value is not None)
        if dangling:
            raise ValueError(
                "api.ssl_certfile is required when these are also set: " + ", ".join(dangling)
            )
        return self

    @model_validator(mode="after")
    def _mtls_options_are_coherent(self) -> "ApiConfig":
        """Reject mTLS settings that would silently no-op, or silently lock everyone out.

        uvicorn loads the client CA bundle only when ``ssl_ca_certs`` is given, but
        sets ``verify_mode`` from ``ssl_cert_reqs`` unconditionally. The two must
        therefore be configured together:

        * ``ssl_ca_certs`` alone leaves ``verify_mode`` at ``CERT_NONE``, so no
          client certificate is ever requested and mTLS does nothing at all.
        * ``ssl_cert_reqs`` alone verifies clients against an empty trust store,
          so every client -- including valid ones -- is rejected.
        """
        if self.ssl_ca_certs is not None and self.ssl_cert_reqs is None:
            raise ValueError(
                'api.ssl_ca_certs is set but api.ssl_cert_reqs is not; uvicorn would '
                'leave verify_mode at CERT_NONE and never request a client certificate. '
                'Set ssl_cert_reqs = "optional" or "required".'
            )
        if self.ssl_cert_reqs in ("optional", "required") and self.ssl_ca_certs is None:
            raise ValueError(
                f'api.ssl_cert_reqs = "{self.ssl_cert_reqs}" requires api.ssl_ca_certs; '
                "without a client CA bundle no certificate can validate, so every "
                "client would be rejected."
            )
        return self

    @property
    def tls_enabled(self) -> bool:
        return self.ssl_certfile is not None

    @property
    def scheme(self) -> str:
        return "https" if self.tls_enabled else "http"

    def uvicorn_ssl_kwargs(self) -> dict[str, Any]:
        """Keyword arguments for uvicorn; empty when TLS is off.

        Shared by both entry points so the CLI and the Windows service cannot
        drift apart in how they enable TLS.
        """
        if not self.tls_enabled:
            return {}
        kwargs: dict[str, Any] = {"ssl_certfile": str(self.ssl_certfile)}
        if self.ssl_keyfile is not None:
            kwargs["ssl_keyfile"] = str(self.ssl_keyfile)
        if self.ssl_keyfile_password is not None:
            kwargs["ssl_keyfile_password"] = self.ssl_keyfile_password
        if self.ssl_ca_certs is not None:
            kwargs["ssl_ca_certs"] = str(self.ssl_ca_certs)
        if self.ssl_cert_reqs is not None:
            kwargs["ssl_cert_reqs"] = SSL_VERIFY_MODES[self.ssl_cert_reqs]
        return kwargs


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sender: EmailStr
    sender_name: str | None = None
    allowed_domains: list[str] = Field(default_factory=list)
    allow_subdomains: bool = False
    reject_base64: bool = True


#: Hosts reachable only from the local machine. Binding anything else puts the
#: API on the network.
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    api: ApiConfig = Field(default_factory=ApiConfig)
    smtp: SmtpConfig
    policy: PolicyConfig

    @model_validator(mode="after")
    def _network_exposure_needs_tls_and_auth(self) -> "AppConfig":
        """Refuse to come up as a network-reachable cleartext open relay.

        Enforced here rather than in the installer so that no entry point -
        ``python -m app``, the Windows service, or a hand-written uvicorn
        command - can bypass it.

        Binding a non-loopback address has two consequences that must both be
        addressed: requests (including the bearer token and message bodies)
        cross the network, and any host that can reach the port can submit mail.
        The second is what makes an unauthenticated relay an *open* relay: the
        domain allowlist still constrains destinations, but anyone on the network
        gets to use them.

        ``ssl_cert_reqs = "optional"`` does not count as authentication - clients
        may simply present no certificate - so only a bearer token or required
        mutual TLS satisfies the check.

        ``api.behind_tls_proxy`` is the one deliberate opt-out, and it covers the
        TLS half only: a proxy that terminates TLS on a private network keeps the
        token off the wire, but it does not authenticate anyone, so a token or
        required mTLS is still demanded. Nothing waives the authentication half.
        """
        if self.api.host in LOOPBACK_HOSTS:
            return self

        problems = []
        if not self.api.tls_enabled and not self.api.behind_tls_proxy:
            problems.append(
                "api.ssl_certfile is unset, so traffic including the bearer "
                "token would cross the network in cleartext (set "
                "api.behind_tls_proxy = true only when a reverse proxy on a "
                "private network terminates TLS for it)"
            )
        authenticates = self.api.token is not None or self.api.ssl_cert_reqs == "required"
        if not authenticates:
            problems.append(
                'neither api.token nor mutual TLS (ssl_cert_reqs = "required") is '
                "configured, so any host on the network could relay mail through it"
            )
        if problems:
            raise ValueError(
                f"api.host = {self.api.host!r} is reachable from the network, but "
                + "; and ".join(problems)
                + '. Bind api.host to 127.0.0.1, or configure both.'
            )
        return self


#: Scalar/optional overrides. ``RELAY_ALLOWED_DOMAINS`` is handled separately
#: because it maps a comma-separated string onto a list.
_ENV_OVERRIDES: dict[str, tuple[str, str]] = {
    "RELAY_API_HOST": ("api", "host"),
    "RELAY_API_PORT": ("api", "port"),
    "RELAY_API_TOKEN": ("api", "token"),
    "RELAY_MAX_RECIPIENTS": ("api", "max_recipients"),
    "RELAY_API_SSL_CERTFILE": ("api", "ssl_certfile"),
    "RELAY_API_SSL_KEYFILE": ("api", "ssl_keyfile"),
    "RELAY_API_SSL_KEYFILE_PASSWORD": ("api", "ssl_keyfile_password"),
    "RELAY_API_SSL_CA_CERTS": ("api", "ssl_ca_certs"),
    "RELAY_API_SSL_CERT_REQS": ("api", "ssl_cert_reqs"),
    "RELAY_API_BEHIND_TLS_PROXY": ("api", "behind_tls_proxy"),
    "RELAY_SMTP_HOST": ("smtp", "host"),
    "RELAY_SMTP_PORT": ("smtp", "port"),
    "RELAY_SMTP_SECURITY": ("smtp", "security"),
    "RELAY_SMTP_USERNAME": ("smtp", "username"),
    "RELAY_SMTP_PASSWORD": ("smtp", "password"),
    "RELAY_SMTP_TIMEOUT": ("smtp", "timeout"),
    "RELAY_SMTP_CA_FILE": ("smtp", "ca_file"),
    "RELAY_SENDER": ("policy", "sender"),
    "RELAY_SENDER_NAME": ("policy", "sender_name"),
    "RELAY_ALLOW_SUBDOMAINS": ("policy", "allow_subdomains"),
    "RELAY_REJECT_BASE64": ("policy", "reject_base64"),
}

_LIST_OVERRIDES: dict[str, tuple[str, str]] = {
    "RELAY_ALLOWED_DOMAINS": ("policy", "allowed_domains"),
}


def _section(data: dict[str, Any], name: str) -> dict[str, Any]:
    """Return ``data[name]`` as a dict, replacing it if it held something else.

    Env vars are documented as authoritative, so a malformed section in the file
    must not block them.
    """
    target = data.get(name)
    if not isinstance(target, dict):
        target = {}
        data[name] = target
    return target


def _apply_env_overrides(raw: dict[str, Any]) -> dict[str, Any]:
    data = copy.deepcopy(raw)
    for env_name, (section, key) in _ENV_OVERRIDES.items():
        value = os.environ.get(env_name)
        if value is not None:
            _section(data, section)[key] = value
    for env_name, (section, key) in _LIST_OVERRIDES.items():
        value = os.environ.get(env_name)
        if value is not None:
            _section(data, section)[key] = [part.strip() for part in value.split(",") if part.strip()]
    return data


def _system_config_dir() -> Path | None:
    """Machine-wide config directory, following each platform's convention.

    Windows: ``%ProgramData%\\SmtpRelay`` - Program Files is read-only by
    convention and is wiped on upgrade, so mutable config does not belong there.
    POSIX: ``/etc/smtp-relay``.
    """
    if sys.platform == "win32":
        root = os.environ.get("ProgramData") or os.environ.get("PROGRAMDATA")
        return Path(root) / WINDOWS_CONFIG_DIRNAME if root else None
    return Path("/etc") / POSIX_CONFIG_DIRNAME


def _candidate_paths(explicit: str | os.PathLike[str] | None) -> tuple[list[Path], bool]:
    """Return the config paths to try, in priority order, and whether one was
    demanded explicitly.

    Three implicit locations, first match wins:

    1. the working directory - convenient when iterating in a checkout
    2. the machine-wide config dir - where a deployed service should read from.
       Essential rather than cosmetic: the SCM starts a service with its working
       directory set to ``C:\\Windows\\System32``, and under a non-editable
       install ``PACKAGE_ROOT`` is ``site-packages``, which is wiped on upgrade.
    3. beside the ``app`` package - correct for an editable checkout, where the
       package lives in the repository
    """
    if explicit is not None:
        return [Path(explicit)], True
    from_env = os.environ.get(CONFIG_ENV_VAR)
    if from_env:
        return [Path(from_env)], True

    name = DEFAULT_CONFIG_PATH.name
    candidates = [Path.cwd() / name]
    system_dir = _system_config_dir()
    if system_dir is not None:
        candidates.append(system_dir / name)
    candidates.append(PACKAGE_ROOT / name)
    # The container's working directory *is* the system config dir, which would
    # otherwise list the same path twice in "Searched: ..." messages.
    unique = list(dict.fromkeys(candidates))
    return unique, False


def load_config(path: str | os.PathLike[str] | None = None) -> AppConfig:
    """Load configuration from ``path``, ``$RELAY_CONFIG``, or ``config.toml``.

    ``config.toml`` is searched for in the working directory first, then beside
    the installed ``app`` package. A missing file is only an error when the path
    was demanded explicitly; otherwise the environment alone may supply
    everything required.
    """
    candidates, explicit = _candidate_paths(path)

    raw: dict[str, Any] = {}
    used: Path | None = None
    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            with candidate.open("rb") as handle:
                raw = tomllib.load(handle)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"{candidate} is not valid TOML: {exc}") from exc
        except OSError as exc:
            raise ConfigError(f"Could not read {candidate}: {exc}") from exc
        used = candidate
        break

    if used is None and explicit:
        raise ConfigError(f"Config file not found: {candidates[0]}")

    source = str(used) if used is not None else "environment only"
    try:
        return AppConfig.model_validate(_apply_env_overrides(raw))
    except ValidationError as exc:
        searched = (
            ""
            if used is not None
            else "\nNo config file was found. Searched: "
            + ", ".join(str(candidate) for candidate in candidates)
        )
        raise ConfigError(f"Invalid configuration (from {source}):{searched}\n{exc}") from exc
