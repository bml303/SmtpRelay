"""Configuration: a TOML file with environment-variable overrides.

Env vars always win over the file, so secrets (``RELAY_SMTP_PASSWORD``,
``RELAY_API_TOKEN``) never have to be written to disk.
"""

from __future__ import annotations

import copy
import os
import tomllib
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, ValidationError

SecurityMode = Literal["starttls", "tls", "none"]

CONFIG_ENV_VAR = "RELAY_CONFIG"
DEFAULT_CONFIG_PATH = Path("config.toml")

#: Directory holding the ``app`` package, i.e. the deployment/install root.
PACKAGE_ROOT = Path(__file__).resolve().parent.parent

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


class ApiConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)
    #: When set, every request must carry ``Authorization: Bearer <token>``.
    token: str | None = None
    max_recipients: int = Field(default=50, gt=0)


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sender: EmailStr
    sender_name: str | None = None
    allowed_domains: list[str] = Field(default_factory=list)
    allow_subdomains: bool = False
    reject_base64: bool = True


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    api: ApiConfig = Field(default_factory=ApiConfig)
    smtp: SmtpConfig
    policy: PolicyConfig


#: Scalar/optional overrides. ``RELAY_ALLOWED_DOMAINS`` is handled separately
#: because it maps a comma-separated string onto a list.
_ENV_OVERRIDES: dict[str, tuple[str, str]] = {
    "RELAY_API_HOST": ("api", "host"),
    "RELAY_API_PORT": ("api", "port"),
    "RELAY_API_TOKEN": ("api", "token"),
    "RELAY_MAX_RECIPIENTS": ("api", "max_recipients"),
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


def _candidate_paths(explicit: str | os.PathLike[str] | None) -> tuple[list[Path], bool]:
    """Return the config paths to try, and whether one was demanded explicitly.

    Falls back to the deployment root (the directory holding the ``app`` package)
    because the Windows SCM starts a service with its working directory set to
    ``C:\\Windows\\System32``, where no ``config.toml`` will ever be found.
    """
    if explicit is not None:
        return [Path(explicit)], True
    from_env = os.environ.get(CONFIG_ENV_VAR)
    if from_env:
        return [Path(from_env)], True
    name = DEFAULT_CONFIG_PATH.name
    return [Path.cwd() / name, PACKAGE_ROOT / name], False


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
