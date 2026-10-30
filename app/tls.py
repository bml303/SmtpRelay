"""Server TLS context from a PKCS#12 file or the Windows certificate store.

Three certificate sources are supported, exactly one of which may be set:

``api.ssl_certfile``
    PEM chain and key on disk. Handed to uvicorn as file paths; uvicorn builds
    the context itself. Nothing in this module runs.
``api.ssl_pfxfile``
    A PKCS#12 (``.pfx`` / ``.p12``) file, optionally passphrase-protected.
``api.ssl_cert_thumbprint``
    A certificate in the Windows ``LocalMachine\\My`` store, located by its
    SHA-1 thumbprint. Windows only.

Python's TLS is OpenSSL, which can neither read PKCS#12 nor sign with a CNG key
handle, so both of the last two sources are decoded with ``cryptography`` and
then loaded through the standard library's file-based ``load_cert_chain``. The
key therefore touches disk briefly - but only PEM-encrypted under a random
one-time passphrase that lives in this process, in a private temporary
directory that is removed as soon as the context exists.

The Windows store source exports the certificate through CryptoAPI
(``PFXExportCertStoreEx``), which requires the key to have been imported as
exportable and the service account to hold read access on it. A non-exportable
key cannot be used from this process at all; terminate TLS in IIS or HTTP.sys
in front of the relay instead (``api.behind_tls_proxy``).
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import secrets
import ssl
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - import cycle guard, config imports this lazily
    from .config import ApiConfig

log = logging.getLogger("smtp_relay.tls")

#: SHA-1 thumbprints as certlm.msc and PowerShell show them: 40 hex digits, with
#: or without separators, any case.
_THUMBPRINT_SEPARATORS = re.compile(r"[\s:\-]")
_THUMBPRINT_RE = re.compile(r"^[0-9A-F]{40}$")

#: The Windows store the installer imports into and the service reads from.
WINDOWS_STORE_NAME = "MY"


class TlsError(RuntimeError):
    """A certificate source that cannot be turned into a TLS context."""


def normalize_thumbprint(value: str) -> str:
    """``"ab:cd ..."`` -> ``"ABCD..."``; raises ``ValueError`` unless 40 hex digits remain."""
    cleaned = _THUMBPRINT_SEPARATORS.sub("", value).upper()
    if not _THUMBPRINT_RE.match(cleaned):
        raise ValueError(
            "a certificate thumbprint is the SHA-1 hash as shown by certlm.msc: "
            f"40 hexadecimal digits, got {value!r}"
        )
    return cleaned


def windows_store_available() -> bool:
    """Whether ``api.ssl_cert_thumbprint`` can work on this host."""
    return sys.platform == "win32"


@dataclass(frozen=True)
class LoadedCertificate:
    """What a decoded PKCS#12 blob yielded, for logging and tests."""

    subject: str
    not_after: str
    thumbprint: str
    chain_length: int


def build_ssl_context(api: ApiConfig) -> ssl.SSLContext:
    """Build the server context for a PFX or Windows-store source.

    Raises :class:`TlsError` with an operator-readable message; the entry points
    turn that into a configuration error at startup rather than a traceback in
    uvicorn's worker thread.
    """
    if api.ssl_pfxfile is not None:
        try:
            blob = Path(api.ssl_pfxfile).read_bytes()
        except OSError as exc:
            raise TlsError(f"api.ssl_pfxfile: cannot read {api.ssl_pfxfile}: {exc}") from exc
        source = f"PKCS#12 file {api.ssl_pfxfile}"
        password = api.ssl_pfx_password
    elif api.ssl_cert_thumbprint is not None:
        blob, password = export_from_windows_store(api.ssl_cert_thumbprint)
        source = f"Windows certificate store LocalMachine\\{WINDOWS_STORE_NAME}, thumbprint {api.ssl_cert_thumbprint}"
    else:  # pragma: no cover - ApiConfig only hands over the two sources above
        raise TlsError("no PKCS#12 or certificate-store source is configured")

    context, info = context_from_pkcs12(
        blob,
        password,
        cert_reqs=api.verify_mode,
        ca_certs=api.ssl_ca_certs,
        source=source,
    )
    log.info(
        "TLS certificate from %s: subject %s, thumbprint %s, valid until %s, %d chain certificate(s)",
        source, info.subject, info.thumbprint, info.not_after, info.chain_length,
    )
    return context


def context_from_pkcs12(
    blob: bytes,
    password: str | None,
    *,
    cert_reqs: int = ssl.CERT_NONE,
    ca_certs: Path | str | None = None,
    source: str = "PKCS#12 data",
) -> tuple[ssl.SSLContext, LoadedCertificate]:
    """Decode a PKCS#12 blob and load it into a fresh server context."""
    from cryptography.hazmat.primitives.serialization import (
        BestAvailableEncryption,
        Encoding,
        PrivateFormat,
        pkcs12,
    )

    try:
        key, cert, chain = pkcs12.load_key_and_certificates(
            blob, password.encode("utf-8") if password else None
        )
    except ValueError as exc:
        raise TlsError(
            f"{source}: cannot be decoded ({exc}). Wrong passphrase, or not a PKCS#12 file?"
        ) from exc
    # Without a key, PKCS#12 has no "main" certificate either: everything comes
    # back in ``chain``. So test for the key first, that is the actual problem.
    if key is None:
        raise TlsError(
            f"{source}: contains no private key. The relay needs the key to serve TLS; "
            "export the certificate together with its key."
        )
    if cert is None:
        raise TlsError(f"{source}: contains no certificate")

    info = LoadedCertificate(
        subject=cert.subject.rfc4514_string(),
        not_after=cert.not_valid_after_utc.isoformat(timespec="seconds"),
        thumbprint=hashlib.sha1(cert.public_bytes(Encoding.DER)).hexdigest().upper(),
        chain_length=len(chain),
    )

    # The standard library can only load a key pair from files. Keep the window
    # small and the content useless on its own: PEM-encrypt the key under a
    # one-time passphrase that never leaves this process, write both files into
    # a fresh private directory, and remove it as soon as OpenSSL has read them.
    passphrase = secrets.token_urlsafe(32)
    key_pem = key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(passphrase.encode("ascii"))
    )
    chain_pem = cert.public_bytes(Encoding.PEM) + b"".join(
        extra.public_bytes(Encoding.PEM) for extra in chain
    )

    from uvicorn.config import create_ssl_context

    with tempfile.TemporaryDirectory(prefix="smtp-relay-tls-") as tmp:
        cert_path = _write_private(Path(tmp) / "chain.pem", chain_pem)
        key_path = _write_private(Path(tmp) / "key.pem", key_pem)
        try:
            context = create_ssl_context(
                str(cert_path),
                str(key_path),
                passphrase,
                ssl.PROTOCOL_TLS_SERVER,
                cert_reqs,
                str(ca_certs) if ca_certs is not None else None,
                None,
            )
        except (ssl.SSLError, OSError) as exc:
            raise TlsError(f"{source}: OpenSSL rejected the certificate or key: {exc}") from exc
    return context, info


def _write_private(path: Path, data: bytes) -> Path:
    """Create ``path`` readable by the owner only (where the OS honours the mode)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    return path


def export_from_windows_store(thumbprint: str) -> tuple[bytes, str]:
    """Return ``(pfx_blob, one_time_password)`` for the certificate with ``thumbprint``.

    The store is opened read-only; the certificate is copied into an in-memory
    store so that only it, not the whole machine store, is exported.
    """
    if not windows_store_available():
        raise TlsError(
            "api.ssl_cert_thumbprint reads the Windows certificate store and is only "
            f"available on Windows (this is {sys.platform}). Use api.ssl_pfxfile or "
            "api.ssl_certfile here."
        )
    try:
        import pywintypes
        import win32crypt
        import win32cryptcon as c
    except ImportError as exc:  # pragma: no cover - pywin32 is pinned for win32
        raise TlsError(f"api.ssl_cert_thumbprint needs pywin32: {exc}") from exc

    wanted = normalize_thumbprint(thumbprint)
    where = f"LocalMachine\\{WINDOWS_STORE_NAME}"
    try:
        store = win32crypt.CertOpenStore(
            c.CERT_STORE_PROV_SYSTEM,
            0,
            None,
            c.CERT_SYSTEM_STORE_LOCAL_MACHINE | c.CERT_STORE_READONLY_FLAG | c.CERT_STORE_OPEN_EXISTING_FLAG,
            WINDOWS_STORE_NAME,
        )
    except pywintypes.error as exc:
        raise TlsError(f"cannot open certificate store {where}: {_win_error(exc)}") from exc

    try:
        matches = [
            ctx
            for ctx in store.CertEnumCertificatesInStore()
            if hashlib.sha1(ctx.CertEncoded).hexdigest().upper() == wanted
        ]
        if not matches:
            raise TlsError(
                f"no certificate with thumbprint {wanted} in {where}. "
                "Import it with install.ps1 -PfxPath, or check the thumbprint in certlm.msc "
                "(Certificates - Local Computer > Personal > Certificates)."
            )
        password = secrets.token_urlsafe(32)
        memory = win32crypt.CertOpenStore(c.CERT_STORE_PROV_MEMORY, 0, None, 0, None)
        try:
            memory.CertAddCertificateContextToStore(matches[0], c.CERT_STORE_ADD_ALWAYS)
            # The REPORT_* flags turn "exported without its key" into an error
            # here, instead of an unusable context further down.
            blob = memory.PFXExportCertStoreEx(
                password,
                c.EXPORT_PRIVATE_KEYS | c.REPORT_NO_PRIVATE_KEY | c.REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY,
            )
        except pywintypes.error as exc:
            raise TlsError(
                f"certificate {wanted} in {where} cannot be exported with its private key "
                f"({_win_error(exc)}). The key must have been imported as exportable "
                "(install.ps1 -PfxPath does this, as does Import-PfxCertificate -Exportable) "
                "and the service account needs read access on it (certlm.msc > All Tasks > "
                "Manage Private Keys, or re-run install.ps1 -CertThumbprint). A key that "
                "must stay non-exportable can only be used by terminating TLS in IIS or "
                "HTTP.sys in front of the relay; see api.behind_tls_proxy."
            ) from exc
        finally:
            memory.CertCloseStore(0)
    finally:
        store.CertCloseStore(0)
    return bytes(blob), password


def _win_error(exc: Any) -> str:
    """``pywintypes.error`` is ``(winerror, funcname, message)``; render it readably."""
    args = getattr(exc, "args", ())
    if len(args) >= 3:
        return f"{args[1]}: {args[2]} (0x{args[0] & 0xFFFFFFFF:08X})"
    return str(exc)
