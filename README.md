# SMTP Relay

A small REST-to-SMTP relay. Clients `POST` JSON; the service validates it against a
schema, checks every recipient domain against an allowlist, and delivers the message
through a configurable mailhost over STARTTLS, implicit TLS, or plaintext.

Built with FastAPI + Pydantic. Delivery is synchronous: the response tells the caller
whether the mailhost actually accepted the message.

## Quickstart

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
cp config.example.toml config.toml      # then edit host/port/sender/allowlist
.venv/bin/python -m app --check         # dry run against the mailhost, nothing sent
.venv/bin/python -m app
```

For a reproducible install from the pinned set instead of resolving fresh:

```bash
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pip install --no-deps -e .
```

`requirements.txt` is the **runtime** set: every transitive dependency the
service imports, pinned to an exact version, for all targets. It is what the
payloads bundle and the image installs. `requirements-dev.txt` includes it and
adds the test suite's packages (`pytest`, `httpx`, `aiosmtpd`, ...), which never
ship, so the SBOM of a payload lists only what the service can execute. Regenerate the runtime set from a clean venv after touching
`[project.dependencies]`, so nothing from the dev set leaks in:

```bash
python3 -m venv /tmp/rt && /tmp/rt/bin/pip install . && /tmp/rt/bin/pip freeze --exclude smtp-relay
```

then restore the `pywin32; sys_platform == 'win32'` line, which a Linux freeze
cannot emit. `scripts/build_dist.py` verifies the closure per target and refuses
to build a payload with a missing transitive dependency.

### Dependencies

Four runtime packages — `fastapi`, `uvicorn`, `pydantic[email]`, `cryptography` —
plus dev extras. `cryptography` exists for the PKCS#12 and Windows-certificate-store
[certificate sources](#certificate-sources); it is pinned to the 46.x line because
47 and later publish no `win_arm64` wheel.

`uvicorn` is deliberately installed **without** its `[standard]` extra. That extra
pulls in `httptools`, `PyYAML`, `watchfiles`, `websockets`, `python-dotenv` and
`uvloop`, none of which this relay uses: config is TOML, there is no `--reload`, no
WebSocket endpoint and no `.env` file.

Excluding it matters on Windows. `PyYAML` publishes no `win_amd64` wheel for CPython
3.15 and no `win_arm64` wheel for 3.11, so it turns `pip install` into a source
build demanding **Visual Studio Build Tools for C++** — to compile a module the
relay never imports. Without the extra, `pydantic-core`, `pywin32`, `cffi` and
`cryptography` are the only compiled dependencies and all have complete wheels, so
**no C/C++ compiler is needed on any of win_amd64/win_arm64 × CPython 3.11–3.15**. uvicorn then serves
over its pure-Python `h11` protocol instead of `httptools`, which is irrelevant at
mail-relay volumes (verified live with 200 KB and 2 MB request bodies).

`tests/test_windows_deployment.py` fails if any of those six packages reappears in
`requirements.txt`, if a test-only package does, or if `pyproject.toml`
re-declares `uvicorn[standard]`.

The API docs are served at <http://127.0.0.1:8000/docs>, the raw OpenAPI schema at
`/openapi.json`, and a liveness probe at `/health`.

To run without a real mailhost, point `config.toml` at a local sink:

```bash
.venv/bin/python -m aiosmtpd -n -l localhost:2525
```

## API

### `POST /mail`

```json
{
  "recipients": ["alice@example.com", "bob@example.org"],
  "subject": "Deploy finished",
  "body": "Build 1234 deployed to production successfully."
}
```

All three fields are required. `recipients` must be non-empty, addresses must be
valid, and `subject`/`body` must be non-empty plain UTF-8 text. Unknown fields are
rejected — the schema is strict, so a typo like `reciever` fails loudly instead of
being silently dropped.

`200 OK`:

```json
{
  "status": "sent",
  "message_id": "<179316759497.15739.1561309392218656981@localhost.localdomain>",
  "recipients": ["alice@example.com", "bob@example.org"]
}
```

```bash
curl -X POST http://127.0.0.1:8000/mail \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -d '{"recipients":["alice@example.com"],"subject":"Hi","body":"Hello there."}'
```

### Status codes

| Code | Meaning | `code` field |
|------|---------|--------------|
| `200` | Delivered; the mailhost accepted the message | — |
| `400` | Recipient domain not in the allowlist | `domain_not_allowed` (plus `rejected_domains`) |
| `400` | Subject or body looks like a base64 blob | `base64_not_allowed` |
| `400` | More recipients than `api.max_recipients` | `too_many_recipients` |
| `401` | Missing or wrong bearer token (only when `api.token` is set) | — |
| `422` | Body does not match the schema | — |
| `502` | Mailhost refused the message or was unreachable | — |

`422` means *malformed*, `400` means *well-formed but not permitted*. Keeping them
apart makes client-side error handling unambiguous.

A request is atomic: if any single recipient domain is not allowlisted, the whole
POST is rejected and **nothing** is sent. There is no partial delivery.

Duplicate recipients are deduplicated case-insensitively, so one address is never
delivered to twice.

## Configuration

`config.toml`, overridable per-value by environment variables. Env always wins, so
secrets never need to be written to disk. See `config.example.toml` for the
annotated template.

| Environment variable | Config key |
|---|---|
| `RELAY_CONFIG` | path to the config file (default `./config.toml`) |
| `RELAY_API_HOST` | `api.host` |
| `RELAY_API_PORT` | `api.port` |
| `RELAY_API_TOKEN` | `api.token` |
| `RELAY_MAX_RECIPIENTS` | `api.max_recipients` |
| `RELAY_API_SSL_CERTFILE` | `api.ssl_certfile` |
| `RELAY_API_SSL_KEYFILE` | `api.ssl_keyfile` |
| `RELAY_API_SSL_KEYFILE_PASSWORD` | `api.ssl_keyfile_password` |
| `RELAY_API_SSL_CA_CERTS` | `api.ssl_ca_certs` |
| `RELAY_API_SSL_CERT_REQS` | `api.ssl_cert_reqs` |
| `RELAY_API_SSL_PFXFILE` | `api.ssl_pfxfile` |
| `RELAY_API_SSL_PFX_PASSWORD` | `api.ssl_pfx_password` |
| `RELAY_API_SSL_CERT_THUMBPRINT` | `api.ssl_cert_thumbprint` (Windows only) |
| `RELAY_API_BEHIND_TLS_PROXY` | `api.behind_tls_proxy` |
| `RELAY_SMTP_HOST` | `smtp.host` |
| `RELAY_SMTP_PORT` | `smtp.port` |
| `RELAY_SMTP_SECURITY` | `smtp.security` |
| `RELAY_SMTP_USERNAME` | `smtp.username` |
| `RELAY_SMTP_PASSWORD` | `smtp.password` |
| `RELAY_SMTP_TIMEOUT` | `smtp.timeout` |
| `RELAY_SMTP_CA_FILE` | `smtp.ca_file` |
| `RELAY_SENDER` | `policy.sender` |
| `RELAY_SENDER_NAME` | `policy.sender_name` |
| `RELAY_ALLOWED_DOMAINS` | `policy.allowed_domains` (comma-separated) |
| `RELAY_ALLOW_SUBDOMAINS` | `policy.allow_subdomains` |
| `RELAY_REJECT_BASE64` | `policy.reject_base64` |

Unknown keys and sections are rejected at startup, so a typo fails immediately
rather than being ignored. Bad configuration exits with code 2 and a message naming
the offending field. A password without a username is one such error: the relay
only authenticates when `smtp.username` is set, so a lone `smtp.password` would be
ignored silently and the mailhost would refuse every message.

### Checking the configuration

Validation catches what the values alone reveal. `--check` tests the rest against
the real world, then exits without serving:

```bash
.venv/bin/python -m app --check              # --no-smtp: skip the mailhost
```

```
smtp-relay 0.3.3 configuration check
  ok    config        /etc/smtp-relay/config.toml (overridden from the environment: RELAY_SMTP_PASSWORD)
  ok    api           https://0.0.0.0:8000, reachable from the network, TLS served by this process, clients authenticate with client certificate (mutual TLS)
  ok    api.tls       PKCS#12 file /etc/smtp-relay/relay.pfx: subject CN=relay.example.com, thumbprint 52B4..., valid for 364 more days (until 2027-10-29T09:12:00+00:00); client certificates required, 1 CA certificate(s) loaded from /etc/smtp-relay/client-ca.pem
  ok    policy        sender relay@example.com; recipients allowed at example.com, example.org
  ok    smtp.dns      smtp.example.com resolves to 192.0.2.25
  ok    smtp.session  connected to smtp.example.com:587 over STARTTLS, TLSv1.3 TLS_AES_256_GCM_SHA384, server certificate verified; offers AUTH PLAIN LOGIN, SIZE 28311552
  ok    smtp.auth     authenticated as relay@example.com
  ok    smtp.sender   smtp.example.com:587 accepts MAIL FROM:<relay@example.com>
Result: 8 ok, 0 warning(s), 0 failed
```

The probes, in order: where the configuration came from and which `RELAY_*`
variables override it; what the API binds and how clients must authenticate;
the API certificate, loaded exactly as the server would load it (PEM pair,
PKCS#12 file or Windows store), with its expiry (warning under 30 days, failure
once expired) and the client CA bundle for mutual TLS; the sender and allowlist;
then one SMTP session with the mailhost: DNS, connect, STARTTLS or implicit
TLS with certificate verification, `AUTH` when credentials are set, `MAIL FROM`
with the configured sender, `RSET`, `QUIT`. **Nothing is sent.** A warning is
raised when the mailhost advertises `AUTH` but no username is configured, when
it advertises `STARTTLS` but the session is cleartext, and when the sender is
outside the authenticated account's domain, which iCloud, Gmail and Microsoft
365 reject at `MAIL FROM`. A port/security mismatch is named as such rather than
reported as a bare handshake error. Secrets never appear in the output.

Exit status: 0 when nothing failed (warnings included), 1 when a probe failed,
2 when the configuration does not load at all. Run it as the account the
service uses, so file permissions and certificate-key ACLs are part of the test:

```bash
# Linux payload
sudo -u smtp-relay /opt/smtp-relay/python/bin/python3 -m app --check --config /etc/smtp-relay/config.toml
# container (ENTRYPOINT is python -m app)
docker run --rm -v ./config.toml:/etc/smtp-relay/config.toml:ro --env-file .env <image> --check
```

```powershell
# Windows payload, elevated (reads %ProgramData%\SmtpRelay\config.toml)
& 'C:\Program Files\SmtpRelay\python\python.exe' -m app --check
```

On Windows the elevated run proves the certificate and the mailhost; whether
`NT SERVICE\SmtpRelay` itself may read the private key is what the installer's
ACL step establishes, and a failure there shows up in the Application event log
at service start.

### SMTP TLS (outbound, to the mailhost)

`smtp.security` accepts `starttls`, `tls`, or `none`. When omitted it is inferred
from the port:

| Port | Mode | Transport |
|---|---|---|
| `465` | `tls` | Implicit TLS (`SMTP_SSL`) — encrypted from the first byte |
| `587` | `starttls` | Connect plaintext, `EHLO`, `STARTTLS`, re-`EHLO` |
| `25` | `none` | Plaintext |
| anything else | `starttls` | Fail safe towards encryption |

An explicit `security` always overrides the inference.

Server certificates **are** validated against the system trust store; there is no
option to disable verification. For an internal PKI, point `smtp.ca_file` (or
`RELAY_SMTP_CA_FILE`) at your CA bundle. An untrusted certificate produces `502`
with `CERTIFICATE_VERIFY_FAILED` and nothing is delivered.

`smtp.local_hostname` sets the name sent in `EHLO`/`HELO`; it defaults to the
local FQDN.

### API TLS (inbound, from clients)

The two TLS concerns are independent: `smtp.*` protects the leg **to** your
mailhost, `api.ssl_*` protects the leg **from** your clients.

TLS on the API is **off by default**, and normally should stay off: `api.host`
binds `127.0.0.1`, so requests never leave the machine and encryption buys
nothing. Enable it only if remote clients will connect to this process directly
rather than through a reverse proxy.

Setting a certificate source — `api.ssl_certfile`, `api.ssl_pfxfile` or, on
Windows, `api.ssl_cert_thumbprint` (see [Certificate sources](#certificate-sources))
— switches the endpoint to HTTPS; plaintext HTTP is then refused on that port, not
served alongside it. The PEM form:

```toml
[api]
host = "0.0.0.0"
ssl_certfile = "/etc/ssl/certs/smtp-relay.crt"
ssl_keyfile = "/etc/ssl/private/smtp-relay.key"
```

| Key | Purpose |
|---|---|
| `api.ssl_certfile` | Server certificate chain in PEM. Its presence enables TLS. |
| `api.ssl_keyfile` | Private key in PEM. Omit if the key is appended to the cert file. |
| `api.ssl_keyfile_password` | Passphrase for an encrypted key. Prefer `RELAY_API_SSL_KEYFILE_PASSWORD`. |
| `api.ssl_pfxfile` | A PKCS#12 file instead of the PEM pair. Its presence enables TLS. |
| `api.ssl_pfx_password` | Its passphrase. Prefer `RELAY_API_SSL_PFX_PASSWORD`. |
| `api.ssl_cert_thumbprint` | Windows only: a certificate in the machine store instead of any file. Its presence enables TLS. |
| `api.ssl_ca_certs` | Client CA bundle, for mutual TLS. Must be paired with `ssl_cert_reqs`. |
| `api.ssl_cert_reqs` | `none` \| `optional` \| `required` — mapped to `ssl.VerifyMode` for uvicorn. `optional`/`required` must be paired with `ssl_ca_certs`. |

Two things are rejected at startup rather than failing obscurely later:

- More than one certificate source, or a dependent key without its source:
  `ssl_keyfile` / `ssl_keyfile_password` need `ssl_certfile`, `ssl_pfx_password`
  needs `ssl_pfxfile`, and `ssl_ca_certs` / `ssl_cert_reqs` need some source —
  otherwise TLS would not be enabled at all.
- Setting `ssl_ca_certs` and `ssl_cert_reqs` **without each other.** uvicorn sets
  `verify_mode` unconditionally but loads the CA bundle only when `ssl_ca_certs` is
  given, so each alone is broken in a different way: a CA bundle with no
  `ssl_cert_reqs` leaves verification at `CERT_NONE` and never requests a client
  certificate (mTLS silently inert), while `ssl_cert_reqs = "required"` with no CA
  bundle verifies clients against an empty trust store and rejects everyone,
  including valid clients.

uvicorn negotiates with its defaults (TLS 1.2+, `PROTOCOL_TLS_SERVER`); `ssl_version`
and `ssl_ciphers` are deliberately not exposed.

Mutual TLS authenticates clients by certificate instead of, or as well as, the
bearer token:

```toml
[api]
ssl_certfile = "/etc/ssl/certs/smtp-relay.crt"
ssl_keyfile = "/etc/ssl/private/smtp-relay.key"
ssl_ca_certs = "/etc/ssl/certs/client-ca.pem"
ssl_cert_reqs = "required"
```

Clients then present a certificate chaining to `client-ca.pem`; anything else —
no certificate, or one signed by a different CA — is refused during the TLS
handshake, before any HTTP request is parsed.

### Certificate sources

Exactly one of three sources provides the server certificate and key:

| Source | Key | Where the key lives | Passphrase at runtime |
|---|---|---|---|
| PEM files | `ssl_certfile` (+ `ssl_keyfile`) | two files you manage | only if the key file is encrypted |
| PKCS#12 file | `ssl_pfxfile` | one `.pfx`/`.p12` file you manage | `ssl_pfx_password`, usually via the environment |
| Windows certificate store | `ssl_cert_thumbprint` | `Cert:\LocalMachine\My`, DPAPI-protected, ACL'd to the service account | none |

Python's TLS is OpenSSL, which reads PEM files natively but can neither parse
PKCS#12 nor sign with a Windows CNG key handle. The other two sources are
therefore decoded by `app/tls.py` with the `cryptography` package and loaded
through the same file-based OpenSSL API as the PEM pair. For a few milliseconds
at startup the key exists in a private temporary directory, PEM-encrypted under
a random one-time passphrase that never leaves the process; the directory is
removed as soon as the context is built. Decoding happens in the main thread
before uvicorn starts, so a wrong passphrase or a missing key is reported as a
configuration error (exit code 2, or an Event Log entry for the service), not
as a traceback from a worker thread. The log also records subject, thumbprint
and expiry of the certificate in use.

**PKCS#12** works on every platform and in the container, and is what Windows
CAs and most admins hand out, so no `openssl pkcs12` conversion is needed:

```toml
[api]
host = "0.0.0.0"
ssl_pfxfile = "/etc/ssl/private/smtp-relay.pfx"   # passphrase in RELAY_API_SSL_PFX_PASSWORD
```

**The Windows certificate store** is the natural home for a certificate on a
Windows host: no key file, no passphrase in `config.toml` or the environment,
renewal by re-import in `certlm.msc`, central visibility. `install.ps1` sets it
up end to end:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -PfxPath C:\certs\relay.pfx -Start
# or, for a certificate already in the store:
powershell -ExecutionPolicy Bypass -File .\install.ps1 -CertThumbprint 0123...CDEF -Start
```

With `-PfxPath` it asks for the passphrase once (never stored), imports the file
into `Cert:\LocalMachine\My` with an **exportable** key, grants the service
account read access on the key file — the same thing *Manage Private Keys* does
in `certlm.msc` — and writes `api.ssl_cert_thumbprint` into `config.toml`. The
PFX file can be deleted afterwards. With `-CertThumbprint` it does the grant and
the config edit for an existing certificate, after checking that the key is
exportable. Both are safe to repeat with `-Force`.

At every start the service exports the certificate with its key through
CryptoAPI (`PFXExportCertStoreEx`) into memory and loads it as above. That is
why the key **must be exportable**, and why the honest description of this mode
is "no key file to manage", not "non-exportable key": a local administrator can
export it, just as they can read a key file. If the key must stay
non-exportable, terminate TLS in IIS (with Application Request Routing) or in
HTTP.sys in front of the relay, bind the store certificate there, forward to
`127.0.0.1` over HTTP, and set [`api.behind_tls_proxy`](#behind-a-tls-terminating-reverse-proxy).
A renewed certificate is picked up at the next service restart.

### Behind a TLS-terminating reverse proxy

If a reverse proxy terminates TLS, leave `api.ssl_*` unset and have the proxy
forward to the relay. On the same host, keep `api.host = "127.0.0.1"` and nothing
more is needed.

When the proxy is *not* on the same host - a container behind an ingress, or a
proxy on a private network - the relay has to bind `0.0.0.0`, which trips the
network-exposure rule. `api.behind_tls_proxy = true` is the deliberate opt-out for
exactly that case:

```toml
[api]
host = "0.0.0.0"
behind_tls_proxy = true
# token still required - see below
```

It waives **only the TLS half** of the rule. The proxy keeps the token off the
public wire, but it does not stop anyone who can reach the relay's port from
submitting mail, so `api.token` (or required mTLS) is still demanded and nothing
waives that. Setting `behind_tls_proxy` together with any certificate source is
rejected: TLS is terminated in exactly one place, and both set means one of them is
misunderstood. The flag is only honest on a private network segment; do not use
it to expose cleartext across a network you do not control.

### Recipient allowlist

```toml
[policy]
allowed_domains = ["example.com", "example.org"]
allow_subdomains = false
```

Matching is on the lowercased domain after the final `@`. By default it is exact:
`example.com` permits `alice@example.com` but **not** `alice@mail.example.com`, and
never `alice@notexample.com`. Setting `allow_subdomains = true` also permits
subdomains, matched on a `.` boundary so the `notexample.com` case stays rejected.

Entries are normalised (whitespace trimmed, lowercased, a leading `@` and trailing
`.` removed). An empty allowlist rejects everything — fail-closed, and a warning is
logged at startup.

### The "no base64" rule

The API contract is plain UTF-8 text: clients send readable strings, not encoded
payloads. With `policy.reject_base64 = true` (the default) the relay also actively
rejects a `subject` or `body` that looks like a base64 blob, returning
`400 base64_not_allowed`.

The check is a heuristic. It flags a field when it is at least 24 characters long,
its length is a multiple of 4, it uses only the base64 alphabet with valid padding,
and it decodes cleanly. Ordinary prose never matches, because spaces and punctuation
fall outside the alphabet. The known false positive is a long token drawn purely
from that alphabet — for example a 64-character hex SHA-256 digest in a body. If you
need to relay such content, set `reject_base64 = false`.

**Do not confuse this with MIME wire encoding.** On the wire, Python's `email`
library applies standard `Content-Transfer-Encoding` (`7bit`, `8bit`, or `base64`) to
the MIME part, and RFC 2047-encodes non-ASCII subjects
(`Subject: =?utf-8?q?=C3=84rger?= mit Umlauten`). That is mandatory transport
encoding applied by every mail client, and is unrelated to the API-level rule above.

## Running the tests

```bash
.venv/bin/python -m pytest          # 195 tests
```

Six layers:

- **unit** (`test_policy.py`, `test_config.py`, `test_logging_setup.py`) —
  allowlist matching, the base64 heuristic, TOML loading, env overrides, and the
  config search paths.
- **security policy** (`test_network_exposure.py`) — a non-loopback `api.host`
  requires both TLS and client authentication, and `ssl_cert_reqs = "optional"`
  does not count as the latter.
- **mocked SMTP** (`test_relay.py`) — negotiation order for each security mode,
  error translation, socket cleanup on failure.
- **integration** (`test_integration.py`) — the whole stack against a real
  `aiosmtpd` server on an ephemeral port, asserting the message actually arrives
  with the right envelope and headers.
- **API TLS / mTLS** (`test_api_tls.py`) — the ssl config plumbing, plus real
  uvicorn servers on ephemeral ports. Mints a full PKI with `openssl` (CA, server
  cert, client cert, and a *rogue* CA with its own client cert) and asserts that a
  trusted client certificate is accepted while a missing or rogue-CA one is
  refused during the handshake. Skips cleanly where `openssl` is unavailable.
- **packaging** (`test_windows_deployment.py`, `test_build_dist.py`) — the service
  module compiles, `SERVICE_CLASS_STRING` resolves to a real importable module,
  every platform-specific pin carries its marker, no `uvicorn[standard]` package
  can reappear, and the payload staging allowlist cannot leak `config.toml`.

Note that the test CA carries `keyUsage=critical,keyCertSign,cRLSign`. Python 3.13
turned on `VERIFY_X509_STRICT` in `ssl.create_default_context()`, so a CA that signs
other certificates without that extension is rejected — `openssl req -x509` does not
add it by default.

This is a **client-side** constraint. It affects a client verifying the server's
chain (here, the test client), not uvicorn, which builds a bare
`ssl.SSLContext(PROTOCOL_TLS_SERVER)` without strict mode. Server-side verification
of client certificates therefore tolerates a CA that lacks the extension; the test
client verifying the server would not. Confirmed empirically: an earlier run with a
non-compliant CA still enforced mTLS correctly, refusing both a missing and a
rogue-CA client certificate.

Two of these are *anti-mock* guards rather than behaviour tests.
`test_relay_calls_match_the_real_smtplib_signatures` binds every argument the relay
passes against the real `smtplib` signatures, and
`test_ssl_kwargs_bind_to_the_real_uvicorn_config` does the same for the uvicorn TLS
arguments. They exist because a fake object can only encode what we assume a library
looks like; see History below.

## Running in Docker

Published images live in this Gitea's container registry, one multi-arch
manifest per release covering `linux/amd64` and `linux/arm64`:

```bash
docker pull gitea.softbase.tech/beat/smtprelay:v0.2.2
```

Image names must be lowercase, hence `smtprelay` for the `SmtpRelay` repository.
Tags carry the `v` like the git tags. To build it yourself, nothing in it is
architecture-specific - the only compiled dependency is `pydantic-core`, which has
manylinux wheels for both - so a single multi-arch build covers both targets:

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  --build-arg VERSION=$(python -c 'import tomllib;print(tomllib.load(open("pyproject.toml","rb"))["project"]["version"])') \
  -t smtp-relay:0.2.0 .
```

What the image does, and deliberately does not do:

- Installs the project into a venv from `python:3.15-slim`, with `requirements.txt`
  used as a constraints file so the runtime set is pinned to the tested versions
  while the test-only packages stay out.
- Runs as the unprivileged user `relay` (uid 10001), logs to stdout, and reads
  configuration from `/etc/smtp-relay/config.toml` and/or `RELAY_*` variables.
  `config.toml` from the checkout is excluded by both the `COPY` allowlist and
  `.dockerignore`, so a local token or password cannot end up in a layer.
- Sets `RELAY_API_HOST=0.0.0.0`, because a container bound to loopback is
  unreachable. That is the **only** exposure-related default. The TLS/auth
  decision stays with you: without either a mounted certificate or
  `RELAY_API_BEHIND_TLS_PROXY=true`, plus `RELAY_API_TOKEN`, the container exits
  with code 2 and the same message the service would print on Windows.
- Declares a `HEALTHCHECK` that calls `GET /health` through the configured scheme
  and port. Docker honours it; Podman ignores it unless built with
  `--format docker`. Disable it under `ssl_cert_reqs = "required"`, because the
  probe has no client certificate.

The usual deployment, behind a reverse proxy that terminates TLS:

```bash
cp config.example.toml config.toml   # smtp.*, policy.*; leave api.host alone
RELAY_API_TOKEN=... RELAY_SMTP_PASSWORD=... docker compose run --rm smtp-relay --check
RELAY_API_TOKEN=... RELAY_SMTP_PASSWORD=... docker compose up -d
curl -s http://127.0.0.1:8000/health
```

`compose.yaml` mounts `./config.toml` read-only at `/etc/smtp-relay/config.toml`,
publishes the port on loopback only (so just the local proxy can reach it), and
runs the container with a read-only root filesystem, all capabilities dropped and
`no-new-privileges`. For an ingress on a private network, drop the `127.0.0.1:`
prefix from the port mapping. To have the relay serve TLS itself instead, mount
the certificate and key, set `RELAY_API_SSL_CERTFILE` / `RELAY_API_SSL_KEYFILE`,
and leave `RELAY_API_BEHIND_TLS_PROXY` unset.

There is no native Linux payload or systemd unit; the image is the Linux
deployment. If a host cannot run containers, `python -m app` under systemd with
`/etc/smtp-relay/config.toml` is the fallback, and the network-exposure rule
applies identically there.

## Deploying on Linux (systemd)

The Linux payload is the same idea as the Windows one: a bundled CPython, every
dependency as a wheel, the application, and an installer that needs **no
internet, no compiler and no system Python**. systemd is required; on anything
else, use the container image.

```bash
.venv/bin/python scripts/build_dist.py --platform linux_x86_64 --zip    # -> .tar.gz
.venv/bin/python scripts/build_dist.py --platform linux_aarch64 --zip
```

On the target:

```bash
tar xzf SmtpRelay-0.3.0-linux_x86_64-cp315.tar.gz
cd SmtpRelay-0.3.0-linux_x86_64-cp315
sudo ./install.sh            # add --start to start immediately
sudoedit /etc/smtp-relay/config.toml
sudo -u smtp-relay /opt/smtp-relay/python/bin/python3 -m app --check --config /etc/smtp-relay/config.toml
sudo systemctl start smtp-relay
journalctl -u smtp-relay -f
```

`install.sh` does, in order:

1. Validates the payload against `MANIFEST.json` **with the bundled interpreter**,
   which also proves the payload matches the machine's architecture; a wrong
   payload fails here, before anything is written.
2. Creates the system account `smtp-relay`: no home, no shell, no password.
3. Copies the runtime and application to `/opt/smtp-relay` and installs the
   pinned dependencies from the bundled wheels, offline. The Windows-only pins
   in `requirements.txt` are skipped by their markers.
4. Seeds `/etc/smtp-relay/config.toml` from the template, never overwriting an
   existing one, owned `root:smtp-relay` mode `0640` inside a `0750` directory,
   so root can edit it and only the service can read it.
5. Renders the unit from `smtp-relay.service`, reloads systemd, enables the
   service, and runs `systemd-analyze verify` on it.

`--force` upgrades in place: the service is stopped, `/opt/smtp-relay` is
replaced, `/etc/smtp-relay` is preserved. `--install-dir`, `--config-dir`,
`--service-name` and `--user` override the defaults. `uninstall.sh` reverses it
and keeps the configuration unless `--remove-config` is passed.

The unit is the Linux equivalent of the Windows least-privilege setup, done the
systemd way. The process runs as `smtp-relay` with an empty capability set,
`ProtectSystem=strict` (the whole filesystem read-only except what systemd
carves out), no home directories, private `/tmp` and `/dev`, no new namespaces
or personalities, the `@system-service` syscall allowlist, and
`RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`. `RELAY_CONFIG` is set
explicitly so the service never picks up a stray `config.toml` from a working
directory. A configuration error exits 2 and is excluded from `Restart=on-failure`
because retrying it cannot help. To bind a port below 1024 directly, add a
drop-in with `AmbientCapabilities=CAP_NET_BIND_SERVICE` rather than editing the
unit.

The sandboxing needs `CAP_SYS_ADMIN` inside whatever systemd is running in,
which a VM or bare-metal host always has and an unprivileged LXC or Docker
container may not. In the latter the service fails immediately with
`status=217/USER` and "Failed to keep CAP_SYS_ADMIN" in the journal; use the
container image there instead of nesting systemd.

Logs go to stderr and therefore to the journal; there is no file logging. The
network-exposure rule applies exactly as everywhere else: behind a local reverse
proxy keep `api.host = "127.0.0.1"`, behind one on another host set
`api.behind_tls_proxy = true` plus a token.

The runtime comes from [python-build-standalone](https://github.com/astral-sh/python-build-standalone),
the builds `uv` installs: the `install_only_stripped` glibc flavour, verified
against the release's `SHA256SUMS` at build time, with the release tag recorded
in `MANIFEST.json`. Set `PBS_RELEASE=<tag>` to pin a release instead of using the
latest.

An end-to-end test boots systemd in a Debian container, installs, checks
`/health`, upgrades in place and uninstalls:

```bash
scripts/test_linux_installer.sh dist/SmtpRelay-0.3.0-linux_x86_64-cp315
```

## Deploying as a Windows service

The relay runs as a **native Windows service** through pywin32 — no external
wrapper binary.

For production, use the [offline payload](#building-an-offline-payload), which
bundles its own CPython. The manual route below is for development and testing; it
creates a venv from whatever interpreter you point it at, and a venv's
`pyvenv.cfg` records `home=` pointing back into that interpreter. If that is the
Python Install Manager's per-user runtime under `%LOCALAPPDATA%`, the service ends
up depending on one user's profile.

```powershell
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\pip install --no-deps -e .
```

Note that under the Python Install Manager, `python.exe` may not resolve at all —
it is an app-execution alias in `%LOCALAPPDATA%\Microsoft\WindowsApps`, which is
per-user and often invisible in an elevated console. `py -3.15` does resolve, so
create the venv with that:

```powershell
py -3.15 -m venv .venv
py -3.15 -c "import sysconfig; print(sysconfig.get_platform())"   # win-amd64 or win-arm64
```

Before touching the service at all, the real smoke test is a plain foreground run,
which involves no Service Control Manager at all:

```powershell
.venv\Scripts\python -m app --check
.venv\Scripts\python -m app
Invoke-RestMethod http://127.0.0.1:8000/health
```

Then, **from an elevated prompt**, using the venv's own interpreter (not the
system Python):

```powershell
.venv\Scripts\python -m app.windows_service install
.venv\Scripts\python -m app.windows_service debug     # optional: run in a console
.venv\Scripts\python -m app.windows_service start
```

**`install` must come before `debug`.** pywin32 implements `debug` by locating the
already-registered service's `pythonservice.exe` via `LocateSpecificServiceExe`, so
running it against an unregistered service prints `The service does not appear to
be installed.` and exits 1. That is pywin32's behaviour, not a fault in this code.

`debug` is still worth running before `start`: it executes the same `SvcDoRun` in a
console and logs to stderr, surfacing errors the SCM would otherwise report only as
"the service did not start". Stop it with Ctrl+C.

Other subcommands: `stop`, `restart`, `remove`.

The service registers as `SmtpRelay`, displayed as "SMTP Relay".

### Building an offline payload

Instead of cloning and installing on the target, build a fully self-contained
payload that installs with **no internet access, no C/C++ compiler, and no
pre-existing Python**:

```bash
.venv/bin/python scripts/build_dist.py                        # win_arm64, CPython 3.15.2
.venv/bin/python scripts/build_dist.py --platform win_amd64
.venv/bin/python scripts/build_dist.py --runtime-version 3.15.1 --zip
.venv/bin/python scripts/build_dist.py --platform linux_x86_64 --zip   # see "Deploying on Linux"
```

This runs from any host OS: both the wheels and the CPython runtime are fetched
for the *target* platform (`win_amd64`, `win_arm64`, `linux_x86_64`,
`linux_aarch64`). Because `--only-binary=:all:` is used, a package with no
matching wheel fails the build **here** rather than demanding a compiler on the
target. Markers are evaluated for a synthetic target environment first, since pip
otherwise evaluates them against the build host and mis-resolves. `--zip`
produces a `.zip` for Windows targets and a `.tar.gz` for Linux ones, the latter
because it preserves executable bits.

The wheel tag is **derived** from `--runtime-version` rather than specified
separately, so the wheels cannot disagree with the bundled interpreter.

**Each build bumps the patch version** — `0.1.0` → `0.1.1` — in both
`pyproject.toml` and `app/__init__.py`, so no two payloads ever share a filename.
That matters more than it sounds: while the version stayed fixed, five materially
different builds were all named `SmtpRelay-0.1.0-win_arm64-cp315.zip` and only a
sha256 told them apart, which is how a stale download nearly got installed as the
current one. The bump is written to the source tree only *after* the payload is
built successfully, and into the staged copy beforehand so the payload's
`pyproject.toml`, `app.__version__` (served at `/health`), `MANIFEST.json` and
directory name all agree. Commit the bump with your source changes.

Use `--version X.Y.Z` to set one explicitly, or `--no-bump` to rebuild without
incrementing (the payload name will then repeat and be overwritten).

The result is `dist/SmtpRelay-<version>-<platform>-<tag>/`:

```
python/                full CPython runtime for the target architecture
app/                   application source
wheels/                every dependency as a target-platform wheel
install.ps1            offline installer (elevated)
uninstall.ps1
config.example.toml    template - the developer's config.toml is never staged
pyproject.toml, requirements.txt, README.md
MANIFEST.json          version, runtime_version, target, per-file sha256, payload digest
```

`dist/` is a build artifact and is gitignored. Staging is an allowlist, so
`config.toml` (which may hold a real SMTP password) cannot leak into a payload;
`tests/test_build_dist.py` asserts that.

Copy the directory to the target and, from an **elevated** prompt:

```powershell
cd C:\Temp\SmtpRelay-0.1.1-win_arm64-cp315
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Start
```

`install.ps1` copies `python/` into `C:\Program Files\SmtpRelay\python`,
bootstraps pip from the wheel inside that runtime via `ensurepip` (falling back to
running pip directly out of the bundled wheel), installs everything with
`--no-index --find-links wheels`, seeds `C:\ProgramData\SmtpRelay\config.toml`
from the template **without overwriting an existing one**, registers the service
under a virtual account with least-privilege ACLs, and adds an Apps & features
entry.

There is **no venv**: the bundled runtime directory *is* the environment. That
matters for a service, because a venv's `pyvenv.cfg` records `home=` pointing at
whatever interpreter created it — and if that is the Python Install Manager's
per-user runtime under `%LOCALAPPDATA%`, a service running under its own account
ends up depending on one user's profile.

Switches: `-InstallDir`, `-ConfigDir`, `-ServiceName`, `-ServiceAccount`,
`-ApiPort`, `-OpenFirewall`, `-Start`, `-Force`, and for the API certificate
`-PfxPath` (+ optional `-PfxPassword` SecureString) or `-CertThumbprint` — see
[Certificate sources](#certificate-sources). `-PfxPassword` can only be passed
when the script runs in the current session (`.\install.ps1 ...` after
`Set-ExecutionPolicy -Scope Process Bypass`); through `powershell -File` every
argument arrives as text, so leave it out there and answer the prompt instead. `uninstall.ps1` leaves the
certificate in the store; remove it in `certlm.msc` if it is no longer wanted.

`uninstall.ps1` stops and removes the service, deletes the install directory and
the Apps & features entry, and **preserves** `C:\ProgramData\SmtpRelay` unless you
pass `-RemoveConfig`.

Two things to know about bundling the runtime:

- **The payload must match the machine's architecture**, not just its Python
  version — there is now no host interpreter to fall back on. `build_dist.py`
  fetches `pythonarm64` for `win_arm64` and `python` for `win_amd64`; verify with
  `sysconfig.get_platform()`. `install.ps1` runs the bundled interpreter early and
  reports a clear error if the architecture is wrong.
- **The runtime receives no automatic security updates.** Patching CPython means
  rebuilding the payload with a newer `--runtime-version` and redeploying.

The nuget runtime is used rather than python.org's *embeddable* zip on purpose:
the embeddable zip ships a `._pth` file with `import site` commented out, which
stops `.pth` processing — and pywin32 depends on `pywin32.pth` to put `win32` and
`win32\lib` on `sys.path` and to run `pywin32_bootstrap`. With it, `import
win32service` fails and the service cannot start. `build_dist.py` refuses a runtime
containing a `._pth` file, and asserts `ensurepip` is present.

### Releasing

Payloads are **not** committed; each is about 32 MB and git would keep every one
forever. A release is a tag plus attachments on the Gitea release page, and the
container image goes to this Gitea's package registry.

The tag is the source of truth. `vX.Y.Z` must match `version` in
`pyproject.toml`, otherwise the pipeline stops before downloading anything:

```bash
.venv/bin/python scripts/build_dist.py --version 0.3.0 --no-bump --platform win_arm64 --zip   # sets the version
git commit -am "Release 0.3.0" && git tag -a --cleanup=verbatim v0.3.0 -F notes.md && git push origin main v0.3.0
```

`.gitea/workflows/release.yaml` then runs the tests, builds the two Windows and
two Linux payloads with the installer checks enabled, writes `SHA256SUMS`, creates or updates
the release with the assets attached, and builds and pushes the multi-arch image
as `gitea.softbase.tech/<owner>/smtprelay:vX.Y.Z` and `:latest`. Release notes
are the annotated tag's message; a lightweight tag falls back to the commit
subjects since the previous tag. Tag with `--cleanup=verbatim`, otherwise git
strips every line starting with `#`, which is every Markdown heading. Every step is idempotent, so re-running a failed
job converges rather than producing duplicate assets.

Two runner requirements: a runner with the `ubuntu-latest` label must be
registered for the repository, the owner, or the instance, and the `image` job
needs that runner to be able to run `docker` with privileges (buildx and QEMU
for the arm64 half). `.gitea/runner/compose.yaml` is a ready-to-run runner with
exactly that setup; its header has the three commands, and it works with Docker
or rootless Podman. Registering it needs a registration token from the
repository's Actions settings, which is deliberately a human step. The
automatic `GITHUB_TOKEN` can create releases and upload assets, but it cannot
log in to this Gitea's container registry, so the `image` job needs a
`REGISTRY_TOKEN` repository secret: a personal access token with only the
`write:package` scope. The secret is used for the registry login alone;
releases and their assets are still published with `GITHUB_TOKEN`. The
project's own runner lives rootful inside a
`podman machine` VM; the compose header shows that invocation too.
Until a runner exists, releases are published by hand as described below, and
the workflow's first run can be verified with a pre-release tag such as
`v0.3.2-rc.1`, which the publisher marks as a pre-release automatically.

The same publisher works by hand, which is how 0.2.0 was released:

```bash
.venv/bin/python scripts/build_dist.py --no-bump --platform win_amd64 --zip
.venv/bin/python scripts/build_dist.py --no-bump --platform win_arm64 --zip
(cd dist && sha256sum SmtpRelay-0.3.0-*.zip > SHA256SUMS)
GITEA_TOKEN=... .venv/bin/python scripts/publish_release.py publish --tag v0.3.0 \
    dist/SmtpRelay-0.3.0-*.zip dist/SHA256SUMS
```

`publish_release.py check-version --tag vX.Y.Z` and `notes --tag vX.Y.Z` show
what the pipeline would do without touching the server.

### Software bill of materials

Every release carries one CycloneDX 1.6 SBOM **per artefact**, six in all,
because the dependency sets genuinely differ: pywin32 only on Windows, a
per-architecture `pydantic-core` wheel, a different CPython source per family,
and Debian packages only in the image.

| Asset | Produced by | Lists |
|---|---|---|
| `SmtpRelay-<ver>-<platform>-cp315.cdx.json` (4) | `build_dist.py`, also inside the payload as `SBOM.cdx.json` | the application, every bundled wheel with its sha256, license and a purl naming the exact file, and the bundled CPython with its download URL and archive sha256; dependency graph from each wheel's `Requires-Dist`, markers evaluated for the target |
| `SmtpRelay-<ver>-image-<arch>.cdx.json` (2) | `syft -o cyclonedx-json@1.6` in the release workflow | the same Python packages plus the Debian packages of `python:3.15-slim` |

The payload SBOM is generated by the build itself rather than by scanning the
result, so it can never list a wheel that was not bundled or miss one that was.
It validates against the CycloneDX 1.6 schema (`cyclonedx-cli validate`). The
`smtprelay:*` properties record the target, the git commit and the runtime
source, so a document can always be traced back to the build that made it.

To scan a release without downloading a payload:

```bash
grype sbom:SmtpRelay-0.3.1-linux_x86_64-cp315.cdx.json
osv-scanner --sbom SmtpRelay-0.3.1-image-amd64.cdx.json
```

An SBOM is inventory, not assurance: pair it with a scheduled scan of the six
documents, and a VEX statement when a finding does not apply.

### Configuration discovery

Two facts make this non-obvious for a service: the SCM starts it with the working
directory set to `C:\Windows\System32`, and under a **non-editable** install the
`app` package lives in `site-packages`, so "beside the package" is a directory that
gets wiped on every upgrade.

Search order, first match wins:

1. an explicit path (internal use)
2. `RELAY_CONFIG`, if set
3. `config.toml` in the working directory
4. **`%ProgramData%\SmtpRelay\config.toml`** — the deployed location
5. `config.toml` beside the `app` package

On Linux the equivalent of step 4 is `/etc/smtp-relay/config.toml`.

**For a service install, put the file at `C:\ProgramData\SmtpRelay\config.toml`.**
Not in `C:\Program Files`: that tree is read-only by convention, is replaced on
upgrade, and is readable by all local users by default — which matters if the file
holds an SMTP password or an API token. Step 5 exists for development against a
checkout, where `app/` sits in the repository and `PACKAGE_ROOT` is the project
root; it is not a deployment location.

`ProgramData` subfolders also inherit read access for standard users, so harden the
directory if the config carries credentials — but keep read access for the service
account, or it cannot read its own configuration:

```powershell
icacls "C:\ProgramData\SmtpRelay" /inheritance:r `
  /grant "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" `
  /grant '"NT SERVICE\SmtpRelay":(OI)(CI)R'
```

Note the quoting: the identity contains a space, so it is quoted while the
permission bits stay outside the quotes. `install.ps1` does this for you, and
grants the service **read-only** access — it never writes to disk, since logs go to
the Event Log.

Better still, keep secrets out of the file entirely and supply them as
`RELAY_SMTP_PASSWORD` / `RELAY_API_TOKEN` — though note a system environment
variable is also readable by local users, so for a genuinely hostile box prefer a
gMSA or a secret manager.

When nothing is found and the environment does not supply the required values, the
startup error names **every** path that was searched.

### Logging

The service logs to the Windows **Application event log** under the source
`SmtpRelay`. A service has no console, so anything written to stderr is discarded
— a file or the event log is the only durable option.

```powershell
Get-EventLog -LogName Application -Source SmtpRelay -Newest 20
```

`install.ps1` registers the event source, because the virtual service account
cannot: `NTEventLogHandler` tries on first use and silently ignores the access
denied, and the result is every record showing as "The description for Event ID
... cannot be found". Two writers share the source with message tables in two
files, so `EventMessageFile` lists both: `win32service.pyd` for the app's log
records (event ID 1) and `servicemanager.pyd` for pywin32's own start, stop and
failure messages. uvicorn is started with `log_config=None` so its records flow
through the same handler rather than installing a competing one. Service start,
stop, and configuration failures are also written via `servicemanager`, so they
appear even if the logging layer itself failed to initialise.

Foreground runs (`python -m app`) and `debug` runs both log to stderr; only the
real service under the SCM uses the Event Log. The service detects this with
`self.ssh is None` — the status handle pywin32 registers in
`ServiceFramework.__init__`, and the same signal its own `ReportServiceStatus`
uses. It deliberately does not inspect `sys.argv`: the non-frozen debug path
launches `pythonservice.exe -debug <name>`, so argv contains `-debug` rather than
`debug` and an equality test silently misses.

### Service account

The service runs as the **virtual service account** `NT SERVICE\SmtpRelay`, not
LocalSystem. LocalSystem carries `SeTcbPrivilege`, full local administrative rights
and acts as the computer on the network — far more than a process that reads one
config file, binds a socket and makes outbound SMTP connections needs.

A virtual account is preferable to `NetworkService` because its SID is unique to
this service. `NetworkService` is shared by every service configured with it, so
anything granted to NetworkService is readable by all of them — including this
service's SMTP credentials. A per-service SID can be granted exactly what it needs.

Both present the **computer account** for network authentication, so NTLM/Kerberos
SMTP auth still works. `LocalService` is the one to avoid: it presents *anonymous*
credentials on the network.

`install.ps1` passes the account to pywin32's `install` (`--username`), so
`CreateService` receives it at creation time, and then grants:

| Path | Grant |
|---|---|
| `C:\Program Files\SmtpRelay` | read + execute, additive (Program Files inheritance left intact) |
| `C:\ProgramData\SmtpRelay` | read only, inheritance stripped |

No write access anywhere — the service logs to the Event Log, so it never creates a
file. Override the account with `-ServiceAccount`.

Three gotchas, all learned on a real Windows 11 ARM64 host:

- **Error 1069 with System event 7038 "No mapping between account names and
  security IDs" can be host state, not configuration.** After the first failed
  logon of `NT SERVICE\SmtpRelay`, LSA kept answering "no mapping" for that
  name across service deletion and re-creation, with either creation method,
  any binary, any display name and any casing, while every fresh name resolved
  instantly. This is also why `icacls` and `NTAccount.Translate` failed with
  1332 for the SID, which the .NET ACL path works around. A reboot cleared it
  and the identical registration then started fine. The installer verifies the
  account with the same lookup the SCM performs at logon and stops with that
  advice if it fails; `-ServiceAccount 'NT AUTHORITY\NetworkService'` is the
  fallback if it persists.
- The installer passes the account to `CreateService` and deletes an existing
  service rather than letting pywin32 update it in place, so every install is a
  clean registration with the account in the canonical position.
- The SID must exist before it can be granted anything, so ACLs are applied
  **after** service registration. `SeServiceLogonRight` is held by
  `NT SERVICE\ALL SERVICES` in the default policy; only a *named* account needs
  it granted explicitly.
- With `SERVICE_SID_TYPE` unrestricted the service SID is in the process token
  **whatever account the service runs as**. Switching the service to
  NetworkService for a test therefore still reads `config.toml` through the
  grant to `NT SERVICE\SmtpRelay`; that is by design, not a hole in the ACL, and
  such a test says nothing about the ACL.

### Operational notes

- **Network exposure is guarded** — setting `api.host` to anything other than
  `127.0.0.1`, `localhost` or `::1` makes the app refuse to start unless TLS
  (`ssl_certfile`) *and* client authentication (`token`, or
  `ssl_cert_reqs = "required"`) are both configured. Without the second, any host
  that can reach the port could relay mail to every allowlisted domain — an open
  relay. `ssl_cert_reqs = "optional"` does not satisfy it, since a client may
  present no certificate at all. The check lives in `AppConfig`, so no entry point
  can bypass it.
- **Firewall** — the API binds `127.0.0.1` by default, so it is reachable only from
  the local machine and **no inbound rule is needed**. To expose it, pass
  `-OpenFirewall` to `install.ps1`, or add the rule yourself:
  ```powershell
  New-NetFirewallRule -DisplayName "SMTP Relay" -Direction Inbound `
    -LocalPort 8000 -Protocol TCP -Action Allow
  ```
  Windows has **no privileged-port concept** — binding 25 or 80 needs nothing
  special — so a high port is collision avoidance, not a security boundary. The
  port trap that *is* Windows-specific is WinNAT: with Hyper-V or WSL2 enabled,
  Windows reserves arbitrary TCP ranges, and binding inside one fails with
  `WinError 10013` or `10048` even though nothing is listening. Check first:
  ```powershell
  netsh int ipv4 show excludedportrange protocol=tcp
  ```
- **Certificates** — `ssl.create_default_context()` reads the Windows certificate
  store, so an internal CA already trusted by Windows needs no `ca_file` at all.
  Validation is always on; there is no option to disable it.
- **Shutdown** — on `stop`, uvicorn's `should_exit` flag is set and the worker
  thread is joined for up to 30 seconds, letting in-flight requests drain. The
  HTTP loop runs in a worker thread precisely so the service's own thread stays
  free to answer SCM control requests.

## Project layout

```
app/
  config.py           TOML + env configuration, validated by Pydantic
  tls.py              server TLS context from a PKCS#12 file or the Windows certificate store
  schemas.py          Request/response models (structural validation -> 422)
  policy.py           Allowlist, base64 heuristic, recipient cap (-> 400)
  relay.py            MIME message building and SMTP delivery (-> 502)
  logging_setup.py    stderr vs. Windows Event Log
  main.py             FastAPI app factory and POST /mail
  __main__.py         `python -m app` entry point and command line (`--check`, `--config`)
  check.py            `--check`: certificate load, dry SMTP session (TLS, AUTH, MAIL FROM), no mail sent
  windows_service.py  native Windows service (pywin32, Windows only)
tests/
scripts/
  build_dist.py       cross-builds the offline payloads (Windows and Linux)
  test_linux_installer.sh  end-to-end install/upgrade/uninstall in a systemd container
  publish_release.py  creates the Gitea release for a tag and attaches the payloads
.gitea/workflows/
  release.yaml        on a vX.Y.Z tag: tests, four payloads + SBOMs, release, multi-arch image
.gitea/runner/
  compose.yaml        a Gitea Actions runner for this repo (Docker or rootless Podman)
  config.yaml
installer/
  windows/
    install.ps1       offline installer: runtime, wheels, config, service, ACLs
    uninstall.ps1
    README.txt        operator instructions shipped in the payload root
  linux/
    install.sh        offline installer: runtime, wheels, config, systemd unit
    uninstall.sh
    smtp-relay.service  hardened unit template rendered by install.sh
    README.txt        operator instructions shipped in the payload root
docker/
  healthcheck.py      container HEALTHCHECK: GET /health via the configured scheme
Dockerfile            multi-arch (amd64/arm64) image, unprivileged, no secrets baked in
compose.yaml          reference deployment behind a TLS-terminating proxy
config.example.toml   annotated configuration template
requirements.txt      fully pinned runtime dependency set, all targets (bundled)
requirements-dev.txt  runtime set + test suite packages (never bundled)
```

`create_app(config)` is an app factory rather than a module-level `app`, so tests can
inject configuration without touching disk. To serve it with uvicorn directly:

```bash
.venv/bin/uvicorn app.main:create_app --factory
```

## Notes

The `/mail` handler is declared `def`, not `async def`. `smtplib` is blocking, so
this lets FastAPI dispatch it to a threadpool instead of stalling the event loop for
the duration of an SMTP transaction.

### History

The first implementation passed `rcpt_to=` to `smtplib.SMTP.send_message()`. The
real parameter is `to_addrs=`. Every mocked test passed, because the `FakeSMTP`
double had been written with the same wrong parameter name — the mock encoded the
bug instead of exposing it. It surfaced as an HTTP 500 on the first live request.
Both the call and the double were corrected, and the signature-binding test and the
`aiosmtpd` integration tests were added so the same class of mistake fails in CI
rather than in production.

The second instance of the same class was pywin32. `python -m app.windows_service`
executes the module as `__main__`, so `GetServiceClassString` falls back to
recording a **filesystem path** as the service's `PythonClass`. `pythonservice.exe`
then imports that file as a top-level module, this package's relative imports fail,
and the process dies before `SvcRun` — so the SCM sees no status transition and
reports only error 1053, "the service did not respond to the start or control
request in a timely fashion". Nothing in the message points at an import error.
Fixed by passing `serviceClassString=SERVICE_CLASS_STRING` explicitly, with a test
that resolves the constant through `importlib.util.find_spec` so a bad path fails
here rather than on a Windows host.

The third was CryptoAPI through pywin32, in the Windows certificate store source.
Locating and exporting the certificate worked first time, built from the
library's export table; the final `CertCloseStore` then failed with
`CRYPT_E_PENDING_CLOSE`, because every enumerated certificate context still
referenced the store. The fake store in the test suite had no such rule, so it
could not have said otherwise. The contexts are now freed first, that one code
is tolerated, and the fake complains the way the real store does.

The fourth was not code but deployment: on the first real host, the relay came
up clean and every message bounced. `smtp.username` was still commented out, so
the relay never authenticated and iCloud answered `554 Client host rejected`,
which reads like an IP block; with that fixed, `policy.sender` was not an
address the account owned, `550 From address is not one of your addresses`.
Both were only discoverable by sending mail. `--check` now holds the same SMTP
session up to `MAIL FROM` without sending, and a password without a username is
a configuration error.

All four were assumptions about a third party that no amount of Linux-side
testing would have caught. The countermeasure in each case is the same: bind
against the real library, or read its source, rather than modelling what it
probably does - and when the real thing can only run on another machine, run it
there before calling the work done.
