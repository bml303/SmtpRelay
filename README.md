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
.venv/bin/python -m app
```

For a reproducible install from the pinned set instead of resolving fresh:

```bash
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip install --no-deps -e .
```

`requirements.txt` pins every transitive dependency to an exact version. It is a
flat file, so it includes the test-only packages (`pytest`, `httpx`, `aiosmtpd`);
use `pip install .` for a production install that skips them. Regenerate it after
touching `pyproject.toml`:

```bash
.venv/bin/python -m pip freeze --exclude-editable > requirements.txt
```

### Dependencies

Three runtime packages — `fastapi`, `uvicorn`, `pydantic[email]` — plus dev extras.

`uvicorn` is deliberately installed **without** its `[standard]` extra. That extra
pulls in `httptools`, `PyYAML`, `watchfiles`, `websockets`, `python-dotenv` and
`uvloop`, none of which this relay uses: config is TOML, there is no `--reload`, no
WebSocket endpoint and no `.env` file.

Excluding it matters on Windows. `PyYAML` publishes no `win_amd64` wheel for CPython
3.15 and no `win_arm64` wheel for 3.11, so it turns `pip install` into a source
build demanding **Visual Studio Build Tools for C++** — to compile a module the
relay never imports. Without the extra, `pydantic-core` and `pywin32` are the only
compiled dependencies and both have complete wheels, so **no C/C++ compiler is
needed on any of win_amd64/win_arm64 × CPython 3.11–3.15**. uvicorn then serves
over its pure-Python `h11` protocol instead of `httptools`, which is irrelevant at
mail-relay volumes (verified live with 200 KB and 2 MB request bodies).

`tests/test_windows_deployment.py` fails if any of those six packages reappears in
`requirements.txt`, or if `pyproject.toml` re-declares `uvicorn[standard]`.

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
the offending field.

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

Setting `api.ssl_certfile` switches the endpoint to HTTPS — plaintext HTTP is then
refused on that port, not served alongside it.

```toml
[api]
host = "0.0.0.0"
ssl_certfile = "/etc/ssl/certs/smtp-relay.crt"
ssl_keyfile = "/etc/ssl/private/smtp-relay.key"
```

| Key | Purpose |
|---|---|
| `api.ssl_certfile` | Server certificate chain. Its presence enables TLS. |
| `api.ssl_keyfile` | Private key. Omit if the key is appended to the cert file. |
| `api.ssl_keyfile_password` | Passphrase for an encrypted key. Prefer `RELAY_API_SSL_KEYFILE_PASSWORD`. |
| `api.ssl_ca_certs` | Client CA bundle, for mutual TLS. Must be paired with `ssl_cert_reqs`. |
| `api.ssl_cert_reqs` | `none` \| `optional` \| `required` — mapped to `ssl.VerifyMode` for uvicorn. `optional`/`required` must be paired with `ssl_ca_certs`. |

Two things are rejected at startup rather than failing obscurely later:

- Setting any `ssl_*` key other than `ssl_certfile` without `ssl_certfile` — TLS
  would not be enabled at all.
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

If you terminate TLS in a reverse proxy instead, leave `api.ssl_*` unset, keep
`api.host = "127.0.0.1"`, and have the proxy forward to it.

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
.venv/bin/python -m pytest          # 132 tests
```

Five layers:

- **unit** (`test_policy.py`, `test_config.py`, `test_logging_setup.py`) —
  allowlist matching, the base64 heuristic, TOML loading, env overrides, and the
  config search paths.
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
- **packaging** (`test_windows_deployment.py`) — the service module compiles, and
  every platform-specific pin carries the marker that keeps `requirements.txt`
  installable on Windows.

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

## Deploying as a Windows service

The relay runs as a **native Windows service** through pywin32 — no external
wrapper binary. Install the dependencies, which pull in pywin32 automatically on
Windows:

```powershell
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\pip install --no-deps -e .
```

Then, **from an elevated prompt**, using the venv's own interpreter (not the
system Python):

```powershell
.venv\Scripts\python -m app.windows_service install
.venv\Scripts\python -m app.windows_service start
```

Other subcommands: `stop`, `restart`, `remove`, and `debug`. Run `debug` first —
it executes in a console instead of under the Service Control Manager, and
surfaces errors that the SCM would otherwise report only as "the service did not
start".

The service registers as `SmtpRelay`, displayed as "SMTP Relay".

### Configuration discovery

A service's working directory is set by the SCM to `C:\Windows\System32`, so the
config file is **not** looked for there alone. Search order:

1. an explicit path (internal use)
2. `RELAY_CONFIG`, if set
3. `config.toml` in the working directory
4. `config.toml` beside the `app` package — the deployment root

Rule 4 is what makes a service work with no extra setup: keep `config.toml` next
to the `app` directory you installed from. If you instead install into
`site-packages`, set `RELAY_CONFIG` as a **machine-level** environment variable
pointing at an absolute path, then restart the service. When nothing is found and
the environment does not supply the required values, the startup error names every
path that was searched.

### Logging

The service logs to the Windows **Application event log** under the source
`SmtpRelay`. A service has no console, so anything written to stderr is discarded
— a file or the event log is the only durable option.

```powershell
Get-EventLog -LogName Application -Source SmtpRelay -Newest 20
```

Registering the event source requires administrative rights, which `install`
already demands. uvicorn is started with `log_config=None` so its records flow
through the same handler rather than installing a competing one. Service start,
stop, and configuration failures are also written via `servicemanager`, so they
appear even if the logging layer itself failed to initialise.

Foreground runs (`python -m app`) still log to stderr.

### Operational notes

- **Firewall** — the API binds `127.0.0.1` by default, so it is reachable only
  from the local machine and **no inbound rule is needed**. Only if you set
  `api.host = "0.0.0.0"` do remote clients come into play, and you should enable
  API TLS before opening the port, otherwise the bearer token crosses the network
  in cleartext:
  ```powershell
  New-NetFirewallRule -DisplayName "SMTP Relay" -Direction Inbound `
    -LocalPort 8000 -Protocol TCP -Action Allow
  ```
- **Service account** — runs as LocalSystem by default, which has the outbound
  network access SMTP needs. Only change it (`sc.exe config SmtpRelay obj= ...`)
  if your mailhost requires a specific identity.
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
  schemas.py          Request/response models (structural validation -> 422)
  policy.py           Allowlist, base64 heuristic, recipient cap (-> 400)
  relay.py            MIME message building and SMTP delivery (-> 502)
  logging_setup.py    stderr vs. Windows Event Log
  main.py             FastAPI app factory and POST /mail
  __main__.py         `python -m app` entry point
  windows_service.py  native Windows service (pywin32, Windows only)
tests/
config.example.toml   annotated configuration template
requirements.txt      fully pinned, cross-platform dependency set
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
