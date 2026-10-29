#!/usr/bin/env bash
# SMTP Relay - offline installer for Linux hosts running systemd.
#
#   sudo ./install.sh [--install-dir DIR] [--config-dir DIR] [--service-name NAME]
#                     [--user NAME] [--force] [--start]
#
# What it does, in order:
#   1. validates the payload against MANIFEST.json using the bundled interpreter
#      (which also proves the payload matches this machine's architecture);
#   2. creates the system account (no home, no shell, no password);
#   3. copies the bundled CPython and the application to --install-dir and
#      installs the pinned dependencies from the bundled wheels, offline;
#   4. seeds --config-dir/config.toml from the template (never overwrites), owned
#      root:<user> mode 0640 so only root and the service can read secrets;
#   5. renders the hardened systemd unit, reloads systemd, enables the service.
#
# No system Python is used or required. Requires root and a running systemd.
# --force re-runs over an existing installation (upgrade): the service is
# stopped, --install-dir replaced, --config-dir preserved.

set -euo pipefail

INSTALL_DIR=/opt/smtp-relay
CONFIG_DIR=/etc/smtp-relay
SERVICE_NAME=smtp-relay
SERVICE_USER=smtp-relay
FORCE=0
START=0

usage() { sed -n '2,19p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-dir)  INSTALL_DIR=$2; shift 2 ;;
        --config-dir)   CONFIG_DIR=$2; shift 2 ;;
        --service-name) SERVICE_NAME=$2; shift 2 ;;
        --user)         SERVICE_USER=$2; shift 2 ;;
        --force)        FORCE=1; shift ;;
        --start)        START=1; shift ;;
        -h|--help)      usage 0 ;;
        *) echo "unknown option: $1" >&2; usage 2 ;;
    esac
done

if [[ -t 1 ]]; then C_STEP=$'\e[36m'; C_OK=$'\e[32m'; C_WARN=$'\e[33m'; C_ERR=$'\e[31m'; C_OFF=$'\e[0m'
else C_STEP=; C_OK=; C_WARN=; C_ERR=; C_OFF=; fi
step() { printf '\n%s==> %s%s\n' "$C_STEP" "$1" "$C_OFF"; }
ok()   { printf '    %s%s%s\n' "$C_OK" "$1" "$C_OFF"; }
warn() { printf '    %s%s%s\n' "$C_WARN" "$1" "$C_OFF"; }
die()  { printf '\n%sERROR: %s%s\n' "$C_ERR" "$1" "$C_OFF" >&2; [[ $# -gt 1 ]] && printf '%s\n' "$2" >&2; exit 1; }

PAYLOAD=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PAYLOAD_PY="$PAYLOAD/python/bin/python3"
WHEEL_DIR="$PAYLOAD/wheels"
UNIT_FILE="/etc/systemd/system/$SERVICE_NAME.service"
PY="$INSTALL_DIR/python/bin/python3"

# ------------------------------------------------------------------ preflight

step "Validating payload in $PAYLOAD"
[[ $EUID -eq 0 ]] || die "This installer must run as root." "  sudo $0 $*"
[[ -d /run/systemd/system ]] || die "systemd is not the running init on this host." \
    "Only systemd hosts are supported. Use the container image elsewhere."
command -v systemctl >/dev/null || die "systemctl not found."
[[ -f "$PAYLOAD/MANIFEST.json" ]] || die "No MANIFEST.json in $PAYLOAD - this is not a complete payload."
[[ -x "$PAYLOAD_PY" ]] || die "Bundled interpreter missing: $PAYLOAD_PY"

# The bundled interpreter both validates the manifest and proves the payload
# matches this machine: a wrong-architecture binary fails right here.
if ! "$PAYLOAD_PY" -I -c 'import sys' 2>/dev/null; then
    die "The bundled interpreter will not run on this machine ($(uname -m))." \
        "The payload was built for a different architecture; download the matching one."
fi

MANIFEST_INFO=$("$PAYLOAD_PY" -I - "$PAYLOAD" <<'PY'
import hashlib, json, platform, sys
from pathlib import Path
root = Path(sys.argv[1])
m = json.loads((root / "MANIFEST.json").read_text())
if m.get("family") != "linux":
    sys.exit(f"payload is for {m.get('platform')}, not Linux")
want = m["platform"].split("_", 1)[1]
have = platform.machine()
if want != have:
    sys.exit(f"payload is for {want}, this machine is {have}")
bad = []
for rel, digest in m["files"].items():
    p = root / rel
    if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest() != digest:
        bad.append(rel)
if bad:
    sys.exit("payload is corrupt or incomplete; first mismatches: " + ", ".join(bad[:5]))
print(m["version"], m["platform"], m["runtime_version"], m["wheel_count"])
PY
) || die "Payload validation failed." "$MANIFEST_INFO"
read -r VERSION PLATFORM RUNTIME_VERSION WHEEL_COUNT <<<"$MANIFEST_INFO"
ok "SmtpRelay $VERSION for $PLATFORM, bundled CPython $RUNTIME_VERSION"
ok "$WHEEL_COUNT wheels verified for offline install"

if [[ -d "$INSTALL_DIR" && $FORCE -ne 1 ]]; then
    die "'$INSTALL_DIR' already exists." "Re-run with --force to upgrade in place, or run uninstall.sh first."
fi
if systemctl cat "$SERVICE_NAME.service" >/dev/null 2>&1; then
    [[ $FORCE -eq 1 ]] || die "Service '$SERVICE_NAME' is already registered." "Re-run with --force to upgrade, or run uninstall.sh first."
    if systemctl is-active --quiet "$SERVICE_NAME.service"; then
        systemctl stop "$SERVICE_NAME.service"
        ok "Stopped the running service for upgrade"
    fi
fi

# ------------------------------------------------------------ service account

step "Service account '$SERVICE_USER'"
NOLOGIN=$(command -v nologin || echo /usr/sbin/nologin)
if ! getent group "$SERVICE_USER" >/dev/null; then
    groupadd --system "$SERVICE_USER"
fi
if ! getent passwd "$SERVICE_USER" >/dev/null; then
    useradd --system --gid "$SERVICE_USER" --home-dir /nonexistent --no-create-home \
        --shell "$NOLOGIN" --comment "SMTP Relay service" "$SERVICE_USER"
    ok "Created system user $SERVICE_USER (no home, no shell)"
else
    ok "System user $SERVICE_USER exists"
fi

# ---------------------------------------------------------------- install dir

step "Installing to $INSTALL_DIR"
rm -rf "$INSTALL_DIR"
install -d -m 0755 -o root -g root "$INSTALL_DIR"
cp -a "$PAYLOAD/python" "$INSTALL_DIR/python"
cp -a "$PAYLOAD/app" "$INSTALL_DIR/app"
for f in pyproject.toml README.md requirements.txt config.example.toml MANIFEST.json; do
    install -m 0644 "$PAYLOAD/$f" "$INSTALL_DIR/$f"
done
chown -R root:root "$INSTALL_DIR"
ok "Bundled CPython $RUNTIME_VERSION at $INSTALL_DIR/python"

step "Installing dependencies from bundled wheels (offline)"
if ! "$PY" -m pip --version >/dev/null 2>&1; then
    "$PY" -m ensurepip --quiet 2>/dev/null || true
fi
if ! "$PY" -m pip --version >/dev/null 2>&1; then
    PIP_WHEEL=$(ls "$WHEEL_DIR"/pip-*.whl 2>/dev/null | head -n1)
    [[ -n "$PIP_WHEEL" ]] || die "pip is unavailable and no pip wheel is bundled."
    "$PY" "$PIP_WHEEL/pip" install --no-index --find-links "$WHEEL_DIR" --quiet --no-warn-script-location --root-user-action=ignore pip
fi
ok "$("$PY" -m pip --version | tail -n1)"
# --root-user-action=ignore: pip warns about running as root, but a private
# runtime under /opt owned by root is exactly the intended layout.
PIP=("$PY" -m pip install --no-index --find-links "$WHEEL_DIR" --quiet --no-warn-script-location --root-user-action=ignore)
"${PIP[@]}" setuptools wheel
# requirements.txt carries sys_platform markers; pip evaluates them for this
# host, so the Windows-only pins (pywin32, colorama) are skipped here.
"${PIP[@]}" -r "$INSTALL_DIR/requirements.txt"
ok "dependencies installed"

step "Installing smtp-relay"
"${PIP[@]}" --no-deps --no-build-isolation "$INSTALL_DIR"
rm -rf "$INSTALL_DIR/build" "$INSTALL_DIR"/*.egg-info
INSTALLED_VERSION=$("$PY" -I -c 'import app; print(app.__version__)')
[[ "$INSTALLED_VERSION" == "$VERSION" ]] || die "Installed app reports $INSTALLED_VERSION, payload is $VERSION."
ok "smtp-relay $INSTALLED_VERSION installed"

# ----------------------------------------------------------------- config dir

step "Configuring $CONFIG_DIR"
install -d -m 0750 -o root -g "$SERVICE_USER" "$CONFIG_DIR"
if [[ -f "$CONFIG_DIR/config.toml" ]]; then
    chown root:"$SERVICE_USER" "$CONFIG_DIR/config.toml"
    chmod 0640 "$CONFIG_DIR/config.toml"
    ok "config.toml already present - left untouched"
else
    install -m 0640 -o root -g "$SERVICE_USER" "$PAYLOAD/config.example.toml" "$CONFIG_DIR/config.toml"
    warn "Seeded config.toml from the template. EDIT IT BEFORE STARTING:"
    warn "  sudoedit $CONFIG_DIR/config.toml"
fi
ok "$CONFIG_DIR: root read-write, $SERVICE_USER read-only, nobody else"

# ---------------------------------------------------------------- systemd unit

step "Registering systemd unit $UNIT_FILE"
sed -e "s|@INSTALL_DIR@|$INSTALL_DIR|g" \
    -e "s|@CONFIG_DIR@|$CONFIG_DIR|g" \
    -e "s|@USER@|$SERVICE_USER|g" \
    -e "s|@GROUP@|$SERVICE_USER|g" \
    "$PAYLOAD/smtp-relay.service" > "$UNIT_FILE.tmp"
install -m 0644 -o root -g root "$UNIT_FILE.tmp" "$UNIT_FILE"
rm -f "$UNIT_FILE.tmp"
systemctl daemon-reload
systemctl enable --quiet "$SERVICE_NAME.service"
ok "Enabled at boot; restart on failure"
if command -v systemd-analyze >/dev/null; then
    if VERIFY=$(systemd-analyze verify --man=no --generators=no "$SERVICE_NAME.service" 2>&1 | grep "$SERVICE_NAME" || true); [[ -n "$VERIFY" ]]; then
        warn "systemd-analyze verify: $VERIFY"
    else
        ok "Unit verified by systemd-analyze"
    fi
fi

if [[ $START -eq 1 ]]; then
    step "Starting $SERVICE_NAME"
    systemctl start "$SERVICE_NAME.service"
    # Type=exec means start has returned only after python3 was exec'd; now wait
    # for the app to answer, using the bundled interpreter and the same config
    # the service reads, so a non-default port or TLS is honoured.
    HEALTH_URL=$(RELAY_CONFIG="$CONFIG_DIR/config.toml" "$PY" -I -c '
from app.config import load_config
s = load_config().api
host = "127.0.0.1" if s.host in ("0.0.0.0", "::", "") else s.host
print(f"{s.scheme}://{host}:{s.port}/health")' 2>/dev/null || echo "http://127.0.0.1:8000/health")
healthy=0
for _ in $(seq 1 30); do
    if ! systemctl is-active --quiet "$SERVICE_NAME.service"; then break; fi
        if "$PY" -I -c "
import ssl, sys, urllib.request
ctx = ssl._create_unverified_context() if sys.argv[1].startswith('https') else None
urllib.request.urlopen(sys.argv[1], timeout=2, context=ctx).read()" "$HEALTH_URL" 2>/dev/null; then
        healthy=1; break
    fi
    sleep 0.5
done
    if [[ $healthy -eq 1 ]]; then
        ok "Service is running and answers at $HEALTH_URL"
    else
        journalctl -u "$SERVICE_NAME.service" -n 20 --no-pager || true
        die "Service did not become healthy at $HEALTH_URL within 15s; see the journal above."
    fi
fi

# -------------------------------------------------------------------- summary

cat <<SUMMARY

Installation complete.

  Program files : $INSTALL_DIR
  Configuration : $CONFIG_DIR/config.toml
  Service       : $SERVICE_NAME.service (enabled$([[ $START -eq 1 ]] && echo ", running" || echo ", not started"))
  Runs as       : $SERVICE_USER
  Runtime       : $PY (bundled CPython $RUNTIME_VERSION, private to this service)

Next steps:
  1. Edit the configuration:   sudoedit $CONFIG_DIR/config.toml
  2. Start the service:        sudo systemctl start $SERVICE_NAME
  3. Follow the logs:          journalctl -u $SERVICE_NAME -f
  4. Health check:             curl -s http://127.0.0.1:8000/health

Exposing the API beyond this machine: set api.host in config.toml, then either
serve TLS from the relay (api.ssl_certfile / api.ssl_keyfile) or declare a
TLS-terminating reverse proxy (api.behind_tls_proxy = true), and in both cases
set api.token or require mutual TLS. The application refuses to start otherwise,
so it cannot silently become a cleartext open relay.
SUMMARY
