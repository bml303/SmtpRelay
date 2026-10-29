#!/usr/bin/env bash
# End-to-end test of installer/linux inside a throwaway systemd container.
#
#   scripts/test_linux_installer.sh dist/SmtpRelay-<ver>-linux_x86_64-cp315
#
# Boots systemd in a Debian container (tests/fixtures/systemd-debian.Containerfile),
# runs install.sh --start, checks /health through the bundled interpreter, then
# runs uninstall.sh --remove-config and asserts nothing is left. Needs podman
# (or docker via the DOCKER env var) on a host whose architecture matches the
# payload. Prints the journal on failure.

set -euo pipefail

PAYLOAD=${1:?usage: $0 <payload directory>}
PAYLOAD=$(cd "$PAYLOAD" && pwd)
ENGINE=${DOCKER:-podman}
IMAGE=smtp-relay-systemd-test
NAME=smtp-relay-e2e-$$
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

if ! "$ENGINE" image exists "$IMAGE" 2>/dev/null; then
    echo "==> building $IMAGE"
    "$ENGINE" build -q -t "$IMAGE" -f "$HERE/tests/fixtures/systemd-debian.Containerfile" "$HERE/tests/fixtures"
fi

cleanup() { "$ENGINE" rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "==> booting systemd container"
# --privileged: the unit's mount-namespace sandboxing (ProtectSystem=strict,
# PrivateTmp, ...) needs CAP_SYS_ADMIN inside the container, which a rootless
# unprivileged container does not get; without it the service dies with
# "Failed to keep CAP_SYS_ADMIN" / status=217/USER. A real host has it.
"$ENGINE" run -d --name "$NAME" --systemd=always --privileged -v "$PAYLOAD:/payload:ro" "$IMAGE" >/dev/null
for _ in $(seq 1 30); do
    state=$("$ENGINE" exec "$NAME" systemctl is-system-running 2>/dev/null || true)
    [[ "$state" == "running" || "$state" == "degraded" ]] && break
    sleep 1
done
echo "    systemd: $state"

x() { "$ENGINE" exec "$NAME" "$@"; }
fail() { echo "FAIL: $1" >&2; x journalctl -u smtp-relay --no-pager -n 40 || true; x systemctl status smtp-relay --no-pager || true; exit 1; }

echo "==> install.sh --start (seeded template config; mailhost is the example)"
x bash /payload/install.sh --start || fail "install.sh exited non-zero"

echo "==> assertions"
x systemctl is-active --quiet smtp-relay || fail "service not active"
x bash -c 'stat -c "%U:%G %a" /etc/smtp-relay/config.toml' | tee /dev/stderr | grep -q "^root:smtp-relay 640$" || fail "config.toml ownership/mode"
x bash -c 'stat -c "%U:%G %a" /etc/smtp-relay' | grep -q "^root:smtp-relay 750$" || fail "config dir ownership/mode"
x bash -c 'stat -c %U /proc/$(systemctl show -p MainPID --value smtp-relay)' | grep -qx "smtp-relay" || fail "process not running as smtp-relay"
x /opt/smtp-relay/python/bin/python3 -I -c '
import json, urllib.request
with urllib.request.urlopen("http://127.0.0.1:8000/health", timeout=5) as r:
    d = json.load(r); print("    /health:", d); assert d["status"] == "ok"
' || fail "health check"
# The unit sets RELAY_CONFIG, so the service must have read exactly that file.
x journalctl -u smtp-relay --no-pager -o cat | grep -q "Listening on http://127.0.0.1:8000" || fail "listening line missing from journal"
x bash -c 'systemd-analyze security smtp-relay --no-pager | tail -n 1' || true
echo "==> upgrade in place (install.sh --force) keeps config"
x bash -c 'echo "# operator edit" >> /etc/smtp-relay/config.toml'
x bash /payload/install.sh --force --start >/dev/null || fail "install.sh --force"
x grep -q "# operator edit" /etc/smtp-relay/config.toml || fail "config.toml was overwritten on upgrade"
x systemctl is-active --quiet smtp-relay || fail "service not active after upgrade"

echo "==> uninstall.sh --remove-config"
x bash /payload/uninstall.sh --remove-config || fail "uninstall.sh exited non-zero"
x bash -c '! test -e /opt/smtp-relay && ! test -e /etc/smtp-relay && ! test -e /etc/systemd/system/smtp-relay.service && ! getent passwd smtp-relay' || fail "residue after uninstall"
x bash -c '! systemctl cat smtp-relay.service >/dev/null 2>&1' || fail "unit still known to systemd"

echo "PASS: install, run, upgrade and uninstall all behaved on $(x cat /etc/os-release | grep PRETTY | cut -d= -f2)"
