#!/usr/bin/env bash
# SMTP Relay - uninstaller for Linux hosts running systemd.
#
#   sudo ./uninstall.sh [--install-dir DIR] [--config-dir DIR] [--service-name NAME]
#                       [--user NAME] [--remove-config] [--keep-user]
#
# Stops and disables the service, removes the unit and the program files, and
# deletes the service account. The configuration directory is PRESERVED unless
# --remove-config is passed, because it may hold the only copy of your settings.

set -uo pipefail

INSTALL_DIR=/opt/smtp-relay
CONFIG_DIR=/etc/smtp-relay
SERVICE_NAME=smtp-relay
SERVICE_USER=smtp-relay
REMOVE_CONFIG=0
KEEP_USER=0

usage() { sed -n '2,9p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-dir)   INSTALL_DIR=$2; shift 2 ;;
        --config-dir)    CONFIG_DIR=$2; shift 2 ;;
        --service-name)  SERVICE_NAME=$2; shift 2 ;;
        --user)          SERVICE_USER=$2; shift 2 ;;
        --remove-config) REMOVE_CONFIG=1; shift ;;
        --keep-user)     KEEP_USER=1; shift ;;
        -h|--help)       usage 0 ;;
        *) echo "unknown option: $1" >&2; usage 2 ;;
    esac
done

step() { printf '\n==> %s\n' "$1"; }
ok()   { printf '    %s\n' "$1"; }
warn() { printf '    %s\n' "$1"; }

[[ $EUID -eq 0 ]] || { echo "ERROR: run as root (sudo $0)" >&2; exit 1; }
UNIT_FILE="/etc/systemd/system/$SERVICE_NAME.service"
residue=()

step "Stopping service '$SERVICE_NAME'"
if systemctl cat "$SERVICE_NAME.service" >/dev/null 2>&1; then
    systemctl disable --now --quiet "$SERVICE_NAME.service" 2>/dev/null || true
    ok "Stopped and disabled"
else
    ok "Not registered"
fi

step "Removing unit"
if [[ -f "$UNIT_FILE" ]]; then
    rm -f "$UNIT_FILE"
    rm -rf "$UNIT_FILE.d"
    ok "Removed $UNIT_FILE"
else
    ok "No unit file"
fi
systemctl daemon-reload
systemctl reset-failed "$SERVICE_NAME.service" 2>/dev/null || true

step "Removing program files"
if [[ -d "$INSTALL_DIR" ]]; then
    rm -rf "$INSTALL_DIR" && ok "Removed $INSTALL_DIR" || residue+=("$INSTALL_DIR")
else
    ok "$INSTALL_DIR not present"
fi

step "Configuration"
if [[ $REMOVE_CONFIG -eq 1 ]]; then
    if [[ -d "$CONFIG_DIR" ]]; then
        rm -rf "$CONFIG_DIR" && ok "Removed $CONFIG_DIR" || residue+=("$CONFIG_DIR")
    else
        ok "$CONFIG_DIR not present"
    fi
else
    warn "Preserved $CONFIG_DIR (pass --remove-config to delete it)."
fi

step "Service account"
if [[ $KEEP_USER -eq 1 ]]; then
    warn "Kept user/group $SERVICE_USER (--keep-user)"
else
    if getent passwd "$SERVICE_USER" >/dev/null; then
        userdel "$SERVICE_USER" 2>/dev/null && ok "Removed user $SERVICE_USER" || residue+=("user $SERVICE_USER")
    fi
    if getent group "$SERVICE_USER" >/dev/null; then
        groupdel "$SERVICE_USER" 2>/dev/null && ok "Removed group $SERVICE_USER" || true
    fi
fi

echo
if [[ ${#residue[@]} -gt 0 ]]; then
    echo "Uninstall finished with residue:"
    printf '  %s\n' "${residue[@]}"
    exit 1
fi
echo "Uninstall complete."
