#!/usr/bin/env bash
# HorseSafe nightly backup → Hetzner Storagebox
# Cron: dagelijks 03:00 als user horsesafe
# Vereist: SSH-key in ~horsesafe/.ssh/id_ed25519 + Storagebox-host in ~/.ssh/config

set -euo pipefail

INSTALL_DIR=/opt/horsesafe
TS=$(date +%Y%m%d-%H%M%S)
LOG_TAG="[horsesafe-backup $TS]"

# Storagebox-host. Override via /opt/horsesafe/.env als STORAGEBOX_TARGET gezet is.
if [ -f "$INSTALL_DIR/.env" ]; then
  # shellcheck disable=SC1091
  set -a; source "$INSTALL_DIR/.env"; set +a
fi
STORAGEBOX_TARGET="${HORSESAFE_BACKUP_TARGET:-}"

echo "$LOG_TAG start"

if [ -z "$STORAGEBOX_TARGET" ]; then
  echo "$LOG_TAG SKIP — HORSESAFE_BACKUP_TARGET niet gezet (configureer via .env)"
  exit 0
fi

# Rsync van DB + vaults
rsync -av --delete \
    "$INSTALL_DIR/db/" \
    "$STORAGEBOX_TARGET/db/" 2>&1

rsync -av --delete \
    "$INSTALL_DIR/vaults/" \
    "$STORAGEBOX_TARGET/vaults/" 2>&1

# 30-dagen-retentie: SQLite-snapshot archive per dag
SNAP_DIR="$INSTALL_DIR/tmp/snapshot-$TS"
mkdir -p "$SNAP_DIR"
sqlite3 "$INSTALL_DIR/db/horsesafe.db" ".backup $SNAP_DIR/horsesafe.db"
tar -cJf "$INSTALL_DIR/tmp/snap-$TS.tar.xz" -C "$INSTALL_DIR/tmp" "snapshot-$TS"
rm -rf "$SNAP_DIR"

rsync -av "$INSTALL_DIR/tmp/snap-$TS.tar.xz" "$STORAGEBOX_TARGET/snapshots/" 2>&1
rm -f "$INSTALL_DIR/tmp/snap-$TS.tar.xz"

# Retentie: verwijder snapshots ouder dan 30 dagen (best-effort)
ssh -o BatchMode=yes "${STORAGEBOX_TARGET%%:*}" "find '${STORAGEBOX_TARGET#*:}/snapshots' -name 'snap-*.tar.xz' -mtime +30 -delete" 2>&1 || true

echo "$LOG_TAG OK"
