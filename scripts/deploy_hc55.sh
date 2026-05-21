#!/usr/bin/env bash
# HorseSafe HC55 deploy-script v0.0.7-Bellare
#
# Idempotente bootstrap voor productie-deploy op HorseCloud55.
# Voer uit als root op de server:
#   bash <(curl -fsSL https://raw.githubusercontent.com/cpaglebbeek/HorseSafe/main/scripts/deploy_hc55.sh)
# of vanuit lokaal-gecloond pad:
#   cd /opt/horsesafe/repo && sudo bash scripts/deploy_hc55.sh
#
# Doet:
#   1. apt-update + python3.12 + nginx + sqlite3 install (idempotent)
#   2. user `horsesafe` aanmaken (no-login)
#   3. /opt/horsesafe/* dirs aanmaken met juiste perms
#   4. git clone of pull cpaglebbeek/HorseSafe naar /opt/horsesafe/repo
#   5. venv + pip install
#   6. .env genereren met random secrets (ALLEEN als nog niet bestaat)
#   7. DB init + migrate
#   8. Frontend kopie naar /opt/horsesafe/web/
#   9. nginx-snippet kopie naar /etc/nginx/snippets/
#  10. systemd-unit kopie naar /etc/systemd/system/
#  11. Backup-cron toevoegen aan /etc/cron.d/horsesafe-backup
#
# Doet NIET (vereist expliciet vervolg):
#   - nginx -s reload  (gebruik na review: nginx -t && systemctl reload nginx)
#   - systemctl enable + start horsesafe
#   - Geen verbreken/restart van andere services

set -euo pipefail

INSTALL_DIR=/opt/horsesafe
REPO_URL=https://github.com/cpaglebbeek/HorseSafe.git
SERVICE_USER=horsesafe

echo "═══ HorseSafe HC55 deploy v0.0.7-Bellare ═══"

# 1. Pre-flight
[ "$(id -u)" -eq 0 ] || { echo "ERROR: run als root"; exit 1; }
command -v apt-get >/dev/null || { echo "ERROR: apt-get niet gevonden"; exit 1; }

# 2. Packages (idempotent)
echo "→ apt install python3.12 + git + nginx + sqlite3 + cron"
apt-get update -qq
apt-get install -y -qq python3.12 python3.12-venv git nginx sqlite3 cron rsync openssh-client >/dev/null

# 3. Service-user
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  echo "→ aanmaken systeem-user $SERVICE_USER"
  useradd -r -s /bin/false -d "$INSTALL_DIR" -M "$SERVICE_USER"
fi

# 4. Directory-structuur
echo "→ directory-structuur"
mkdir -p "$INSTALL_DIR"/{db,vaults,logs,tmp,web}
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
chmod 700 "$INSTALL_DIR"/{db,vaults,logs,tmp}
chmod 755 "$INSTALL_DIR"/web

# 5. Git clone of update
if [ -d "$INSTALL_DIR/repo/.git" ]; then
  echo "→ git pull (update)"
  sudo -u "$SERVICE_USER" git -C "$INSTALL_DIR/repo" fetch --quiet
  sudo -u "$SERVICE_USER" git -C "$INSTALL_DIR/repo" reset --hard origin/main --quiet
else
  echo "→ git clone $REPO_URL"
  sudo -u "$SERVICE_USER" git clone --quiet "$REPO_URL" "$INSTALL_DIR/repo"
fi

# 6. Python venv + deps
if [ ! -d "$INSTALL_DIR/venv" ]; then
  echo "→ python venv aanmaken"
  sudo -u "$SERVICE_USER" python3.12 -m venv "$INSTALL_DIR/venv"
fi
echo "→ pip install requirements"
sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/repo/backend/requirements.txt"

# 7. .env (alleen bij eerste keer; daarna niet overschrijven!)
ENV_FILE="$INSTALL_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
  echo "→ .env genereren met random secrets (eerste keer)"
  cat > "$ENV_FILE" <<EOF
# HorseSafe production env — gegenereerd $(date -u +%Y-%m-%dT%H:%M:%SZ)
HORSESAFE_DB_PATH=$INSTALL_DIR/db/horsesafe.db
HORSESAFE_VAULTS_DIR=$INSTALL_DIR/vaults
HORSESAFE_JWT_SECRET=$(openssl rand -hex 32)
HORSESAFE_TOTP_ENCRYPTION_KEY=$(openssl rand -hex 32)
HORSESAFE_COOKIE_SECURE=true
HORSESAFE_COOKIE_SAMESITE=strict
HORSESAFE_RATE_LIMIT_ENABLED=true
HORSESAFE_BCRYPT_ROUNDS=12
HORSESAFE_PUBLIC_URL=https://horsecloud55.ddns.net/HorseSafe
# Vul Gmail-credentials hieronder in vóór magic-link in gebruik te nemen:
HORSESAFE_GMAIL_USER=
HORSESAFE_GMAIL_APP_PASSWORD=
EOF
  chmod 600 "$ENV_FILE"
  chown "$SERVICE_USER:$SERVICE_USER" "$ENV_FILE"
else
  echo "→ .env bestaat al — niet overschreven"
fi

# 8. DB init + migrate
echo "→ DB init + migrate"
cd "$INSTALL_DIR/repo"
sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/python" -m backend.db.init
sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/python" -m backend.db.migrate

# 9. Frontend kopie
echo "→ frontend kopiëren naar $INSTALL_DIR/web/"
rsync -a --delete "$INSTALL_DIR/repo/frontend/" "$INSTALL_DIR/web/"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/web"

# 10. nginx-snippet
NGINX_SNIPPETS_DIR=/etc/nginx/snippets
mkdir -p "$NGINX_SNIPPETS_DIR"
echo "→ nginx-snippet kopiëren naar $NGINX_SNIPPETS_DIR/horsesafe.conf"
cp "$INSTALL_DIR/repo/scripts/nginx_snippet.conf" "$NGINX_SNIPPETS_DIR/horsesafe.conf"

# 11. systemd-unit (kopie, NIET enable/start)
echo "→ systemd-unit kopiëren naar /etc/systemd/system/horsesafe.service"
cp "$INSTALL_DIR/repo/scripts/horsesafe.service" /etc/systemd/system/horsesafe.service
systemctl daemon-reload

# 12. Backup-script + cron
echo "→ backup-script + cron"
cp "$INSTALL_DIR/repo/scripts/backup_to_storagebox.sh" "$INSTALL_DIR/backup.sh"
chmod 755 "$INSTALL_DIR/backup.sh"
chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/backup.sh"
cat > /etc/cron.d/horsesafe-backup <<'EOF'
# HorseSafe nightly backup → Hetzner Storagebox
0 3 * * * horsesafe /opt/horsesafe/backup.sh >> /opt/horsesafe/logs/backup.log 2>&1
EOF
chmod 644 /etc/cron.d/horsesafe-backup

echo ""
echo "═══ PROVISIONING COMPLEET ═══"
echo ""
echo "VOLGENDE STAPPEN (NIET geautomatiseerd — eis review):"
echo ""
echo "  1. Review nginx-snippet:"
echo "       cat $NGINX_SNIPPETS_DIR/horsesafe.conf"
echo ""
echo "  2. Include in horsecloud55-server-block (één regel toevoegen):"
echo "       sudo sed -i '/server_name horsecloud55.ddns.net/a\\    include /etc/nginx/snippets/horsesafe.conf;' /etc/nginx/sites-enabled/horsecloud55"
echo "     OF handmatig editen."
echo ""
echo "  3. Valideer + reload:"
echo "       sudo nginx -t && sudo systemctl reload nginx"
echo ""
echo "  4. Start service + enable boot:"
echo "       sudo systemctl enable --now horsesafe"
echo "       sudo systemctl status horsesafe"
echo ""
echo "  5. Smoke-test:"
echo "       curl -fsS https://horsecloud55.ddns.net/HorseSafe/api/health"
echo "       bash $INSTALL_DIR/repo/scripts/post_deploy_smoke.sh"
echo ""
echo "  6. Eerste admin (na registratie via UI):"
echo "       sudo -u $SERVICE_USER $INSTALL_DIR/venv/bin/python -m backend.db.promote_admin <email>"
echo ""
