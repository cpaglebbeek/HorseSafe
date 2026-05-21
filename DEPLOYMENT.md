# DEPLOYMENT.md — HorseSafe

> Productie-deploy op HorseCloud55. **Niet uitvoeren** vóór Fase 1-5 stabiel + sanitycheck groen + SHARED_INFRASTRUCTURE.md update.

## Doel-omgeving

| Item | Waarde |
|---|---|
| Host | `horsecloud55.ddns.net` (Hetzner CX21, Helsinki) |
| OS | Ubuntu 24.04 LTS |
| Python | 3.12 |
| Webserver | nginx 1.24 (gedeeld) |
| TLS | Let's Encrypt (gedeeld, certbot auto-renew) |
| Backend-poort | **3997** (gereserveerd) |
| Service-user | `horsesafe` (geen sudo) |
| Install-pad | `/opt/horsesafe/` |

## Pre-flight checks

1. **SHARED_INFRASTRUCTURE.md update** met poort 3997 + nginx-snippet
2. **Geen poort-conflict**: `ss -tlnp | grep 3997` → leeg
3. **DNS:** geen subdomain nodig — gebruikt main `/HorseSafe/` pad
4. **TLS:** bestaande wildcard / main cert dekt al
5. **Backup-storagebox:** vrije ruimte gecheckt

## Bootstrap

```bash
# als root
useradd -r -s /bin/false -d /opt/horsesafe horsesafe
mkdir -p /opt/horsesafe/{backend,web,db,vaults,logs,tmp}
chown -R horsesafe:horsesafe /opt/horsesafe
chmod 700 /opt/horsesafe/{db,vaults,logs,tmp}
chmod 755 /opt/horsesafe/{backend,web}

# Code-deploy
sudo -u horsesafe git clone https://github.com/cpaglebbeek/HorseSafe.git /opt/horsesafe/repo
sudo -u horsesafe ln -s /opt/horsesafe/repo/backend /opt/horsesafe/backend
sudo -u horsesafe ln -s /opt/horsesafe/repo/frontend /opt/horsesafe/web

# Python venv
sudo -u horsesafe python3.12 -m venv /opt/horsesafe/venv
sudo -u horsesafe /opt/horsesafe/venv/bin/pip install -r /opt/horsesafe/backend/requirements.txt

# DB-init
sudo -u horsesafe /opt/horsesafe/venv/bin/python -m backend.db.init

# .env (mode 600)
cat > /opt/horsesafe/.env <<EOF
HORSESAFE_JWT_SECRET=$(openssl rand -hex 32)
HORSESAFE_TOTP_ENCRYPTION_KEY=$(openssl rand -hex 32)
HORSESAFE_MAGIC_LINK_BRIDGE_URL=...
HORSESAFE_GMAIL_APP_PASSWORD=...
EOF
chmod 600 /opt/horsesafe/.env
chown horsesafe:horsesafe /opt/horsesafe/.env
```

## Systemd

`/etc/systemd/system/horsesafe.service`:
```ini
[Unit]
Description=HorseSafe password-safe backend
After=network.target

[Service]
Type=simple
User=horsesafe
Group=horsesafe
WorkingDirectory=/opt/horsesafe/backend
EnvironmentFile=/opt/horsesafe/.env
ExecStart=/opt/horsesafe/venv/bin/uvicorn app:app --host 127.0.0.1 --port 3997
Restart=on-failure
RestartSec=5

# Hardening
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/horsesafe/db /opt/horsesafe/vaults /opt/horsesafe/logs /opt/horsesafe/tmp
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now horsesafe
systemctl status horsesafe
```

## Nginx-snippet (append to shared config)

```nginx
# /etc/nginx/sites-enabled/horsecloud55 — APPEND ONLY, niet vervangen
location /HorseSafe/ {
    alias /opt/horsesafe/web/;
    try_files $uri $uri/ /HorseSafe/index.html;

    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
}

location /HorseSafe/api/ {
    proxy_pass http://127.0.0.1:3997/;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 60s;
    client_max_body_size 50M;
}
```

```bash
nginx -t && systemctl reload nginx
```

## Backup-protocol

`/opt/horsesafe/scripts/backup.sh` (cron daily 03:00):
```bash
#!/bin/bash
set -euo pipefail
TS=$(date +%Y%m%d-%H%M%S)
DEST="u123456@u123456.your-storagebox.de:/horsesafe/$TS"
rsync -avz --delete \
  /opt/horsesafe/db/ \
  /opt/horsesafe/vaults/ \
  "$DEST/"
# Audit-log archief
tar -cJf "/opt/horsesafe/logs/audit-$TS.tar.xz" /opt/horsesafe/logs/audit.log
# Retentie 30 dagen
ssh u123456@u123456.your-storagebox.de "ls /horsesafe/ | sort | head -n -30 | xargs -I{} rm -rf /horsesafe/{}"
```

## Restore-procedure

1. Stop service: `systemctl stop horsesafe`
2. Restore: `rsync -av $BACKUP/ /opt/horsesafe/`
3. `chown -R horsesafe:horsesafe /opt/horsesafe/{db,vaults}`
4. Start: `systemctl start horsesafe`
5. Verify: `curl https://horsecloud55.ddns.net/HorseSafe/api/health`

## Rollback

Symlinks (`/opt/horsesafe/{backend,web}` → `repo/`) maken rollback simpel:
```bash
cd /opt/horsesafe/repo
git checkout <previous-tag>
systemctl restart horsesafe
```

## Smoke-tests post-deploy

```bash
curl -fsS https://horsecloud55.ddns.net/HorseSafe/                # 200 + HTML
curl -fsS https://horsecloud55.ddns.net/HorseSafe/api/health      # 200 {"status":"ok"}
curl -fsS https://horsecloud55.ddns.net/HorseSafe/api/openapi.json | jq .info.version
```
