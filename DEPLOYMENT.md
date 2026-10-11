# DEPLOYMENT.md — HorseSafe

> Productie-deploy op HorseCloud55 (`icthorsecloud.nl`). LIVE sinds v0.0.7-Bellare; huidige stand v0.2.x-Koblitz.
> **Het uitvoerbare runbook is [`docs/DEPLOY_HC55_LIVE.md`](docs/DEPLOY_HC55_LIVE.md)** (eerste deploy, update-deploy met
> verplichte backup, rollback). Dit document beschrijft de doelomgeving en de achtergrond. Bijgewerkt 2026-10-11 (v0.2.1).

## Doel-omgeving

| Item | Waarde |
|---|---|
| Host | `icthorsecloud.nl` (Hetzner CX21, Helsinki) |
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

Gebruik `scripts/deploy_hc55.sh` (idempotent; zie runbook). Het script:

- maakt de service-user `horsesafe` en `/opt/horsesafe/{db,vaults,logs,tmp,web}` aan;
- kloont/pullt de repo naar `/opt/horsesafe/repo` en installeert de venv in `/opt/horsesafe/venv`;
- genereert bij de eerste keer `/opt/horsesafe/.env` (mode 600) met willekeurige JWT- en TOTP-sleutels;
- draait `backend.db.init` + `backend.db.migrate`;
- **kopieert** (rsync, geen symlink) alleen de productie-frontend naar `/opt/horsesafe/web/` — zonder
  `tests/`, `node_modules/`, `package*.json`, `playwright.config.ts`, `devserver.py` en `README.md`;
- zet nginx-snippet, systemd-unit en backup-cron klaar (reload/start doe je zelf na review).

Verplichte `.env`-sleutels naast de gegenereerde: zie `backend/.env.example` — vanaf v0.2.0-Koblitz
`HORSESAFE_SMTP_HOST/PORT/USER/PASSWORD/FROM/STARTTLS` (Hostinger 587, From = SMTP-gebruiker) en
`HORSESAFE_WEBAUTHN_RP_ID/ORIGIN/RP_NAME` (= `icthorsecloud.nl`). `HORSESAFE_TEST_ATTESTATION` staat in
productie altijd op `false`.

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
5. Verify: `curl https://icthorsecloud.nl/HorseSafe/api/health`

## Rollback

Zie runbook §Rollback. Let op: `web/` is een kopie (geen symlink) en migraties zijn niet omkeerbaar —
bij een migratie in de teruggedraaide versie ook de DB-backup uit `/opt/horsesafe/backups-predeploy/`
terugzetten.

## Smoke-tests post-deploy

```bash
curl -fsS https://icthorsecloud.nl/HorseSafe/                # 200 + HTML
curl -fsS https://icthorsecloud.nl/HorseSafe/api/health      # 200 {"status":"ok"}
curl -sS -o /dev/null -w '%{http_code}' https://icthorsecloud.nl/HorseSafe/api/openapi.json  # 404: docs dicht in productie
bash scripts/post_deploy_smoke.sh                             # volledige smoke
```
