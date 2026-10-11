# DEPLOY_HC55_LIVE.md — HorseSafe productie-deploy runbook

> v0.0.7-Bellare. Volgorde + commands voor live-deploy + rollback.

## Voorbereiding (eenmalig, server-side)

### Prerequisites verifiëren
- HorseCloud55 SSH-toegang: `ssh horsecloud55`
- nginx 1.24+ draait (gedeeld met andere services)
- Python 3.12 beschikbaar via apt
- Poort 3997 vrij: `ss -tlnp | grep 3997` → leeg
- Let's Encrypt cert dekt `icthorsecloud.nl`

### Eerste deploy

```bash
ssh horsecloud55

# 1. Run bootstrap (idempotent)
sudo bash <(curl -fsSL https://raw.githubusercontent.com/cpaglebbeek/HorseSafe/main/scripts/deploy_hc55.sh)

# 2. Review .env: vul HORSESAFE_SMTP_USER/PASSWORD/FROM in (Hostinger, uit ClaudeSecrets) en controleer
#    HORSESAFE_WEBAUTHN_RP_ID/ORIGIN tegen de host
sudo nano /opt/horsesafe/.env

# 3. Voeg nginx-include toe aan de horsecloud55-server-block
sudo nano /etc/nginx/sites-enabled/horsecloud55
# In de server { ... } block (na server_name):
#     include /etc/nginx/snippets/horsesafe.conf;

# 4. Valideer + reload nginx
sudo nginx -t && sudo systemctl reload nginx

# 5. Start service + enable boot
sudo systemctl enable --now horsesafe
sudo systemctl status horsesafe   # → active (running)
sudo journalctl -u horsesafe -n 20 --no-pager

# 6. Smoke-test
curl -fsS https://icthorsecloud.nl/HorseSafe/api/health
bash /opt/horsesafe/repo/scripts/post_deploy_smoke.sh

# 7. Eerste admin (Christian registreert via UI, daarna promote)
sudo -u horsesafe /opt/horsesafe/venv/bin/python -m backend.db.promote_admin christian@example.com
```

## Update-deploy (na git-push naar main) — sinds v0.2.1-Koblitz

**Altijd eerst een backup** van DB, vaults en `.env` (migraties zijn niet terug te draaien):

```bash
ssh icthorsecloud.nl
TS=$(date -u +%Y%m%d-%H%M%S); B=/opt/horsesafe/backups-predeploy; sudo mkdir -p $B
sudo sqlite3 /opt/horsesafe/db/horsesafe.db ".backup $B/horsesafe-$TS.db"
sudo tar -czf $B/vaults-$TS.tgz -C /opt/horsesafe vaults
sudo install -m 600 /opt/horsesafe/.env $B/env-$TS

cd /opt/horsesafe/repo
sudo -u horsesafe git pull
sudo -u horsesafe /opt/horsesafe/venv/bin/pip install -r backend/requirements.txt
sudo -u horsesafe /opt/horsesafe/venv/bin/python -m backend.db.migrate
# Alleen de productie-frontend (geen tests/, npm-bestanden, devserver.py, README.md)
sudo rsync -a --delete --chown=horsesafe:horsesafe \
  --exclude 'tests/' --exclude 'node_modules/' --exclude 'package.json' --exclude 'package-lock.json' \
  --exclude 'playwright.config.ts' --exclude 'devserver.py' --exclude 'README.md' --exclude 'test-results/' \
  frontend/ /opt/horsesafe/web/
sudo systemctl restart horsesafe
bash scripts/post_deploy_smoke.sh
```

Nieuwe `.env`-sleutels vergelijk je met `backend/.env.example` (sinds Koblitz o.a. `HORSESAFE_SMTP_*`,
`HORSESAFE_WEBAUTHN_RP_ID/ORIGIN/RP_NAME` en `HORSESAFE_TEST_ATTESTATION=false`). Geheimen komen uit
ClaudeSecrets en worden nooit in de repo of het transcript gezet.

Of: het bootstrap-script opnieuw draaien (idempotent, overschrijft `.env` niet; de backup blijft verplicht):
```bash
sudo bash /opt/horsesafe/repo/scripts/deploy_hc55.sh
sudo systemctl restart horsesafe
```

## Rollback

Code terugzetten is niet genoeg als er een migratie meekwam: zet dan ook de DB-backup terug.
```bash
sudo systemctl stop horsesafe
cd /opt/horsesafe/repo
sudo -u horsesafe git checkout <vorige-tag>
sudo -u horsesafe /opt/horsesafe/venv/bin/pip install -r backend/requirements.txt
sudo rsync -a --delete --chown=horsesafe:horsesafe \
  --exclude 'tests/' --exclude 'node_modules/' --exclude 'package.json' --exclude 'package-lock.json' \
  --exclude 'playwright.config.ts' --exclude 'devserver.py' --exclude 'README.md' --exclude 'test-results/' \
  frontend/ /opt/horsesafe/web/
# Alleen bij een migratie in de teruggedraaide versie:
sudo install -o horsesafe -g horsesafe -m 600 /opt/horsesafe/backups-predeploy/horsesafe-<TS>.db /opt/horsesafe/db/horsesafe.db
sudo systemctl start horsesafe
curl -fsS https://icthorsecloud.nl/HorseSafe/api/health
```

## Volledige uninstall (failsafe)

```bash
sudo systemctl stop horsesafe
sudo systemctl disable horsesafe
sudo rm /etc/systemd/system/horsesafe.service
sudo systemctl daemon-reload

sudo rm /etc/nginx/snippets/horsesafe.conf
# Verwijder de include-regel uit /etc/nginx/sites-enabled/horsecloud55 (handmatig)
sudo nginx -t && sudo systemctl reload nginx

sudo rm /etc/cron.d/horsesafe-backup

# Pas op — vault-data wordt verwijderd:
sudo rm -rf /opt/horsesafe
sudo userdel horsesafe
```

## Backup-config (eenmalig)

```bash
# Genereer SSH-key voor horsesafe-user (eenmalig)
sudo -u horsesafe ssh-keygen -t ed25519 -N "" -f /opt/horsesafe/.ssh/id_ed25519

# Voeg public-key toe aan Storagebox via web-interface of:
sudo -u horsesafe ssh-copy-id -i /opt/horsesafe/.ssh/id_ed25519 u123456@u123456.your-storagebox.de

# Configureer target in .env
sudo nano /opt/horsesafe/.env
# Voeg toe: HORSESAFE_BACKUP_TARGET=u123456@u123456.your-storagebox.de:/horsesafe

# Test handmatig
sudo -u horsesafe bash /opt/horsesafe/backup.sh
```

## Health-monitoring

- `GET /HorseSafe/api/health` — publiek, geen auth
- Response: `{"status":"ok","version":"...","db":"ok","vaults_dir":"ok","test_attestation":false}` — `test_attestation` moet in productie altijd `false` zijn
- Uptime-monitoring via bestaande Dashboard-stack (Dashboard-tile v0.0.8+)
- Backup-log: `/opt/horsesafe/logs/backup.log` — controleer dagelijks 03:01+

## Bekende limieten v0.0.7-Bellare

- **URL nog op `icthorsecloud.nl/HorseSafe/`** — `icthorse.nl/HorseSafe/` subdomain pas v0.1.0
- **Geen Dashboard-tile** — komt v0.0.8+
- **Geen externe pen-test** — pre-v0.1.0 publicatie
