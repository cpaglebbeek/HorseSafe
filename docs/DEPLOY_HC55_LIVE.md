# DEPLOY_HC55_LIVE.md — HorseSafe productie-deploy runbook

> v0.0.7-Bellare. Volgorde + commands voor live-deploy + rollback.

## Voorbereiding (eenmalig, server-side)

### Prerequisites verifiëren
- HorseCloud55 SSH-toegang: `ssh horsecloud55`
- nginx 1.24+ draait (gedeeld met andere services)
- Python 3.12 beschikbaar via apt
- Poort 3997 vrij: `ss -tlnp | grep 3997` → leeg
- Let's Encrypt cert dekt `horsecloud55.ddns.net`

### Eerste deploy

```bash
ssh horsecloud55

# 1. Run bootstrap (idempotent)
sudo bash <(curl -fsSL https://raw.githubusercontent.com/cpaglebbeek/HorseSafe/main/scripts/deploy_hc55.sh)

# 2. Review .env (vooral als magic-link gewenst is, vul Gmail-credentials in)
sudo nano /opt/horsesafe/.env
# → vul HORSESAFE_GMAIL_USER + HORSESAFE_GMAIL_APP_PASSWORD in indien magic-link nodig

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
curl -fsS https://horsecloud55.ddns.net/HorseSafe/api/health
bash /opt/horsesafe/repo/scripts/post_deploy_smoke.sh

# 7. Eerste admin (Christian registreert via UI, daarna promote)
sudo -u horsesafe /opt/horsesafe/venv/bin/python -m backend.db.promote_admin christian@example.com
```

## Update-deploy (na git-push naar main)

```bash
ssh horsecloud55
cd /opt/horsesafe/repo
sudo -u horsesafe git pull
sudo -u horsesafe /opt/horsesafe/venv/bin/pip install -r backend/requirements.txt
sudo -u horsesafe /opt/horsesafe/venv/bin/python -m backend.db.migrate
sudo rsync -a --delete frontend/ /opt/horsesafe/web/
sudo chown -R horsesafe:horsesafe /opt/horsesafe/web
sudo systemctl restart horsesafe
sudo systemctl status horsesafe
```

Of: gewoon de bootstrap-script opnieuw draaien (idempotent):
```bash
sudo bash /opt/horsesafe/repo/scripts/deploy_hc55.sh
sudo systemctl restart horsesafe
```

## Rollback

Bij failed deploy:
```bash
# 1. Stop service
sudo systemctl stop horsesafe

# 2. Git checkout vorige tag
cd /opt/horsesafe/repo
sudo -u horsesafe git checkout <previous-tag>
sudo -u horsesafe /opt/horsesafe/venv/bin/pip install -r backend/requirements.txt
sudo rsync -a --delete frontend/ /opt/horsesafe/web/

# 3. Start service
sudo systemctl start horsesafe
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
- Response: `{"status":"ok","version":"...","db":"ok","vaults_dir":"ok"}`
- Uptime-monitoring via bestaande Dashboard-stack (Dashboard-tile v0.0.8+)
- Backup-log: `/opt/horsesafe/logs/backup.log` — controleer dagelijks 03:01+

## Bekende limieten v0.0.7-Bellare

- **URL nog op `horsecloud55.ddns.net/HorseSafe/`** — `icthorse.nl/HorseSafe/` subdomain pas v0.1.0
- **Geen Dashboard-tile** — komt v0.0.8+
- **Geen externe pen-test** — pre-v0.1.0 publicatie
