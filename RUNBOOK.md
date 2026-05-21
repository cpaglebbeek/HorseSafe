# RUNBOOK.md — HorseSafe operationele procedures

> Cross-ref: `DEPLOYMENT.md` (eerste deploy), `MONITORING.md` (alerts).

## Standaard-operaties

### Service-status
```bash
ssh horsecloud55 'systemctl status horsesafe'
ssh horsecloud55 'journalctl -u horsesafe -n 50 --no-pager'
```

### Restart
```bash
ssh horsecloud55 'systemctl restart horsesafe'
# Verify
curl -fsS https://horsecloud55.ddns.net/HorseSafe/api/health
```

### Code-update
```bash
ssh horsecloud55 'cd /opt/horsesafe/repo && sudo -u horsesafe git pull'
ssh horsecloud55 'cd /opt/horsesafe/repo/backend && sudo -u horsesafe /opt/horsesafe/venv/bin/pip install -r requirements.txt'
ssh horsecloud55 'systemctl restart horsesafe'
```

### Migrations
```bash
ssh horsecloud55 'cd /opt/horsesafe/repo && sudo -u horsesafe /opt/horsesafe/venv/bin/python -m backend.db.migrate'
```

### Backup-restore (single vault)
```bash
# 1. Identify vault-uuid van user
sqlite3 /opt/horsesafe/db/horsesafe.db "SELECT id, name FROM vaults WHERE user_id='<u>';"

# 2. Restore vanaf storagebox
rsync -av u123456@u123456.your-storagebox.de:/horsesafe/<datum>/vaults/<u>/<v>.kdbx /opt/horsesafe/vaults/<u>/<v>.kdbx

# 3. Recompute etag
NEW_ETAG=$(sha256sum /opt/horsesafe/vaults/<u>/<v>.kdbx | awk '{print $1}')
sqlite3 /opt/horsesafe/db/horsesafe.db "UPDATE vaults SET etag='$NEW_ETAG', size_bytes=$(stat -c%s ...) WHERE id='<v>';"
```

### TLS-cert renewal (handmatig fallback)
```bash
certbot renew --dry-run
certbot renew --force-renewal
systemctl reload nginx
```

## Incidenten

### Service-down

1. **Check status:** `systemctl status horsesafe`
2. **Check logs:** `journalctl -u horsesafe -n 200 --no-pager`
3. **Check disk:** `df -h /opt/horsesafe`
4. **Check DB:** `sqlite3 /opt/horsesafe/db/horsesafe.db ".tables"` → moet users, vaults, audit_log, ... tonen
5. **Restart:** `systemctl restart horsesafe`
6. **Als persistent:** rollback naar vorige git-tag, restart, monitor

### Failed-login-spike (mogelijk brute-force)

1. **Identify IP:** `sqlite3 .../horsesafe.db "SELECT ip, COUNT(*) FROM failed_logins WHERE ts > $(date -d '1 hour ago' +%s) GROUP BY ip ORDER BY 2 DESC LIMIT 10;"`
2. **Tijdelijke ban:** `iptables -A INPUT -s <ip> -j DROP`
3. **Audit:** check of legitieme user-fouten of attack
4. **Notify:** e-mail naar getroffen account-eigenaar als brute-force op specifiek account

### Vault-corruption (user-report)

1. **Backup eerst:** `cp /opt/horsesafe/vaults/<u>/<v>.kdbx /tmp/<v>-suspect.kdbx`
2. **Check integriteit:** kdbxweb-cli kan blob valideren zonder decryptie (header + HMAC-check)
3. **Restore vanaf storagebox** indien echte corruptie
4. **Audit-trail:** check `audit_log` voor recente `vault_update` events op deze vault — wie/wanneer

### Datalek-procedure (Art. 33-34 GDPR)

**Trigger:** server-compromise, DB-leak, of TLS-MitM-evidence.

1. **T+0**: isolate server (firewall block all except SSH from beheer-IP)
2. **T+0**: notify Christian (this is YOU) + Hofstra (legal-advisor)
3. **T+0 - T+4u**: scope-bepaling
   - Welke users? (alle of subset?)
   - Welke data? (account-DB? TOTP-secrets? vault-blobs?)
   - Was vault-decryptie mogelijk? (= vault-content gelekt of alleen ciphertext?)
4. **T+24u**: melding AP via [meldloket](https://datalekken.autoriteitpersoonsgegevens.nl) — verplicht binnen 72u
5. **T+48u**: e-mail naar getroffen users (template `docs/templates/datalek-notify.txt`)
6. **T+72u**: status-pagina update
7. **Post-mortem**: rapport in `docs/incidents/<datum>.md`; root-cause + maatregelen

**Wat is GEEN datalek:**
- Vault-blob alleen → ciphertext, niet leesbaar zonder master-key → geen "persoonsgegeven-leak" in GDPR-zin
- Audit-log met user_id's geanonimiseerd → niet meer persoonsgegeven

### Magic-link bridge down

1. **Detect:** alerts uit iCt_Horse-side
2. **Workaround:** TOTP-only login geforceerd via banner op login-pagina
3. **Communicate:** statuspagina + e-mail
4. **Fix:** zie iCt_Horse magic-link bridge runbook

## Onderhouds-vensters

- **Geplande deploys:** zaterdag 06:00-07:00 CET (laagste verkeer)
- **Security-patches Ubuntu:** maandelijks 1e zondag 04:00
- **Audit-log-rotatie:** dagelijks 03:00 (logrotate)
- **Audit-anonimisering 13mnd:** weekly cron zondag 04:00

## Contacten

- **Operationeel:** Christian Glebbeek — cglebbeek@gmail.com
- **Security:** security@icthorse.nl (PGP)
- **Hosting:** Hetzner support — ticket via robot.your-server.de
- **Juridisch:** mr. Hofstra (advocaat)
- **AP-melding:** [datalekken.autoriteitpersoonsgegevens.nl](https://datalekken.autoriteitpersoonsgegevens.nl)
