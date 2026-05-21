---
date: 2026-05-22
session: horsesafe_fase7_bellare
status: open
resume: "verder met HorseSafe v0.1.0-Massey — public launch: icthorse.nl/HorseSafe/ subdomain + externe pen-test + open-source-beslissing AGPL-3.0 + Dashboard-tile + LinkedIn-aankondiging"
project: HorseSafe
ecosystem: iCt Horse Diensten
parent_master: Meta_iCt_Horse_Diensten
linked_actions: [HS-V010-PUBLIC-LAUNCH]
---

# Sessie 2026-05-22 — HorseSafe Fase 7 v0.0.7-Bellare: PRODUCTIE-DEPLOY LIVE

## Trigger
Gebruiker akkoord op WhatIf Fase 7 + optie (c) — AI provisioneert + dry-run, gebruiker approve't laatste 2 stappen.

## 🎉 LIVE OP `https://horsecloud55.ddns.net/HorseSafe/`

## Wat is uitgevoerd

**Repo-artefacten (Fase 7 pre-deploy, commit 6dd3f35):**
- `scripts/deploy_hc55.sh` (idempotent bootstrap)
- `scripts/horsesafe.service` (systemd-unit met full hardening)
- `scripts/nginx_snippet.conf` (appendable include + `auth_basic off`)
- `scripts/backup_to_storagebox.sh` (nightly rsync)
- `scripts/post_deploy_smoke.sh` (curl-roundtrip)
- `docs/DEPLOY_HC55_LIVE.md` (runbook)

**HC55 server-state (LIVE):**
- `/opt/horsesafe/` met `repo/`, `venv/`, `db/`, `vaults/`, `logs/`, `tmp/`, `web/`
- System-user `horsesafe`
- systemd `horsesafe.service` → **active, enabled** (PID 1659327)
- nginx-snippet `/etc/nginx/snippets/horsesafe.conf` + include in horsecloud-server-block
- `/etc/cron.d/horsesafe-backup` (skip indien target niet gezet)
- `.env` met random JWT-secret + TOTP-encryption-key + bcrypt-rounds=12

**Bug ontdekt + gefixed tijdens deploy:**
- Initial smoke-test gaf 401 — basic-auth realm "HorseCloud" actief op /HorseSafe/*
- Fix: `auth_basic off;` toegevoegd aan beide HorseSafe-location-blocks in nginx-snippet
- Commit `897e409` + scp naar HC55 + nginx reload
- Smoke-test daarna volledig groen

**Live-smoke-test resultaat:**
```
✓ /health    → {"status":"ok","version":"0.0.6-Adleman","db":"ok","vaults_dir":"ok"}
✓ POST /auth/register → user_id terug
✓ POST /auth/login → JWT-cookie + mfa_required=false
✓ GET /vault → []
✓ GET /auth/me → has_keypair=false
✓ POST /auth/logout → ok
```

## Belangrijke beslissingen

| Punt | Keuze | Reden |
|---|---|---|
| Deploy-flow | Optie (c): AI bootstrap + dry-run, jij approve't nginx-reload + service-start | Maximale review-moment vóór persistent mutation |
| URL | `horsecloud55.ddns.net/HorseSafe/` (intern) | Snel live, `icthorse.nl/HorseSafe/` pas v0.1.0 |
| `auth_basic off` | Verplicht voor /HorseSafe/* | HorseSafe heeft eigen JWT+MFA — dubbele-auth zou eindgebruikers blokkeren |
| Eerste admin | Niet automatisch | Bij echte first-user-registratie + handmatige promote |
| Backup-target | Cron actief maar HORSESAFE_BACKUP_TARGET leeg | SKIP-flow tot Storagebox-credentials ingesteld |
| Repo-private | PAT in /root/.git-credentials | Git clone via HTTPS+PAT, niet SSH-key |

## Operationele stappen (chronologisch)

1. ✅ Pre-check: Python 3.12, port 3997 vrij
2. ✅ Bootstrap manueel als root (PAT-clone) — deploy_hc55.sh inhoud gerepliceerd
3. ✅ Dry-run validatie: nginx -t, systemd-analyze, port-check
4. ⚠️ Initial nginx-include → 401 Unauthorized (basic-auth)
5. ✅ Snippet-fix: `auth_basic off;` + scp + reload nginx
6. ✅ systemctl enable --now horsesafe → active
7. ✅ Smoke-test live groen
8. ✅ Cleanup smoke-account
9. ✅ Doc-updates: SHARED_INFRASTRUCTURE.md poort 3997 LIVE, CHANGELOG, ACTIONS, version

## Service-status verify

```
● horsesafe.service - HorseSafe — zero-knowledge wachtwoord-vault SaaS backend
     Loaded: loaded (/etc/systemd/system/horsesafe.service; enabled; preset: enabled)
     Active: active (running) since Thu 2026-05-21 22:18:26 UTC
   Main PID: 1659327 (uvicorn)
      Tasks: 6 (limit: 18687)
     Memory: 40.5M (peak: 40.9M)
     CGroup: /system.slice/horsesafe.service
             └─1659327 /opt/horsesafe/venv/bin/python3.12 ... uvicorn backend.app:app --host 127.0.0.1 --port 3997
```

## Versie

v0.0.6-Adleman → **v0.0.7-Bellare**

## Wat NIET in v0.0.7 (volgt v0.1.0-Massey)

- icthorse.nl/HorseSafe/ subdomain (Hostinger DNS-config)
- Externe pen-test
- Open-source-beslissing (AGPL-3.0 voorgesteld)
- Dashboard-tile voor health
- Public launch + LinkedIn-aankondiging
- HORSESAFE_BACKUP_TARGET configureren (Storagebox SSH-key)
- HORSESAFE_GMAIL_USER/PASSWORD voor magic-link
- Eerste admin promoten (wacht op echte first-user)

## Volgende sessie

**Hervat-opdracht:**
> `verder met HorseSafe v0.1.0-Massey — public launch`

**Scope v0.1.0:**
1. Subdomain `icthorse.nl/HorseSafe/` (Hostinger DNS + nginx-proxy-config indien nodig)
2. Externe pen-test (interne checklist; mogelijk externe partner)
3. Open-source-beslissing: AGPL-3.0 publiek
4. Dashboard-tile op HC55 dashboard.icthorse.nl
5. Backup-target configureren (Storagebox)
6. LinkedIn-post draft + sitemap.xml-toevoeging
7. Public-ready privacy-statement + cookie-banner-check
8. Optionele: eerste betalende klant-pilot

## Acties vastgelegd

- HorseSafe/ACTIONS.md — Fase 7 afgevinkt, v0.1.0-Massey items omhoog
- HorseSafe/CHANGELOG.md — [0.0.7-Bellare] sectie compleet
- HorseSafe/version.json + backend/config.py — v0.0.7-Bellare
- Meta_Master/SHARED_INFRASTRUCTURE.md — poort 3997 LIVE
- Meta_Master/STATUS.md + RESUME.md — volgt in commit-stap
- claude_memory/project_horsesafe.md + MEMORY.md — Fase 7-status
