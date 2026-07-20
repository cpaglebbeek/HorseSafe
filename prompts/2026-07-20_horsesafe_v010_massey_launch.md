---
date: 2026-07-20
repo: HorseSafe
status: open
resume: "verder met HorseSafe public-go: (1) git-history-scrub uitvoeren per LAUNCH_PREP.md §1 (plaintext [REDACTED-PREFIX]*-wachtwoorden weg via git-filter-repo + force-push), (2) daarna repo PUBLIC + AGPL-3.0 (§2), (3) sitemap + LinkedIn (§3-4). Los daarvan geblokkeerd op user-credentials: Storagebox SSH-key (backup) + Gmail App Password (magic-link)."
---

# Sessie 2026-07-20 — HorseSafe v0.1.0-Massey public launch (deels; public-go geblokkeerd)

**Agent:** Claude Fable 5
**Repo:** HorseSafe (`cpaglebbeek/HorseSafe`, branch `main`, PRIVATE)
**Overgenomen resume:** #182/#183 — "verder met HorseSafe v0.1.0-Massey public launch"
**Commits:** `939fdf9` (code+hardening) → `<launch-prep>` (docs)

---

## Opdracht

Geparkeerde Massey-launch overnemen. User-keuzes vooraf: **volledige Massey-scope** +
**repo public + AGPL na schone secret-scan**.

## Uitgevoerd

### 1. icthorse.nl/HorseSafe/ LIVE ✅
- Hostinger SSH (key uit ClaudeSecrets/hostinger), subdir-`.htaccess` in
  `domains/icthorse.nl/public_html/{HorseSafe,horsesafe}/` → 302 naar
  `horsecloud55.ddns.net/HorseSafe/`. Zelfde geïsoleerde patroon als StaffKennis; WP-root ongemoeid.
- E2e: `icthorse.nl/HorseSafe/api/health` → 200 `0.1.0-Massey`.

### 2. Pen-test-checklist v0.1.0 ✅ (1 fix)
- 8 punten LIVE geprobed. Bevinding: **OpenAPI-docs publiek** (`/api/docs`, `/openapi.json`,
  `/redoc` = 200) → info-disclosure voor zero-knowledge dienst.
- **Fix:** nieuwe setting `docs_enabled` (default `false`) in `config.py`; `app.py` zet
  `docs_url/redoc_url/openapi_url=None`. Env `HORSESAFE_DOCS_ENABLED=false` op HC55.
  Na deploy: `/api/docs` → 404. (`/HorseSafe/docs` = 200 is enkel de SPA-fallback index.html.)
- Rest groen: HSTS+CSP+X-Frame, auth-bypass 401, path-traversal 401, SQLi→422 (Pydantic),
  rate-limit 429 na 4, geen CORS, geen Set-Cookie op fail. Tabel in SECURITY.md.

### 3. Versie + deploy ✅
- `0.0.10-Goldwasser` → `0.1.0-Massey` (config.py + version.json + codename-lijst).
- pytest **68/68** (nieuwe `test_openapi_docs_disabled_by_default`; health-version-assert generiek).
- Deploy: `git pull` in `/opt/horsesafe/repo` (`939fdf9`) + restart. Health = 0.1.0-Massey.

### 4. Privacy + launch-content ✅
- PRIVACY_STATEMENT.md 0.0.0-skeleton → 0.1.0 finaal.
- LAUNCH_PREP.md: scrub-procedure + LinkedIn-draft + sitemap-entry + AGPL-public-stappen.

## GEBLOKKEERD

### Public-go — secret-scan NIET schoon 🚫 (headline)
- `git grep` over volledige history vond **plaintext-wachtwoorden**: `[REDACTED-ACCOUNT-PW]`
  (account-pw) + `[REDACTED-VAULT-PW]` (oude vault-master) in `ACTIONS.md`, `CHANGELOG.md`,
  `prompts/2026-06-05_*.md`.
- Live vault-master zelf staat NIET in history (geverifieerd tegen ClaudeSecrets), maar de
  strings onthullen het patroon `[REDACTED-PREFIX]<Woord>!` dat elders live is (o.a. `[REDACTED-LIVE-PW]`).
- Per afspraak "alleen bij 100% schoon" → **public-go gestopt, repo blijft PRIVATE**.
- Scrub-procedure (git-filter-repo + force-push) klaargezet in LAUNCH_PREP.md §1.

### Backup + magic-link — geen credentials 🚫
- Storagebox SSH-key + Gmail App Password ontbreken in ClaudeSecrets én op HC55.
  `backup.sh` skipt netjes bij lege target; magic-link disabled (MFA blijft via TOTP).

### Dashboard health-tile — buiten scope
- Dashboard-repo doet repo-sync-status, geen live health-probing → nieuwe feature, uitgesteld.

## Openstaand (zie ACTIONS.md + LAUNCH_PREP.md)
1. git-history-scrub → public + AGPL (na user-akkoord op force-push/history-rewrite)
2. Storagebox-credentials aanleveren → backup activeren
3. Gmail App Password aanleveren → magic-link activeren
4. Sitemap + LinkedIn na public
5. Dashboard health-tile (los feature-verzoek)
