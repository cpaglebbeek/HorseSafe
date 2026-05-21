# Openstaande Acties — HorseSafe

> Laatst bijgewerkt: 2026-05-21

## 🆕 2026-05-21 — newp Fase 2 → Fase 3+

Skeleton + ontwerp-documenten af. Volgende stappen vereisen akkoord:

- [ ] **GitHub-remote aanmaken** — `gh repo create cpaglebbeek/HorseSafe --private` + initial push (wacht op akkoord in deze sessie)
- [ ] **Tarball consume + extract** — `/bugcheck consume 103502_keepassxc-2.7.12-src.tar.xz_ecc9c5` → kopie in `specs/keepassxc-source/` als referentie (LEZEN-only, geen vendoring) (wacht op akkoord)
- [ ] **/sanitycheck draaien** op skeleton (newp-fase N+1, verplicht)
- [x] ~~**Fase 1 — Backend skeleton** — FastAPI-app met /auth/register, /auth/login, /vault, /vault/{id} GET+PUT (geen MFA nog, alleen auth-laag 1). Doel: lokaal draaien met `uvicorn`. Geen deploy.~~ ✅ 2026-05-21 — 15/15 tests, 96% coverage, smoke-test ok
- [x] ~~**Fase 2 — Frontend POC** — HTML+vanilla-JS met kdbxweb. Login + vault-unlock + 1 entry tonen. Geen UI-polish.~~ ✅ 2026-05-21 — kdbxweb+argon2 vendored, S1/S2/S6/S7 schermen LIVE, e2e playwright 2/2 groen, full roundtrip (registreer + login + vault-create in browser + entry + pw-toggle + lock + reopen) werkt
- [x] ~~**Fase 3 — MFA integratie** — magic-link bridge naar iCt_Horse + TOTP setup-flow~~ ✅ 2026-05-21 — TOTP RFC 6238 + AES-GCM-encrypted-at-rest secret + Gmail SMTP magic-link + vault-MFA-gate; backend 25/25 pytest + frontend 3/3 playwright; qrcode-generator vendored; settings-page + mfa-challenge-page LIVE
- [x] ~~**Fase 4 — Admin-pagina** — user-CRUD + storage-stats + audit-log-viewer + MFA-backup-codes + admin-rescue~~ ✅ 2026-05-21 — admin.html (S11) + backup-codes.html (S13) + 6 admin-endpoints + 3 auth-endpoints (/me, backup-codes/{generate,verify}) + bcrypt-hashed backup-codes (single-use) + DB-migrate runner + CLI promote-admin; backend 40/40 pytest + frontend 5/5 playwright
- [x] ~~**Fase 5 — Import/export + KDBX-roundtrip-oracle**~~ ✅ 2026-05-21 — KDBX3/4 + Bitwarden JSON + KeePass-CSV import/export (XLSX uitgesteld v0.0.7+) + admin-CSV-audit-export + account-pw-change + KeePassXC-CLI oracle in CI; backend 54/54 pytest + frontend 5/5 playwright; client-side parse (zero-knowledge intact); BUG-001 definitief deferred naar v1.0-Bernstein
- [x] ~~**Fase 6 — Vault-sharing**~~ ✅ 2026-05-21 — ECDH-P256 (WebCrypto native) + AES-GCM-wrapped private-key + per-entry share + inbox/decline/accept; backend 67/67 pytest + 4 nieuwe audit-events + DB-migratie 004; frontend shares.html + js/sharing.js + keypair-gen in settings + Deel-knop in vault; zero-knowledge intact (server kent alleen pubkeys + opaque ciphertexts)
- [ ] **Browser-extensie** (v0.2.0+) — MV3, autocomplete, échte clipboard-wipe (uitgesteld, optioneel)
- [ ] **Fase 7 — Productie-deploy HC55** — nginx-snippet + systemd-unit + Let's Encrypt + SHARED_INFRASTRUCTURE.md update (volgende — v0.0.7-Bellare)

## Niet-blokkerende vervolgvragen (WhatIf-uitloop)

- [ ] **Wachtwoord-policy globaal config** — wil je een per-server-policy (min-lengte 12, ...) afdwingen voor account-pw? Of laissez-faire? (open)
- [ ] **GDPR DPIA** — voor latere dienst-aanbieding aan zakelijke klanten: DPIA-template opstellen wanneer eerste betalende klant? (uitstellen tot v0.1.0)
- [ ] **Open-source moment** — bij welke versie public maken? Default-voorstel was v0.1.0 zodra MFA + KDBX-compat bewezen werkt. Akkoord blijft? (open)
- [ ] **Codenaam v0.0.1** — Rijndael past bij Daemen+Rijmen (AES-ontwerpers). Akkoord? Of liever start met Diffie? (default: Rijndael)
- [ ] **CI-platform** — GitHub Actions voor tests (gratis voor private repo's tot 2000 min/maand)? (default: ja)
- [ ] **Disaster-recovery user-flow** — moet user expliciet aangemoedigd worden om elke 30 dagen een KDBX-export te downloaden? E-mail-reminder? (open)

## Backlog (lange termijn)

- [ ] **Shared vaults** (v0.2+) — re-encryptie per ontvanger
- [ ] **Offline-modus** (v0.1+) — ServiceWorker-cache laatste blob
- [ ] **FIDO2/WebAuthn** (v0.3+) — hardware-token MFA-laag
- [ ] **Mobile-app** (v1.0?) — native Android (Kotlin Compose) wrapper
- [ ] **CLI-tool** — `horsesafe-cli` voor scripts (KeePassXC-cli equivalent)
- [ ] **Audit-export** — user kan eigen audit-log downloaden
- [ ] **Vault-templates** — pre-defined categorieën (Email, Banking, Social, Work) voor new-vault-bootstrap
- [ ] **TOTP-codes in entries** — entry kan TOTP-secret bevatten → preview-code in UI (KeePassXC-feature)
- [ ] **Yubico OTP / OnlyKey** — als extra MFA-optie

## Afgerond

- [x] ~~Repo-skeleton + ontwerp-documenten~~ ✅ 2026-05-21
- [x] ~~Naamkeuze HorseSafe + codenaam-thema Cryptografen + v0.0.0-Rijndael~~ ✅ 2026-05-21
- [x] ~~WhatIf-akkoord op 22 punten (alle defaults)~~ ✅ 2026-05-21
- [x] ~~GitHub-remote `cpaglebbeek/HorseSafe` (PRIVATE) aanmaken + initial push~~ ✅ 2026-05-21
- [x] ~~Tarball-consume + extract naar `Meta_iCt_Horse_Diensten/sources/keepassxc-source/`~~ ✅ 2026-05-21
- [x] ~~`/sanitycheck` op skeleton (newp-fase N+1)~~ ✅ 2026-05-21 (PASS ~95%)
- [x] ~~P2: `docs/screens/` + `.github/workflows/ci.yml` + `Meta_Master/TODO_VASTLEGGING.md` entry~~ ✅ 2026-05-21
- [x] ~~**Fase 1 — Backend FastAPI-skeleton v0.0.1-Diffie**~~ ✅ 2026-05-21 (15/15 tests groen, 96% coverage, smoke-test ok)
