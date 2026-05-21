# Openstaande Acties — HorseSafe

> Laatst bijgewerkt: 2026-05-21

## 🆕 2026-05-21 — newp Fase 2 → Fase 3+

Skeleton + ontwerp-documenten af. Volgende stappen vereisen akkoord:

- [ ] **GitHub-remote aanmaken** — `gh repo create cpaglebbeek/HorseSafe --private` + initial push (wacht op akkoord in deze sessie)
- [ ] **Tarball consume + extract** — `/bugcheck consume 103502_keepassxc-2.7.12-src.tar.xz_ecc9c5` → kopie in `specs/keepassxc-source/` als referentie (LEZEN-only, geen vendoring) (wacht op akkoord)
- [ ] **/sanitycheck draaien** op skeleton (newp-fase N+1, verplicht)
- [x] ~~**Fase 1 — Backend skeleton** — FastAPI-app met /auth/register, /auth/login, /vault, /vault/{id} GET+PUT (geen MFA nog, alleen auth-laag 1). Doel: lokaal draaien met `uvicorn`. Geen deploy.~~ ✅ 2026-05-21 — 15/15 tests, 96% coverage, smoke-test ok
- [ ] **Fase 2 — Frontend POC** — HTML+vanilla-JS met kdbxweb. Login + vault-unlock + 1 entry tonen. Geen UI-polish. (volgende — v0.0.2-Hellman)
- [ ] **Fase 3 — MFA integratie** — magic-link bridge naar iCt_Horse + TOTP setup-flow. (planning)
- [ ] **Fase 4 — Admin-pagina** — user-CRUD + stats. (planning)
- [ ] **Fase 5 — Import/export** — KDBX3/4, Bitwarden JSON, KeePass-CSV, XLSX. (planning)
- [ ] **Fase 6 — Browser-extensie** (v0.2.0) — MV3, autocomplete, échte clipboard-wipe. (planning, optioneel)
- [ ] **Fase 7 — Productie-deploy HC55** — nginx-snippet + systemd-unit + Let's Encrypt + SHARED_INFRASTRUCTURE.md update. (na fase 1-5 stabiel)

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
