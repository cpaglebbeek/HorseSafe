---
resume: false
status: closed
date: 2026-05-18
project: HorseSafe
version: 0.0.8-Rogaway
phase: post-MVP-feature
---

# HorseSafe v0.0.8-Rogaway — XLSX import + export

## Aanleiding

Gebruiker: *"ik mis nog wel export naar .xlsx formaat en import"*

XLSX was bij v0.0.5-Shamir (Fase 5 import/export) **bewust uitgesteld** omdat geen pure-JS-bibliotheek beschikbaar leek zonder build-step. Onderzoek tijdens deze sessie: **SheetJS Community 0.18.5** (oude npm-published versie, Apache-2.0) is een 245 KB UMD-bundle die `window.XLSX` exposeert — past in ons "no build-step, vanilla ES2022"-stramien (PRINCIPLES P-DEV-02).

## WhatIf (akkoord verleend)

A. Vendor SheetJS 0.18.5 → `frontend/vendor/sheetjs/xlsx.mini.min.js`
B. `parseXlsx(arrayBuffer)` + `buildXlsx(entries)` in `frontend/js/import-export.js`
C. CSP intact: alleen `<script src="…">`, geen inline-XLSX
D. UI: `xlsx`-optie in `import.html` + `export.html` dropdowns
E. Versie: v0.0.7-Bellare → **v0.0.8-Rogaway**
F. Deploy: lokaal test + commit + HC55 sync

Gebruiker: *"alles akkoord, bouw"*.

## Gerealiseerd

| # | Wat | Status |
|---|---|---|
| A | `frontend/vendor/sheetjs/xlsx.mini.min.js` (245 KB) + `LICENSE.APACHE-2.0` | ✅ |
| A | `frontend/vendor/README.md` — sheetjs-sectie | ✅ |
| B | `parseXlsx` + `buildXlsx` in `frontend/js/import-export.js` | ✅ |
| C | Headers case-insensitive `Title|Username|Password|URL|Notes`; `Title` + `Password` verplicht | ✅ |
| D | `import.html` dropdown + script-include | ✅ |
| D | `export.html` dropdown + script-include | ✅ |
| D | `page-import.js` xlsx-branch | ✅ |
| D | `page-export.js` xlsx-branch (MIME `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`) | ✅ |
| E | `backend/config.py` + `version.json` → 0.0.8-Rogaway | ✅ |
| E | `CHANGELOG.md` [0.0.8-Rogaway] section | ✅ |
| E | `ACTIONS.md` update | ✅ |
| F | git commit + push | pending |
| F | HC55 deploy (git pull + rsync) | pending |
| F | Live-verificatie export + reimport round-trip | pending |

## Architectuur-impact

- **Zero-knowledge ongewijzigd.** XLSX-parsing/building gebeurt client-side; server ziet alleen ciphertext (KDBX4) + audit-event (`{format: "xlsx", count: N}`).
- **CSP-compliant.** Geen inline-scripts; alleen `<script src="vendor/sheetjs/xlsx.mini.min.js">`. CSP regel `script-src 'self' 'wasm-unsafe-eval'` blijft intact.
- **Geen back-end mutaties.** Audit-import-endpoint accepteert generieke format-string; geen schema-migratie nodig.
- **Plaintext-export.** XLSX = klartekst, identieke audit + confirm-dialog als CSV/JSON.

## Codenaam

**Rogaway** — Phillip Rogaway, mede-bedenker AEAD-paradigma (OCB-mode, format-preserving encryption). Past in cryptografen-thema. Volgende beschikbare: Bernstein.

## Open / next

- HC55 deploy (zelfde flow als v0.0.7: `git pull` als root in `/opt/horsesafe/repo`, `chown -R horsesafe:horsesafe`, geen systemd-restart nodig want frontend-static).
- Live-roundtrip test: download `horsesafe-<ts>.xlsx`, open in Excel/LibreOffice, weer importeren in HorseSafe.
- v0.1.0-Massey blijft geparkeerd (publieke launch).
