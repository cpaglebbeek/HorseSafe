---
date: 2026-05-21
session: newp_horsesafe
status: open
resume: "verder met HorseSafe Fase 1 — backend FastAPI-skeleton + frontend kdbxweb POC; eerst akkoord op GitHub-remote-creation + tarball-consume"
project: HorseSafe
ecosystem: iCt Horse Diensten
linked_actions: [HS-FASE-1-BACKEND, HS-FASE-2-FRONTEND, HS-GITHUB-REMOTE, HS-TARBALL-CONSUME, HS-SANITYCHECK]
---

# Sessie 2026-05-21 — HorseSafe newp Fase 2: repo-skeleton + ontwerp-documenten

## Trigger
- Gebruiker: `newp "HorseSafe". Saas passwordsafe, gelijk opensource keepass...`
- Inclusief uploads in ClaudeBug → KeePassXC 2.7.12 src tarball (11MB, 18-05)

## Specificaties (uit prompt)

| Eis | Vastlegging |
|---|---|
| SaaS password-safe op HorseCloud55 | ARCHITECTURE.md §3.1 |
| Eerst intern, later dienst | README.md status + URL-pad |
| Same mogelijkheden als open-source KeePass | DEPENDENCIES.md (kdbxweb) + CLAUDE.md (KDBX4-compat) |
| Inloggen via /HorseSafe op HC55 | ARCHITECTURE.md §3.2 nginx |
| Gebruikersdatabase + admin-pagina | ARCHITECTURE.md §2.2 SQLite + DESIGN.md S11 |
| Users maken zelf hun database | DESIGN.md S5/S6, v0.0.x = 1/user |
| Encryptie: pw / key / beide | DESIGN.md S6 + CLAUDE.md crypto-defaults |
| Server slaat pw + key NIET op | THREAT_MODEL.md zero-knowledge bewijs §3 |
| Import/export JSON/XLSX/CSV unprotected | DESIGN.md S9/S10 + PRINCIPLES.md P-UX-03 |
| Chrome/Edge plugin autocomplete (optioneel) | extension/README.md, v0.2.0 scope |
| Pw → clipboard, URL klikbaar, 10s wipe | DESIGN.md clipboard-strategie + BUGLIST-PRE-003 |
| MFA op pw + admin-pagina | PRINCIPLES.md P-AUTH-02 |
| MFA: Gmail magic-link + authenticator | ARCHITECTURE.md §2.3 + DEPENDENCIES.md externe services |

## /verifyrules — uitgevoerd

Naleefmatrix 8/15 ✅, 6 ⏳ (wachten op fase), 1 ⚠ (statusblok ingehaald). Rapport in conversatie-log.

## WhatIf — 22 punten, alle defaults akkoord

| Blok | Status |
|---|---|
| A (positionering: ecosysteem + privacy + URL-pad) | ✅ Meta_iCt_Horse_Diensten + PRIVATE → public bij v0.1 + HC55 intern → icthorse.nl |
| B (tech-stack: backend + frontend + storage) | ✅ Python FastAPI + kdbxweb + /opt/horsesafe |
| C (crypto: vaults/user + data-verlies + KDBX-compat + sync + sharing) | ✅ 1/user v0.0.x + verlies=permanent + KDBX4 + optimistic-lock + solo v0.0.x |
| D (auth: magic-link + TOTP + 2 lagen) | ✅ Hergebruik iCt_Horse stack + RFC 6238 + onafhankelijke lagen |
| E (UX: clipboard + extensie + export) | ✅ Best-effort v0.0.x + extensie v0.2.0 + reden+confirm+audit |
| F (admin/import/backup/browser/codenaam) | ✅ Zonder vault-toegang + KDBX/Bitwarden/CSV/XLSX + rsync + 4 browsers + Cryptografen-Rijndael |

## Bugcheck-resultaat

```
══ 2026-05-18 — 1 upload(s) ══
  [10:35:02] keepassxc-2.7.12-src.tar.xz
  upload-id: 103502_keepassxc-2.7.12-src.tar.xz_ecc9c5
    file: keepassxc-2.7.12-src.tar.xz (11M)
```

Status: **read-only, niet geconsumeerd**. Wacht op akkoord om te consumen + extracten naar `Meta_iCt_Horse_Diensten/sources/keepassxc-source/`.

## Wat is gedaan (deze sessie, Fase 2)

1. ✅ `/Users/christian/Documents/Gemini_Projects/HorseSafe/` aangemaakt + `git init`
2. ✅ Sub-dirs: backend/, frontend/, extension/, docs/, prompts/, specs/
3. ✅ Top-level docs: README.md, CLAUDE.md, ARCHITECTURE.md, DESIGN.md, PRINCIPLES.md, DEPENDENCIES.md, THREAT_MODEL.md, BUGLIST.md, ACTIONS.md, version.json, .gitignore
4. ✅ Sub-READMEs in backend/, frontend/, extension/, docs/, specs/, prompts/
5. ✅ Sessie-MD (dit bestand)

## Wat moet nog (na akkoord)

- ⏳ Meta_iCt_Horse_Diensten/PROJECTS.json + ECOSYSTEMS.md update (HorseSafe als project #4)
- ⏳ Meta_Master/STATUS.md + SHARED_INFRASTRUCTURE.md (poort 3997 reservering, NIET deploy)
- ⏳ Meta_Master/RESUME.md regenereren via update_resume.py
- ⏳ Memory: project_horsesafe.md + MEMORY.md pointer + claude_memory/ kopie
- ⏳ GitHub-remote `gh repo create cpaglebbeek/HorseSafe --private` + initial push (vraag akkoord)
- ⏳ Tarball `/bugcheck consume 103502_keepassxc-2.7.12-src.tar.xz_ecc9c5` + extract naar `Meta_iCt_Horse_Diensten/sources/keepassxc-source/` (vraag akkoord)
- ⏳ /sanitycheck draaien op skeleton (newp-fase N+1)

## Volgende sessie

Hervat-opdracht:
> `verder met HorseSafe Fase 1 — backend FastAPI-skeleton`

Of als deze sessie nog opent voor Fase 0-restwerk:
> `verder met HorseSafe GitHub-remote-creation + tarball-consume + sanitycheck`

## Linked actions (in `HorseSafe/ACTIONS.md`)

- HS-GITHUB-REMOTE
- HS-TARBALL-CONSUME
- HS-SANITYCHECK
- HS-FASE-1-BACKEND
- HS-FASE-2-FRONTEND
