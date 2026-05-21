# CLAUDE.md — HorseSafe

> Repo-specifieke regels voor AI-agenten (Claude / Codex / Gemini). Globale regels staan in `/Users/christian/CLAUDE.md` + `/Users/christian/Documents/Gemini_Projects/CLAUDE.md`. Ecosysteem-regels staan in `Meta_iCt_Horse_Diensten/CLAUDE.md`.

## Productpositie

HorseSafe is een **iCt Horse-dienst**, sub-master `Meta_iCt_Horse_Diensten`, broertje van iCtHorseAssist + VeiligDelen + iCtHorseSupport. **Zero-knowledge wachtwoord-vault.**

## Cardinale regels

1. **Zero-knowledge is heilig.** Server ziet master-pw of keyfile NOOIT. Elke commit die dit principe schendt = **rood** (debug_protocol). Master-pw, keyfile en derived key staan uitsluitend in geheugen van de browser-tab.
2. **KDBX4-compat is harde eis.** Export = native KDBX4 → opent in KeePassXC-desktop. Geen propriëtair format als enige fallback.
3. **Versie-bump bij elke functionele wijziging.** Conform `feedback_randomringtone_versioning.md` (alle projecten): minimaal +0.0.1 per bugfix, +0.1.0 bij design-impact, +1.0.0 bij architectuur-impact.
4. **Codenamen uit Cryptografen-thema.** Rijndael (Daemen+Rijmen) is v0.0.x. Voorbeelden: Diffie, Hellman, Rivest, Shamir, Adleman, Bellare, Rogaway, Bernstein. (NB: Lampson + Diffie zijn al gebruikt door iCtHorseSupport — overlap toegestaan binnen iCt Horse Diensten-thema-cluster, mits unieke versie.)
5. **Shared infra:** vóór elke nginx- of poort-wijziging eerst `Meta_Master/SHARED_INFRASTRUCTURE.md` raadplegen. Gereserveerde poort: **3997**.
6. **WhatIf vóór bouw** conform `feedback_whatif_protocol.md`: plan + impact + akkoord vóór destructieve of architecturele actie.
7. **Versleutelings-test in CI:** elke build moet bewijzen dat een KDBX4-blob na server-round-trip identiek terugkomt en in KeePassXC-desktop opent. Anders = build geblokt.

## Cryptografische defaults

| Item | Default |
|---|---|
| KDBX-formaat | 4 (header + inner stream) |
| Buiten-cipher | AES-256-CBC + HMAC-SHA-256 (KeePassXC-standaard) |
| Inner-cipher | ChaCha20 |
| KDF | Argon2id, t=12, m=128 MiB, p=2 (KeePassXC-default) |
| Keyfile-formaat | KeePassXC 2.x XML (sha-256 hash) |
| Master-key-derivatie | composiet: HMAC-SHA-256(pw-hash ‖ keyfile-hash) |

**Alle waardes komen uit KeePassXC 2.7.12 default — zie `Meta_iCt_Horse_Diensten/sources/keepassxc-2.7.12-src.tar.xz` na consume.**

## Code-conventies

- **Backend:** Python 3.12 + FastAPI, Pydantic v2, async-first, type-hints verplicht
- **Frontend:** ES2022 modules, geen build-step (vanilla); `kdbxweb` via ESM-import
- **Tests:** pytest + playwright (e2e); doel-coverage 80% backend, 60% frontend
- **Lint:** ruff + black voor backend; eslint + prettier voor frontend
- **Audit-trail:** elke import + export = log-entry met user-id + tijdstip + formaat + reden (alleen plaintext-formaten vereisen reden)

## Sessie-protocol

- **Sessie-MD's in `prompts/YYYY-MM-DD_<slug>.md`** conform Meta_Master CLAUDE.md
- **ACTIONS.md** bijwerken bij elke sessie met nieuwe taken
- **BUGLIST.md** bijhouden conform `feedback_debug_buglist_protocol.md`
- **"over en uit"** triggert volledig protocol uit globale CLAUDE.md

## Auto git commit + push

Conform globale Gemini_Projects/CLAUDE.md: na elke wijziging `git commit + push`.

## Niet-onderhandelbare grenzen

- ❌ Server-side pw/keyfile-opslag (zelfs encrypted) → verbreekt zero-knowledge
- ❌ Server-side decryptie → verbreekt zero-knowledge
- ❌ "Recovery" via server-known seed → verbreekt zero-knowledge
- ❌ Plaintext-export zonder confirm-dialog + audit-log + reden
- ❌ Build zonder versie-bump
- ❌ Nginx-edit zonder SHARED_INFRASTRUCTURE.md te raadplegen
