---
date: 2026-05-21
session: horsesafe_fase6_adleman
status: done
resume: ""
project: HorseSafe
ecosystem: iCt Horse Diensten
parent_master: Meta_iCt_Horse_Diensten
linked_actions: []
---

# Sessie 2026-05-21 — HorseSafe Fase 6 v0.0.6-Adleman: Vault-sharing LIVE

## Trigger
Gebruiker akkoord op WhatIf Fase 6 ("1, alles akkoord") na 6 blokken / 16 punten.

## Wat is gebouwd

**Backend (+13 tests, 67/67 ✅):**
| Component | Files |
|---|---|
| Routes | `routes/shares.py` — 7 endpoints (keypair set/get/rewrap + pubkey-lookup + share create/inbox/sent/accept/decline) |
| Services | `services/share_service.py` — keypair-CRUD + share-CRUD + pubkey-lookup-by-email |
| Models | `models/share.py` (KeypairSet/Rewrap, ShareCreate, ShareInboxItem, PubkeyResponse) + `models/audit.py` +4 events + `models/admin.py` (has_keypair op MeResponse) |
| DB | `migrations/004_sharing.sql` (ALTER users + CREATE shares) + `schema.sql` v4 |
| Tests | `tests/test_sharing.py` — 13 tests |

**Frontend:**
| Component | Files |
|---|---|
| JS | `js/sharing.js` — ECDH-P256 (generateKeypair + unwrapPrivateKey + encryptForRecipient + decryptFromSender) |
| HTML | `shares.html` (S14 inbox+sent+decryptie-pane) |
| Updates | `settings.html` keypair-status + generate-form, `vault.html` Shares-knop + Deel-knop, `js/main.js` share-flow (prompt+lookup+encrypt+POST), `js/settings.js` keypair-generate-handler |

**Crypto-ontwerp:**
- ECDH P-256 (WebCrypto native — geen externe lib)
- Private-key at-rest: AES-GCM met PBKDF2-SHA256(vault-master-pw + user-id, 100k iter) → 256-bit AES-key
- Share-payload: ephemeral ECDH-keypair + AES-GCM-256 met shared-secret
- Server kent: pubkey (plain), encrypted_privkey (opaque), encrypted_payload (opaque)
- Server kent NIET: private-key, share-content, master-pw

## Verificatie

| Test | Resultaat |
|---|---|
| Backend pytest | **67/67 ✅** (van 54, +13 sharing-tests) |
| Ruff lint | ✅ |
| Black format | ✅ |
| Frontend e2e | **5/5 ✅** in 9.6s (oude blijven werken; nieuwe sharing-flow interactief — niet automatisch e2e) |
| Uvicorn smoke | health → `0.0.6-Adleman` |

## Belangrijke beslissingen

| Punt | Keuze | Reden |
|---|---|---|
| Algoritme | ECDH P-256 (WebCrypto native) | Curve25519 zou 50KB vendor-lib vereisen |
| Private-key wrap | AES-GCM + PBKDF2-SHA256-100k(master-pw+user-id) | Standaard pattern, vereist niet apart pw |
| Share-eenheid | Individuele entries per share-actie | Maximaal flexibel |
| Ontvanger | Per-email (één per share) | Multi-recipient = meerdere shares |
| Keypair-gen | Lazy via settings | Geen impact op bestaande users |
| Schema-strategie | schema.sql v4 + migration 004 | Voorkomt ALTER-failure in nieuwe DBs |
| Pw-change impact | /keypair/rewrap endpoint | Pubkey blijft, alleen wrap vernieuwt |

## Wat NIET gebouwd (per WhatIf-scope)

- Revocation → v0.0.7+
- Hele-vault sharing → v0.0.7+
- Multi-recipient → v0.0.7+
- Invite-via-email-naar-niet-bestaand-account → v0.0.7+
- Curve25519 (vendored tweetnacl) → v1.0-Bernstein
- Frontend playwright-test voor 2-user-share-flow → manueel testen (complex met 2 contexts)

## Volgende sessie

**Hervat-opdracht:**
> `verder met HorseSafe Fase 7 — productie-deploy HorseCloud55 (v0.0.7-Bellare)`

**Scope Fase 7:**
1. SHARED_INFRASTRUCTURE.md poort 3997 finaliseren (was reservering, nu echte deploy)
2. Nginx-snippet voor /HorseSafe/ + /HorseSafe/api/
3. systemd-unit `horsesafe.service`
4. `/opt/horsesafe/` bootstrap-script
5. Let's Encrypt TLS-cert (subdomain of /HorseSafe/-path)
6. Smoke-test post-deploy: health + register + roundtrip
7. Backup-script naar Hetzner-Storagebox
8. Eerste admin promoten via `python -m backend.db.promote_admin`

## Acties vastgelegd

- `HorseSafe/ACTIONS.md` — Fase 6 afgevinkt, Fase 7 omhoog
- `HorseSafe/CHANGELOG.md` — [0.0.6-Adleman] sectie compleet
- `HorseSafe/version.json` + `backend/config.py` — v0.0.6-Adleman
- Meta_Master `STATUS.md` + `RESUME.md` — volgt in commit-stap
- `claude_memory/project_horsesafe.md` + `MEMORY.md` — bijwerken
