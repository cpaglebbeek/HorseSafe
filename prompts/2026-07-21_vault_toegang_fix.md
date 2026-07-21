---
date: 2026-07-21
session: vault_toegang_fix
status: closed
resume: "Geen — vault-toegang gefixt en live bewezen; eerstvolgende werkstap blijft public-go (LAUNCH_PREP.md §1 history-scrub)"
---

# Sessie 2026-07-21 — Vault-toegang fix (data-level, geen versie-bump)

## Aanleiding

Gebruiker: "ik kom nog niet in database met combinatie key en ww" — met opdracht
zelf te fixen en via Playwright + /loopuntilverified-principe te bewijzen.

## Bevindingen

1. **Server-data was al goed.** De live vault-blob (8471 B) opende gewoon met de
   huidige master-pw + keyfile (pykeepass én echte browser, 45 entries). De
   bevinding van 2026-07-20 ("live blob un-openable") gold de OUDE 6759 B-blob;
   die is sindsdien al vervangen.
2. **Oorzaak gebruikersprobleem** (meest waarschijnlijk): verkeerde lokale
   bestanden — in `~/Downloads` staan meerdere generaties keyfiles/DB's
   (`.bak-20260720-64hex-old`, unopenable `.bak-20260720`) en de credentials
   zijn 20-7 geroteerd. Oude keyfile of oud pw ⇒ "Verkeerd wachtwoord of
   verkeerde keyfile."
3. **HS-BUG-005 speelt niet meer voor deze DB**: browser-unlock werkt met
   zowel 64-hex als XML-keyfile (DB is AES-KDF; ook geen HS-BUG-001
   headless-hang).

## Uitgevoerd

- Live blob via app-API (login → GET backup → PUT met If-Match etag) vervangen
  door nieuwste merged DB uit ClaudeSecrets (8647 B, incl. HorseBoat-update
  2026-07-21 01:07). Re-download byte-identiek (sha256-match).
- Entry-set-diff oud↔nieuw: identieke 45 entries (zelfde UUIDs) — geen verlies.
  Oude blob was byte-identiek aan `~/Downloads/Database.kdbx` (backup bestond al;
  extra kopie in sessie-scratchpad).
- `~/Downloads/Database.kdbx` gesynct met canonieke ClaudeSecrets-versie (600).

## Verificatie (loopuntilverified, 2 iteraties → fixed point)

| # | Bewering | Bewijs |
|---|---|---|
| 1 | Merged DB opent lokaal met pw+keyfile (beide formaten) | pykeepass, 45 entries |
| 2 | Zonder keyfile faalt terecht | CredentialsError |
| 3 | Live PUT round-trip byte-identiek | sha256-match na re-download |
| 4 | Geen dataverlies | UUID+titel-diff leeg |
| 5 | Live browser-unlock werkt (beide keyfiles) | Playwright chromium, entry-count=45, screenshots |
| 6 | Alleen-pw geeft nette melding (HS-BUG-006 intact) | Playwright, "Verkeerd wachtwoord of verkeerde keyfile." |
| 7 | Account-login zonder MFA | API 200, mfa_required=false |

Rapport + screenshot gemaild naar cglebbeek@gmail.com via info@icthorse.nl
(Gmail-MCP OAuth nog `invalid_grant` sinds 20-7 → herstel: `gmail-mcp auth`).

## Root Cause Analysis (3 niveaus)

- **Functioneel:** gebruiker kon vault niet openen ondanks juiste server-data.
- **Technisch:** meerdere credential-/keyfile-generaties in `~/Downloads` +
  credential-rotatie 20-7; verkeerde combinatie ⇒ InvalidKey.
- **Architectonisch:** ontbreken van één afdwingbare canonieke bron client-side;
  canoniek = `ClaudeSecrets/secrets/horsesafe/` — Downloads is slechts mirror.

## Geen code gewijzigd

Data-level fix; versie blijft v0.1.0-Massey. Openstaand werk onveranderd:
public-go history-scrub (LAUNCH_PREP.md §1), Storagebox-key + Gmail App
Password voor backup/magic-link.
