# GDPR_COMPLIANCE.md — HorseSafe

> Compliance-matrix tegen GDPR. Cross-ref: `PRIVACY_STATEMENT.md`, `DPIA.md`, `SECURITY.md`.

## Rol-classificatie

| Klantgroep | Rol HorseSafe |
|---|---|
| Eindgebruiker individueel (consumer) | Verwerkingsverantwoordelijke (consumer kiest content) |
| Zakelijke klant (v1.0+) | Verwerker (klant = verwerkingsverantwoordelijke voor hun medewerkers) |

Door zero-knowledge is HorseSafe **technisch geen content-verwerker** — server kan inhoud niet zien. Wel: metadata-verwerker (vault-namen, grootte, tijdstempels).

## Art. 5 — Beginselen

| Beginsel | Hoe ingevuld |
|---|---|
| Rechtmatigheid | Art. 6(1)(b) contract — gebruiker accepteert ToS |
| Behoorlijkheid + transparantie | `PRIVACY_STATEMENT.md` |
| Doelbinding | Alleen voor wachtwoord-vault-functionaliteit |
| Minimale gegevens | Alleen e-mail + auth-data; geen profile |
| Juistheid | User kan e-mail wijzigen in settings |
| Opslagbeperking | 13 mnd audit, daarna anonimiseren |
| Integriteit + vertrouwelijkheid | Zero-knowledge + TLS + Argon2id |
| Verantwoording | DPIA + audit-log + dit document |

## Art. 6 — Rechtsgronden

| Verwerking | Rechtsgrond |
|---|---|
| Account-aanmaak + login | Art. 6(1)(b) noodzakelijk voor uitvoering overeenkomst |
| Vault-blob opslag | Art. 6(1)(b) |
| Audit-log | Art. 6(1)(f) gerechtvaardigd belang (security) |
| Failed-login-throttle | Art. 6(1)(f) |
| Backup-encryptie | Art. 32 verplichte beveiligingsmaatregel |

## Art. 13 — Informatie aan betrokkene

Verstrekt via `PRIVACY_STATEMENT.md` link in:
- Registratiepagina (S3)
- Footer van iedere pagina
- E-mail-template magic-link

## Art. 15-22 — Rechten

| Recht | Implementatie |
|---|---|
| Inzage (15) | Settings → "Download mijn data" (vault + audit-csv) |
| Rectificatie (16) | Settings → e-mail/pw aanpassen |
| Wissing (17) | Settings → "Verwijder mijn account" met re-auth + typ-bevestiging |
| Beperking (18) | Handmatig via security@icthorse.nl |
| Dataportabiliteit (20) | KDBX-export = open standaard |
| Bezwaar (21) | security@icthorse.nl |
| Geautomatiseerde besluitvorming (22) | n.v.t. — geen profiling |

## Art. 25 — Privacy by design + by default

- **By design:** zero-knowledge architectuur — server kan content niet zien
- **By default:** dark-theme + wachtwoord verborgen + clipboard-wipe + MFA verplicht voor vault

## Art. 28 — Verwerkersovereenkomst (DPA)

Voor zakelijke klanten v1.0+: DPA-template levert in:
- Verwerkersrol (alleen metadata + auth)
- Sub-verwerkers (Hetzner + Google Gmail)
- Subprocessing-notificatie 30 dagen vooruit
- Audit-recht klant
- Datalek-notificatie 24u

## Art. 30 — Verwerkingsregister

Zie `docs/verwerkingsregister.csv` (na live). Velden: doel, categorie, rechtsgrond, retentie, ontvangers, beveiliging.

## Art. 32 — Beveiliging

Zie `SECURITY.md`. Maatregelen:
- Pseudonimisering: niet relevant (zero-knowledge gaat verder)
- Versleuteling: AES-256 + Argon2id (vault) + TLS 1.3 + AES-GCM (TOTP-secret at-rest)
- Confidentiality, integrity, availability, resilience: backup + HSTS + HMAC + monitoring
- Periodieke evaluatie: jaarlijks pen-test

## Art. 33-34 — Datalek-procedure

Zie `RUNBOOK.md` §incident-response.

Toezichthouder-melding: AP via [meldloket](https://datalekken.autoriteitpersoonsgegevens.nl).
Betrokkene-notificatie: e-mail aan getroffenen + statuspagina.

**Wat is een datalek bij HorseSafe?**
- ❌ Vault-blob-leak alleen → géén datalek (ciphertext, niet leesbaar)
- ✅ Account-DB-leak (e-mail+pw-hashes) → datalek
- ✅ TOTP-secret-leak → datalek (account-laag-compromise mogelijk)
- ✅ JWT-secret-leak → datalek (session-hijack mogelijk)
- ✅ Backup-credentials leak → potentieel datalek

## Art. 35 — DPIA

Zie `DPIA.md`. Conclusie: verwerking valt **niet** onder DPIA-plicht (geen large-scale gevoelige data; zero-knowledge), maar DPIA-light uitgevoerd ter zorgvuldigheid.

## Art. 44-49 — Doorgifte derde landen

Geen doorgifte buiten EU. Hetzner (DE/FI) + Google (EU SCC).

## Compliance-audit-checklist

- [x] PRIVACY_STATEMENT aanwezig
- [x] DPIA-light uitgevoerd
- [x] Verwerkingsregister-skelet
- [ ] DPA-template (voor v1.0 B2B)
- [ ] Cookie-banner — niet nodig (geen tracking-cookies)
- [x] Datalek-procedure gedocumenteerd
- [ ] Bewaartermijnen geïmplementeerd in code (cron-job 13mnd-audit-anonim)
- [x] Rechten-van-betrokkene endpoints (UI flows benoemd)
- [x] Beveiligingsmaatregelen Art. 32 ingevuld
- [ ] Jaarlijkse review-cyclus ingepland

## Verschil met andere password-managers

| Aspect | HorseSafe | 1Password | LastPass | Bitwarden self-host |
|---|---|---|---|---|
| Server ziet vault-inhoud | ❌ nee | ❌ nee | ❌ nee | ❌ nee |
| Server ziet vault-metadata | ⚠️ ja (naam/grootte) | ⚠️ ja | ⚠️ ja | ⚠️ ja |
| EU-host default | ✅ | ❌ (US) | ❌ (US) | depends |
| Open-standaard format (KDBX) | ✅ | ❌ | ❌ | ❌ (eigen) |
| AGPL public source (gepland v0.1.0) | ✅ | ❌ | ❌ | ✅ |
