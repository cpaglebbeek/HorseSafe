# PRIVACY_STATEMENT.md — HorseSafe

> Privacyverklaring conform GDPR Art. 12-14. Finaal voor v0.1.0 (publieke dienst).

**Verwerker:** iCt Horse — KvK 96787112 — info@icthorse.nl
**Functionaris Gegevensbescherming:** n.v.t. (geen wettelijke verplichting, klein bedrijf)
**Versie:** 0.1.0 (finaal, publieke launch)
**Datum:** 2026-07-20

## 1. Welke gegevens verzamelen we?

| Gegeven | Doel | Rechtsgrond | Retentie |
|---|---|---|---|
| E-mailadres | Account-identificatie, magic-link MFA | Art. 6(1)(b) | Tot account-delete |
| Account-wachtwoord (hash) | Account-authenticatie | Art. 6(1)(b) | Tot delete; argon2id |
| TOTP-secret | Account-MFA | Art. 6(1)(b) | Tot delete; AES-GCM-at-rest |
| IP-adres + UA | Failed-login throttle + audit | Art. 6(1)(f) | 13 maanden (audit) of 24u (throttle) |
| Vault-blob (ciphertext) | Opslag versleutelde wachtwoorden | Art. 6(1)(b) | Tot delete door user |
| Vault-metadata (naam, grootte, etag) | Vault-management | Art. 6(1)(b) | Tot delete |
| Audit-log | Security, GDPR-bewijslast | Art. 6(1)(f) | 13 maanden, daarna geanonimiseerd |

## 2. Wat verzamelen we NIET?

- ❌ Vault-inhoud (entries, wachtwoorden, URLs) — server kan dit niet decrypteren
- ❌ Master-wachtwoord van vault — verlaat browser nooit
- ❌ Keyfile-inhoud — verlaat browser nooit
- ❌ Browser-fingerprint, locatie-data, tracking-cookies
- ❌ Telemetrie naar externe services

## 3. Wie heeft toegang?

| Partij | Toegang |
|---|---|
| Gebruiker (jij) | Volledige toegang tot eigen account + vault |
| HorseSafe-admin (Christian) | User-CRUD, server-stats, **GEEN vault-content** (zero-knowledge) |
| Verwerker iCt Horse | Server-infra-beheer, geen routine-data-toegang |
| Sub-verwerker Hetzner | Server-hosting (Helsinki, EU) — geen logische toegang |
| Sub-verwerker Google (Gmail) | Magic-link e-mail verzending — alleen e-mail-adres + token |

## 4. Doorgifte buiten EU?

**Nee.** Server staat in Helsinki (Hetzner, EU). Magic-link via Gmail (Google EU-Standard Contract Clauses).

## 5. Jouw rechten (GDPR Art. 15-22)

- **Inzage**: download eigen vault als KDBX + audit-log als CSV via settings-pagina
- **Rectificatie**: e-mail/pw aanpassen in settings
- **Wissing**: account-delete in settings → onmiddellijke unlink + hard-delete na 30 dagen
- **Beperking**: contact security@icthorse.nl
- **Dataportabiliteit**: KDBX-export werkt in elke KeePass-client (KeePassXC, KeePass2, AuthPass, ...)
- **Bezwaar**: contact security@icthorse.nl
- **Niet onderworpen aan geautomatiseerde besluitvorming**: geen profiling, geen AI-keuzes over jou

## 6. Beveiligingsmaatregelen (Art. 32)

Zie `SECURITY.md` + `THREAT_MODEL.md`. Samenvatting:
- Zero-knowledge encryptie (server kan vault-content niet lezen)
- TLS 1.3 + HSTS
- Argon2id KDF voor zowel account- als vault-wachtwoord
- MFA verplicht voor vault-toegang
- HC55-hardening (PrivateTmp, NoNewPrivileges, ProtectSystem strict)
- Nightly encrypted backups
- Append-only audit-log

## 7. Datalek-procedure

Datalek → e-mail-notificatie binnen 72u aan getroffenen + melding AP (Autoriteit Persoonsgegevens) indien hoog risico. Zie `RUNBOOK.md` §incident-response.

## 8. Klachten

- Direct: security@icthorse.nl
- Toezichthouder: [Autoriteit Persoonsgegevens](https://autoriteitpersoonsgegevens.nl)

## 9. Cookies

| Cookie | Doel | Persistentie |
|---|---|---|
| `horsesafe_session` | JWT-sessie (HttpOnly + Secure + SameSite=Strict) | 12u sliding |

Geen tracking-cookies. Geen analytics. Geen third-party cookies.

## 10. Wijzigingen aan deze verklaring

Bij wijzigingen: e-mail naar geregistreerde users. Wijzigingsgeschiedenis in `CHANGELOG.md`.
