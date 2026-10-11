# DPIA.md — HorseSafe Data Protection Impact Assessment

> DPIA-light. Onder GDPR Art. 35 lid 3 niet verplicht (geen large-scale of bijzondere categorieën), maar uitgevoerd ter zorgvuldigheid.

**Datum:** 2026-05-21 (herbeoordeeld 2026-10-10 voor v0.2.0-Koblitz, zie §9)
**Versie:** v0.0.0 → v0.2.0-Koblitz
**Verantwoordelijke:** Christian Glebbeek (iCt Horse)
**Reviewer:** n.v.t. (single-stakeholder; revisie bij v0.1.0 publiek met externe input)

## 1. Doel van de verwerking

HorseSafe is een SaaS wachtwoord-vault waarmee individuele gebruikers + later organisaties hun credentials veilig kunnen opslaan + ophalen.

## 2. Aard van de gegevens

| Categorie | Gevoeligheid |
|---|---|
| E-mailadres | Gewoon persoonsgegeven |
| Account-pw-hash | Geheim (gehashed met argon2id) |
| TOTP-secret | Geheim (encrypted at rest) |
| IP+UA | Gewoon (technisch + audit) |
| Vault-content (in browser) | **Potentieel gevoelig** — kan banking, medisch, ID-nummers bevatten |
| Vault-blob (op server) | **Ciphertext** — server kan dit niet decrypteren |
| Verzegelde ontgrendelkopie `{ph,kh}` (v0.2.0) | **Ciphertext** — verzegeld naar de YubiKey van de gebruiker (P-CRYPT-09); server kan dit niet openen |
| Hardware-sleutelmetadata (v0.2.0) | Gewoon — label, soort, AAGUID (YubiKey-model), credential-id, publieke sleutels, signCount, tijdstippen van gebruik/vrijgave/blokkade |
| Vingerafdruk (v0.2.0) | **Niet verwerkt door HorseSafe** — blijft in de YubiKey Bio (match-on-device); server ziet alleen de vlag "gebruiker geverifieerd" |
| Meldingsmails (v0.2.0) | Gewoon — e-mailadres, onderwerp, tijd, IP; verstuurd via de SMTP-provider van iCt Horse |

## 3. Noodzaak + proportionaliteit

- **Noodzakelijk?** Ja — wachtwoord-vault kan niet zonder opslag credentials
- **Proportioneel?** Ja — minimale dataverzameling; alleen wat nodig is voor auth + opslag
- **Alternatieven?** Lokale wachtwoord-managers (KeePassXC desktop) → vereisen file-sync zelf. HorseSafe biedt synced-access met behoud van zero-knowledge.

## 4. Risico-analyse

| Risico | Waarschijnlijk­heid | Impact | Restrisico na mitigatie |
|---|---|---|---|
| Server-disk-leak vault-blobs | Laag-midden | **Geen** (ciphertext, niet leesbaar zonder master-key) | Verwaarloosbaar |
| Account-DB-leak (e-mails + hashes) | Laag | Midden (e-mail-spam, geen credentialing) | Laag (argon2id-hashes) |
| TOTP-secret-leak | Laag | Midden (account-laag-toegang, niet vault) | Laag (AES-GCM-at-rest + 2-laags-auth) |
| Master-key-leak via browser-mem-dump | Zeer laag | Hoog (vault-content-leak) | Laag (vault auto-lock + device-trust-aanname) |
| Phishing-site stelen credentials | Midden | Hoog (account+vault toegang) | Midden (mitigatie: HSTS + user-education + v0.2 extensie URL-pinning) |
| Clipboard-leak naar andere app | Hoog | Laag (1 wachtwoord, 10s window) | Laag (best-effort wipe + v0.2 extensie) |
| Insider-attack (admin) | Zeer laag | **Geen vault-content** (zero-knowledge); midden account-laag | Laag (audit-log + GDPR-rechten) |
| Subverwerker-uitval (Hetzner) | Laag | Hoog (DOS) | Midden (rsync-backup + restore-procedure) |
| Subverwerker-uitval (mailprovider; v0.2.0 SMTP info@icthorse.nl, Gmail fallback) | Laag | Midden (magic-link en meldingen weg; TOTP-fallback; noodsleutel-vrijgave bewust uitgeschakeld) | Laag |
| Server geeft verzegelde kopie vrij aan aanvaller (v0.2.0) | Laag | **Geen** zonder fysieke YubiKey + UV (kopie niet te openen) | Verwaarloosbaar |
| Misbruik noodsleutel via overgenomen account (v0.2.0) | Zeer laag | Hoog | Laag (24 u wachttijd + mail + blokkade; fysieke sleutel + PIN van 63 tekens nodig) |
| Gecompromitteerde server serveert kwaadaardige JS bij ontgrendelen (v0.2.0, R1) | Zeer laag | Hoog | Laag-midden (ongewijzigd t.o.v. v0.1.0; geaccepteerd en gedocumenteerd) |
| Quantum-computer-attack op AES-256 | Zeer laag (decennia) | Hoog | n.v.t. (toekomstige Argon2id-upgrade) |

## 5. Maatregelen

Zie `SECURITY.md` + `GDPR_COMPLIANCE.md`. Kernzaken:

1. **Zero-knowledge encryptie** — primaire mitigatie voor server-side risico's
2. **KDBX4-compat** — disaster-recovery onafhankelijk van HorseSafe
3. **MFA verplicht** — mitigeert account-laag-phishing
4. **Audit-log** — accountability + insider-attack-detectie
5. **HSTS + CSP** — browser-laag bescherming
6. **Sandboxed systemd-unit** — server-laag isolation
7. **GDPR-rechten in UI** — minimaliseert administratieve toegang

## 6. Raadpleging betrokkenen

- **v0.0.x intern**: Christian + Joyce + paar test-users → directe feedback
- **v0.1.0 publiek**: feedback-mailbox + LinkedIn-aankondiging met privacy-info

## 7. Conclusie

| Aspect | Oordeel |
|---|---|
| Verwerking rechtmatig | ✅ |
| Verwerking proportioneel | ✅ |
| Restrisico's acceptabel | ✅ (na mitigaties) |
| Hoog risico voor betrokkenen | ❌ |
| DPIA-melding AP nodig | ❌ (geen "hoog risico") |

**Eindoordeel:** verwerking kan plaatsvinden. DPIA-her-evaluatie:
- Bij v0.1.0 (public + zakelijke pilots)
- Bij elke architecturale wijziging
- Jaarlijks regulier

## 8. Hervalmoment

- ~~Bij toevoegen FIDO2 (v0.5.0) → re-evaluate (extra verwerking biometrics?)~~ uitgevoerd bij v0.2.0-Koblitz, zie §9
- Bij v0.3.0-Miller (Android-app, telefoon-credential, apparaatgegevens en attestation-ketens) → re-evaluate
- Bij v0.4.0-Montgomery (goedkeuringen met IP/plaats/browser-metadata naar de telefoon) → re-evaluate
- Bij EU-buiten host-verhuizing → re-evaluate
- Bij beleidwijziging Hetzner/Google → re-evaluate

## 9. Herbeoordeling v0.2.0-Koblitz (2026-10-10)

**Wijziging:** ontgrendelen met een YubiKey Bio, noodsleutel met wachttijd, step-up en meldingsmails. Ontwerp: `docs/HARDWARE_KEYS.md`.

| Vraag | Oordeel |
|---|---|
| Verwerkt HorseSafe biometrische gegevens (Art. 9)? | **Nee.** De vingerafdruk wordt ingeschreven en gematcht in de YubiKey Bio zelf. Er gaan geen biometrische templates of metingen naar browser of server; de server ontvangt alleen een handtekening met de UV-vlag. |
| Nieuwe persoonsgegevens? | Ja, beperkt: sleutelmetadata (label, AAGUID/model, credential-id, publieke sleutels, signCount, tijdstippen) en meldingsmails. Noodzakelijk voor beveiliging en uitvoering van de dienst (Art. 6(1)(b) en (f)). |
| Blijft zero-knowledge intact? | Ja (P-CRYPT-01, -09): de server bewaart alleen een kopie die verzegeld is naar gebruikershardware en die hij aantoonbaar niet kan openen. Geen key-escrow (P-CRYPT-06). |
| Dataminimalisatie | Challenges alleen als hash; audit zonder geheime of cryptografische payloads; geen telemetrie. |
| Bewaartermijn | Sleutels tot verwijderen (of CASCADE met vault/account); challenges max. 1 dag; audit 13 maanden. |
| Nieuwe subverwerker? | De SMTP-provider van iCt Horse (afzender info@icthorse.nl) vervangt Gmail als primaire mailroute. Opnemen in `GDPR_COMPLIANCE.md` / verwerkersoverzicht. |
| Rechten betrokkene | Sleutels zijn door de gebruiker zelf in te zien en te verwijderen; inzage/verwijdering verder ongewijzigd. |

**Conclusie:** geen hoog risico; geen DPIA-melding bij de AP nodig. Restrisico's zijn gelijk aan of lager dan v0.1.0 (extra hardwarefactor), met R1 en R2 als expliciet geaccepteerde restrisico's (`THREAT_MODEL.md`).
