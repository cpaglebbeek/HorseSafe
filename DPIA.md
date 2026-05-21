# DPIA.md — HorseSafe Data Protection Impact Assessment

> DPIA-light. Onder GDPR Art. 35 lid 3 niet verplicht (geen large-scale of bijzondere categorieën), maar uitgevoerd ter zorgvuldigheid.

**Datum:** 2026-05-21
**Versie:** v0.0.0
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
| Subverwerker-uitval (Gmail) | Laag | Midden (magic-link broken; TOTP-fallback) | Laag |
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

- Bij toevoegen FIDO2 (v0.5.0) → re-evaluate (extra verwerking biometrics?)
- Bij EU-buiten host-verhuizing → re-evaluate
- Bij beleidwijziging Hetzner/Google → re-evaluate
