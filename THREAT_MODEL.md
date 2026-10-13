# THREAT_MODEL.md — HorseSafe

> STRIDE-analyse + zero-knowledge bewijslast + bekende beperkingen.

## Aannames

- Gebruiker draait HorseSafe in een moderne browser (Chrome/Edge/Firefox/Safari recent)
- Gebruiker heeft controle over zijn eigen device (geen evil-maid / keylogger)
- Gebruiker kent zijn master-pw en bewaart keyfile veilig (USB/printout/separate device)
- HC55-server kan gecompromitteerd raken (worst case in dit model)
- TLS staat aan en valide cert (LE auto-renew)
- (v0.3.0-Miller deel 1) De YubiKeys worden ingericht en gekeurd met de Android-app (`android/`) op een eigen telefoon (Galaxy Z Fold6) in vliegtuigmodus. De app heeft geen INTERNET-permissie en verwerkt niets op de server; een telefoon met root of malware valt buiten het model (R19).
- (v0.2.0-Koblitz) Hardware-sleutels zijn een YubiKey Bio (dagelijks) en een reserve-YubiKey met PIN van 63 tekens (noodsleutel, in de fysieke kluis). De gebruiker ontgrendelt met hardware-sleutels alleen in Chrome/Edge op icthorsecloud.nl.

## STRIDE-matrix

| Categorie | Dreiging | HorseSafe mitigatie |
|---|---|---|
| **S** Spoofing | Aanvaller logt in als user | MFA (TOTP, of magic-link als tweede stap ná het wachtwoord in dezelfde browser — nooit los, zie R14). Backup-codes alleen aan te maken vanuit een MFA-sessie. Failed-login throttle. JWT-binding aan IP+UA optioneel (v0.1). |
| **S** Spoofing | Phishing-site doet zich voor als HorseSafe | HSTS + CSP + browser-extensie URL-check (v0.2). User-education in onboarding. |
| **T** Tampering | Server vervangt vault-blob met malicious content | KDBX4 heeft HMAC-integriteit ingebouwd. Mismatch → kdbxweb weigert decryptie. |
| **T** Tampering | MitM tussen browser en server | TLS 1.3 + HSTS + cert-pinning (v0.2 via extensie). |
| **T** Tampering | Server muteert audit-log | Append-only file naast SQLite-tabel; nightly hash-chain naar storagebox. |
| **R** Repudiation | User ontkent export-actie | Audit-log + reden-veld + IP + UA. |
| **I** Information disclosure | Server-disk-dump lekt vault | **Vault = KDBX4-ciphertext**. Zonder master-key niet ontsleutelbaar. |
| **I** Information disclosure | Server-RAM-dump lekt sessie-data | Server kent nooit master-key. RAM kan JWT-cookies bevatten → session-hijack mogelijk → mitigatie: korte JWT-TTL + sliding window + cookie-rotation. |
| **I** Information disclosure | Browser-RAM-dump lekt master-key | Threat-actor heeft device-toegang → outside scope. Mitigatie: vault-auto-lock na 5 min inactiviteit. |
| **I** Information disclosure | Clipboard lekt pw naar andere app | 10s wipe (best-effort). v0.2 = extensie wipe (échte). |
| **I** Information disclosure | Telemetrie lekt entry-titels | Geen telemetrie naar third-party. Eigen audit-log enkel server-side. |
| **D** Denial of service | Aanvaller spamt magic-link aanvragen | Rate-limit per e-mail (3/uur) + per IP (10/uur). |
| **D** Denial of service | Aanvaller uploadt gigantische blobs | `client_max_body_size 50M` in nginx + backend-check op KDBX4-header. |
| **E** Elevation of privilege | Normale user wordt admin | `is_admin` is server-DB-flag, alleen gezet via directe DB-actie (geen UI). Admin-route check op JWT-claim. |
| **E** Elevation of privilege | User leest andermans vault | `/vault/{id}` check: `vaults.user_id == jwt.user_id`. Test in CI. |
| **S** Spoofing (v0.2.0) | Aanvaller registreert een eigen authenticator of een gesynchroniseerde passkey | Server verifieert `packed`-attestation tot Yubico-root, AAGUID-allowlist, UV=1, BE=0/BS=0, origin + rpId. Tweede sleutel alleen met step-up. Mail bij elke koppeling. |
| **S** Spoofing (v0.2.0) | Gekloonde YubiKey-credential | signCount-regressie → 409 `sign_count_regression`, audit `vault_key_clone_suspect` + mail. |
| **T** Tampering (v0.2.0) | Server verwisselt of verplaatst een verzegelde kopie (andere vault/sleutel) | Seal_v2-AAD bindt versie, purpose, vault_id en key_id; HKDF-salt bindt epk en pk_c; client bouwt de AAD zelf en controleert `pk` uit PRF == `public_key`. KDBX-header-HMAC bewijst daarna dat CK klopt. |
| **R** Repudiation (v0.2.0) | Gebruiker of aanvaller ontkent een sleutelactie | Audit-events voor koppelen, ontgrendelen, vrijgave, blokkade, rekey en step-up met IP + UA; mail bij elke beveiligingsrelevante actie. |
| **I** Information disclosure (v0.2.0) | Server-dump lekt de verzegelde kopieën | Kopie is verzegeld naar een sleutel die alleen in de YubiKey (PRF) bestaat; de server kan hem niet openen (P-CRYPT-09). Zie R9 voor wat een geopende kopie waard is. |
| **D** Denial of service (v0.2.0) | Aanvaller met account-sessie verwijdert of blokkeert sleutels | Defensieve acties zonder step-up maar met mail + audit. De keyfile-route blijft altijd werken (R5). |
| **E** Elevation of privilege (v0.2.0) | Aanvaller met account-sessie + TOTP vraagt de noodsleutel vrij of heft een blokkade op | Opheffen alleen met Bio-step-up (nooit wachtwoord of TOTP, besluit 3), en alleen met een Bio die er al was vóór de blokkade. TOTP kan niet zonder de huidige code worden vervangen; TOTP-step-up heeft 24 u afkoeltijd na Bio verwijderen of TOTP instellen (R6). Vrijgave vraagt 24 u wachttijd met mail, en daarna nog de fysieke noodsleutel + PIN van 63 tekens. Zonder meldkanaal geen vrijgave. |

## Zero-knowledge bewijs (formeel)

**Stelling:** een aanvaller met **volledige server-toegang** (root, alle disk, alle DB-content, alle code, ongelimiteerd CPU) kan **geen** vault-inhoud reconstrueren.

**Bewijs:**

1. Vault-content wordt **uitsluitend in browser** geserialiseerd naar KDBX4 + geëncrypteerd.
2. De master-key (= composiet van master-pw + keyfile via KeePassXC-formule) wordt **uitsluitend in browser-RAM** geconstrueerd.
3. De master-key wordt **nooit** naar de server gestuurd (audit: alleen `/vault/{id}`-uploads van pure KDBX4-bytes; geen apart key-veld in request-body of header).
4. De server slaat enkel de KDBX4-blob op (= ciphertext + KDF-parameters + HMAC).
5. KDBX4 gebruikt AES-256 of ChaCha20 met sleutel = Argon2id(master-key, salt, t, m, p) waar t=12, m=128 MiB, p=2.
6. **Argon2id is memory-hard**: brute force op random 64-bit-equivalente master-key kost ~2^64 × 128 MiB-passes ≈ 10^25 J ≈ 3.16 × 10^17 jaar bij Landauer-limiet voor de hele wereld-energieproductie.
7. **Conclusie:** zonder client-side master-key is decryptie computationeel onhaalbaar. QED.

**Caveats:**

- Bewijs faalt als master-pw zwak is (bv. < 60 bits entropie) → user-education verplicht in S3.
- Bewijs faalt bij client-side compromise (malware op browser-host) → outside scope.
- Bewijs faalt als kdbxweb-implementatie buggy is → mitigatie: CI round-trip test met KeePassXC-desktop als oracle.

### Aanvulling v0.2.0-Koblitz: verzegelde ontgrendelkopie (P-CRYPT-09)

Vanaf Koblitz bewaart de server per hardware-sleutel een kopie van het ontgrendelmateriaal `CK = {ph, kh}` (wachtwoord-hash en keyfile-hash, de invoer van de KDBX4-composite-key). Het bewijs hierboven blijft gelden, met deze toevoeging:

8. `sealed_c = Seal_v2(pk_c, CK)`: X25519-ECDH met een eenmalige sleutel, HKDF-SHA256 en AES-256-GCM. Openen vereist `sk_c`.
9. `sk_c` wordt bij elk gebruik opnieuw afgeleid uit de WebAuthn-PRF (hmac-secret) van de YubiKey, en alleen na gebruikersverificatie (vinger of PIN). De server krijgt alleen `pk_c` en de verzegelde kopie; PRF-uitvoer en `sk_c` verlaten de browser niet.
10. **Conclusie:** een aanvaller met volledige server-toegang heeft voor een kopie nog steeds de fysieke YubiKey plus UV nodig. Zonder sleutel geldt dezelfde onhaalbaarheid als stap 7.

**Caveats (aanvullend):** een gecompromitteerde server kan kwaadaardige web-JS serveren die CK bij het ontgrendelen in de browser onderschept (R1). Dat risico bestond al voor wachtwoord en keyfile (P-CRYPT-05) en wordt niet groter.

**Actieve aanvaller op de sleutellijst (R15):** stap 8-10 gaan uit van een passieve server of een gelekte DB. Een aanvaller die `vault_keys.public_key` kan *wijzigen* zou de client naar zijn eigen sleutel laten verzegelen; daarom verzegelt de client alleen naar publieke sleutels die bij het koppelen in de versleutelde KDBX zijn vastgelegd (pins, `HorseSafe.KeyPins.v1`). Die lijst kan de server lezen noch vervalsen zonder de KDBX-sleutel.

## Hardware-sleutels: dreigingen en restrisico's (v0.2.0-Koblitz e.v.)

Uitgebreide tabel: `docs/HARDWARE_KEYS.md` §9. Samengevat:

| # | Dreiging | Mitigatie / restrisico | Fase |
|---|---|---|---|
| R1 | Gecompromitteerde server serveert kwaadaardige JS en vangt CK bij webontgrendeling | Geaccepteerd en expliciet; gelijk aan v0.1.0 (P-CRYPT-05). Op termijn native kluis (Lange), getekende bundel of extensie | alle |
| R2 | 24-uurswachttijd van de noodsleutel wordt alleen door de server afgedwongen | Wie de server overneemt heeft nog de fysieke noodsleutel + PIN van 63 tekens nodig; melding, blokkade en audit | Koblitz |
| R3 | YubiKey Bio valt na 3 mislukte vingers terug op de PIN | Niet uit te zetten; PIN van 63 tekens, minimale PIN-lengte 63, 8 pogingen tot reset | Koblitz |
| R5 | DoS met alleen een account-sessie (sleutels verwijderen, blokkeren) | Uitbreidende acties vragen step-up, defensieve niet; alles gemeld en gelogd; keyfile-route blijft | Koblitz |
| R6 | Account-sessie + TOTP + verwijderen van alle bio-sleutels geeft TOTP-step-up, en daarmee een eigen (echte) Bio koppelen. | TOTP-step-up pas 24 uur (`recovery_delay_hours`) na het verwijderen van een Bio of na het instellen van TOTP terwijl er al sleutels waren (403 `stepup_cooldown`, met meldingen). TOTP kan niet worden vervangen zonder de huidige code (409 `totp_already_configured`). Deblokkeren kan nooit met TOTP en alleen met een Bio die al gekoppeld was vóór de blokkade (`stepup_key`, 403 `stepup_key_too_new`). Vóór rekey/opnieuw verzegelen toont de client elke ontvangende sleutel (recent gekoppeld gemarkeerd) en vraagt bevestiging. Daarna is voor de noodsleutel nog steeds de fysieke sleutel met PIN nodig, plus 24 uur met meldingen. Restrisico: zonder TOTP is het accountwachtwoord genoeg voor S; de mailbox alleen niet (R14). | Koblitz |
| R9 | `kh` is bij een 64-hex keyfile gelijk aan de keyfile | Een geopende kopie staat gelijk aan wachtwoord-hash plus keyfile; openen vereist PRF (of K_wrap vanaf Miller) | Koblitz |
| R10 | XSS in de webapp leest CK | Strikte CSP (`script-src 'self'`), geen inline-JS; gelijk aan v0.1.0 | Koblitz |
| R12 | Attestation-uitzondering voor tests (virtuele authenticator) | Alleen met `HORSESAFE_TEST_ATTESTATION`; `/health` toont de vlag; app weigert te starten met de vlag aan en rpId `icthorsecloud.nl` | Koblitz |
| R13 | Mailserver onbereikbaar → noodsleutel-vrijgave zonder dat de eigenaar het merkt | Vrijgave geweigerd zonder meldkanaal (503 `notify_unavailable`); teruggedraaid als de melding niet afgeleverd wordt (503 `notify_failed`) | Koblitz |
| R14 | Magic-link of backup-codes als omweg om MFA (reviewronde 2): de magic-link gaf zonder wachtwoord een `mfa=true`-sessie (mailbox = S, en alle Koblitz-meldingen gaan naar diezelfde mailbox); backup-codes aanmaken kon met alleen het wachtwoord en gaf via `/backup-codes/verify` `mfa=true`. | Besluit (reviewronde 2, 10-10-2026): de magic-link is uitsluitend een **tweede stap** bovenop een wachtwoordsessie van dezelfde gebruiker in dezelfde browser; zonder die sessie wordt hij geweigerd en niet verbruikt (`login.html?error=magic_link_login_first`); hij geeft nooit zelf een sessie. `POST /auth/backup-codes/generate` vereist een sessie met MFA (403 `mfa_required`); bestaande codes blijven dan geldig. S = wachtwoord + tweede factor (TOTP, magic-link of een eerder met MFA aangemaakte backup-code). | Koblitz |
| R15 | Wie `vault_keys.public_key` kan wijzigen (DB-schrijftoegang, gemanipuleerde back-up, injectie elders) laat bij de volgende reseal/rekey het echte `{ph,kh}` naar zijn eigen sleutel verzegelen; een verwisselde sleutel ziet er in de bevestigingsdialoog hetzelfde uit. | De client legt bij het koppelen `{key_id: public_key}` vast **in de versleutelde KDBX** (Meta/CustomData `HorseSafe.KeyPins.v1`, beschermd door de KDBX-HMAC; eerst vastleggen en opslaan, dan pas `POST …/keys`). `resealAll`/`rekey` verzegelen alleen naar sleutels die daar exact zo staan; anders `key_pin_mismatch`/`key_not_pinned` vóór er iets verzegeld wordt, en het sleutelpaneel waarschuwt. Restrisico: een sleutel waarvan de pin ontbreekt (kluis buiten HorseSafe zonder CustomData opgeslagen, of koppelen afgebroken) moet opnieuw gekoppeld worden; R1 (kwaadaardige JS) blijft. | Koblitz |
| R4 | Release-APK getekend met de debug-keystore op HC55; het wachtwoord daarvan is publiek bekend, dus wie het bestand kan lezen kan een geaccepteerde update maken | E8 accepteert dit voorlopig; signer-digest `32491e0f…3f17` op M12 en in `android/scripts/verify_apk.sh`; publiceren alleen vanaf een lokale build op HC55; geen in-app update in deel 1. Open: eigen release-keystore of bewust aanvaarden | Miller deel 1 |
| R16 (B-17) | PIN-bytekopieën in de yubikit-heap (`ClientPin.preparePin` wist zijn uitvoer niet; ECDH-geheim niet gewist). yubikit maakt geen String van de PIN; `Ctap2Session.clientPin` is package-private | App houdt de PIN alleen in een gewiste CharArray; "Afsluiten" beëindigt het proces na elke stap met PIN; release niet-debuggable. Geaccepteerd restrisico | Miller deel 1 |
| R17 | 8 PIN-pogingen bij 63 tekens: typfouten kosten pogingen; 0 = geblokkeerd, alleen reset | Controleteken per groep, Oefenen zonder sleutel, M8 blokkeert bij ≤ 3 pogingen, typadvies voor de laptop | Miller deel 1 |
| R18 | MPE-gat server-side: de server dwingt bij koppelen geen `minPinLength=63`/`credProtect` af en weigert een Bio Multi-protocol (PIN max. 8) niet | App weigert MPE met PIV en `maxPINLength` < 63/onbekend; alleen met de app ingerichte sleutels koppelen; Koblitz-patch gepland (afhankelijk van Chrome-meting) | Miller deel 1 / Koblitz-patch |
| R19 | Gecompromitteerde telefoon (root, malware, a11y-dienst, overlay) leest de PIN of vervalst het oordeel | FLAG_SECURE, overlays verborgen, a11y/multi-window/DeX/opname/ontwikkelaarsopties blokkeren de PIN-schermen, geen INTERNET, vliegtuigmodus; server verifieert attestation bij het koppelen zelf. Root-malware met geheugentoegang: buiten scope | Miller deel 1 |
| R20 | Hoofd- en noodsleutel-PIN niet tussen sessies te vergelijken | Elke inrichting een nieuwe willekeurige PIN; papierregel + oranje melding | Miller deel 1 |
| R21 | Platform-crashbuffer (`logcat -b crash`) bevat bij een crash type en stapnaam | Geen PIN-data in exception-berichten (canary-test), geen logging, `CrashGuard` voorkomt dropbox | Miller deel 1 |
| R22 | Wissen in de app (0.3.1): per ongeluk de verkeerde of de enige gekoppelde sleutel wissen, of een a11y-dienst/aanvaller met telefoon én sleutel wist hem (denial of service; geen toegang tot de kluis) | Bevestiging met de laatste 4 cijfers van het serienummer + 3 s vasthouden; reset alleen kort na opnieuw insteken en met aanraking (YubiKey zelf); zelfde-sleutelcontrole serienummer + AAGUID; omgevingsbewaking blokkeert wissen; waarschuwing "enige sleutel = buitengesloten"; noodsleutel apart bewaard. Kon al met `ykman` | Miller 0.3.1 |
| R7, R8, R11 | Telefoondiefstal met toestel-PIN, `sk_c` kort in app-RAM, Doze-vertraging | Zie `docs/HARDWARE_KEYS.md` §9 | Miller deel 2 |

## Vault-content vs. metadata

| Type data | Server-zichtbaarheid |
|---|---|
| Entry-titel | ❌ ciphertext binnen KDBX4 |
| Username | ❌ ciphertext |
| Password | ❌ ciphertext |
| URL | ❌ ciphertext |
| Notes | ❌ ciphertext |
| Attachments | ❌ ciphertext |
| Entry-aantal | ❌ ciphertext (zit in KDBX-body) |
| **Vault-bestandsnaam** | ✅ (vaults.name = "default" of user-gekozen — **let op**, gebruiker mag gevoelige string kiezen) |
| **Vault-grootte (bytes)** | ✅ (size_bytes) — indirect verklikt entry-aantal |
| **Update-tijdstip** | ✅ (updated_at) — verklikt activiteit |
| Account-e-mail | ✅ (users.email — onvermijdelijk voor magic-link) |
| Account-pw | ❌ (argon2id-hash op server) |
| TOTP-secret | ⚠️ plaintext base32 op server (RFC 6238 noodzaak) — beschermt alleen account-laag |
| Magic-link token | ⚠️ tijdelijk plaintext server-RAM/DB tot redemption |
| Verzegelde kopie `{ph,kh}` (v0.2.0) | ❌ ciphertext, verzegeld naar YubiKey-PRF; server kan niet openen (P-CRYPT-09) |
| Hardware-sleutelmetadata (v0.2.0) | ✅ label, soort, AAGUID (verklikt het YubiKey-model), credential-id, X25519-publieke sleutel, signCount, tijdstippen van gebruik, vrijgave en blokkade |
| Vingerafdruk (v0.2.0) | ❌ blijft in de YubiKey Bio; server ziet alleen de UV-vlag |

**Risico-acceptatie:** metadata-lekage (vault-grootte, update-tijdstip) is bewust geaccepteerd. Gebruiker wordt geïnformeerd in onboarding.

## Bekende beperkingen v0.0.x

1. **Browser clipboard-wipe = best-effort.** Werkt alleen bij tab-focus. Extensie (v0.2) lost dit op.
2. **MFA-secret server-side plaintext.** Onvermijdelijk voor TOTP-verificatie. Mitigatie: PBKDF2-encrypted-at-rest met server-master-key (uit env-var, niet in repo).
3. **Geen sharing tussen users.** v0.0.x = solo. v0.2.x = re-encryptie per ontvanger met diens publieke key.
4. **Geen offline-modus.** Vault-toegang vereist server-bereikbaarheid. v0.1.x = ServiceWorker-cache van laatste blob voor read-only offline.
5. **Hardware-sleutels alleen in Chrome/Edge op de laptop** (v0.2.0-Koblitz). Safari en iOS worden fail-closed geweigerd; telefoon volgt in Miller. FIDO2 als account-MFA (los van de vault-laag) staat nog op de roadmap (Rogaway).
6. **Mail via één SMTP-provider** (v0.2.0: generieke mailer, info@icthorse.nl via 587 STARTTLS; Gmail alleen fallback). Bij storing: TOTP voor login; noodsleutel-vrijgave is dan bewust uitgeschakeld (R13).
7. **Single-device locking in v0.0.x.** Gelijktijdige edits op twee devices → conflict-merge in v0.1.x.
8. **Android-app deel 1 (v0.3.0-Miller) richt in en keurt alleen.** Ontgrendelen op de telefoon, koppelen en meldingen volgen in deel 2. Sinds v0.3.1 kan de app een sleutel wissen (R22); de koppeling in HorseSafe moet je daarna zelf verwijderen.

## Dreigingen waar HorseSafe NIET tegen beschermt

- Malware op user-device (keylogger, screen-grabber)
- Side-channel attacks op WebCrypto in browser
- Quantum-computer attacks op AES-256 (post-2040+ overweging)
- Coercion ("rubber-hose cryptanalysis")
- Lekken via Argon2-cache-timing in shared-hosting scenario (n/a voor HC55 dedicated)

## Compliance-implicaties

- **GDPR** Artikel 32: pseudonimiserings- en versleutelings-eis = ruim voldaan (zero-knowledge gaat verder dan GDPR-minimum)
- **NIS2** voor latere dienst-aanbieding: documentatie voldoet aan Artikel 21 lid 2(h) "encryption policies"
- **DPA-template** voor zakelijke klanten: leverbaar (zero-knowledge = beperkte verwerkersrol)
