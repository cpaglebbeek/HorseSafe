# CHANGELOG — HorseSafe

Alle wijzigingen worden hier gedocumenteerd. Format: [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]
- Later: noodsleutel blokkeren vanaf de telefoon, update in de app; achtergrondmelding voor verzoeken (ntfy/WorkManager).

## [0.4.1-Montgomery] — 2026-10-16 (bugfix)

### Opgelost
- **HS-BUG-011:** "🔑 Sleutels" opende het paneel onder alle entries, buiten beeld (bij 342 entries leek de knop
  niets te doen). Paneel staat nu boven de lijst; openen scrolt ernaartoe en zet de focus op de titel. Alleen web;
  APK blijft 0.4.0 (vc 400). Test `keys-panel.spec.ts` met 300 entries.

## [0.4.0-Montgomery] — 2026-10-16 (vertrouwde browser + telefoonvinger)

Besluit HARDWARE_KEYS §11.3 (akkoord 16-10), contract §14, invulling §14.11. Vervangt §11.2 punt 3 (6 cijfers + SAS).

### Toegevoegd
- **Vertrouwde browser:** niet-exporteerbare ECDSA-sleutel in IndexedDB; koppelbewijs = HMAC met sleutel uit CK over
  (vault_id, browser_id, pub_B, label); alleen kluizen met keyfile; step-up vereist; max 10 per gebruiker.
- **Inloggen op een vertrouwde browser** met e-mail + browserhandtekening + TOTP (challenge eenmalig, geen enumeratie,
  TOTP-tijdstap-replay geweigerd).
- **Ontgrendelen met de telefoon:** verzoek ondertekend door de browser met tijdelijke X25519-sleutel; app controleert
  handtekening (vóór vinger) en koppelbewijs (na vinger), verzegelt CK als Seal_v2 `relay`; antwoord eenmalig, ≤ 120 s,
  daarna gewist (410). Weigeren trekt de sessie in (+ 15 min afkoelen); "Weigeren en browser intrekken" ook het vertrouwen.
- **Sessies:** JWT-claim `sid`; `revoked_sessions`; uitloggen, intrekken, weigeren en rekey trekken sessies in.
- Migratie 007 (`trusted_browsers`, `browser_challenges`, `approvals`, `revoked_sessions`); testvectoren `trust_v1`
  (Python = JS = Kotlin); app-scherm M20 goedkeuringskaart (alleen BIOMETRIC_STRONG); versionCode 400.

### Beveiliging (adversariële review, §14.12)
- Browsersessie beperkt tot ontgrendelen tot na telefoongoedkeuring (default-deny); beheer nooit via browser-login.
- Intrekken vangt ook verlengde sessies (`browser_sessions`); absolute sessiegrens 12 u (`auth_time`).
- TOTP-tijdstap atomair eenmalig (`totp_used`); uitloggen sluit open verzoeken; `secure_delete`; UA opgeschoond.

### Tests
- pytest 326 (was 269), node 130 (was 97), Playwright 16/16 (was 13), JVM 391 (was 337).

## [0.3.5-Miller] — 2026-10-14 (kluis: categorieën + zoeken)

Gevraagd door Christian na het vervangen van de kluis door `database1` (342 entries, 9 categorieën): "ik mis de logische
categorieën en een zoekfunctie" (WhatIf + akkoord 14-10). Alleen frontend; geen schema- of API-wijziging; APK blijft 0.3.4.

### Added
- **Categorieboom** (S7): KDBX-groepen met submappen en aantallen, "Alle entries" zonder prullenbak, prullenbak apart
  onderaan; op schermen ≤ 1100 px een keuzelijst. Kolom "Categorie" in de lijst; vault-pagina breder (1440 px).
- **Zoeken**: titel, gebruikersnaam, URL, notities en categorienaam; alle woorden, zonder hoofdletter-/accentgevoeligheid;
  nooit in wachtwoorden of beveiligde velden; standaard de hele kluis, optioneel alleen de gekozen categorie; `/` en `Esc`.
  Alleen in de browser (`js/vault-index.js`, pure functies + unittests).
- "+ Nieuwe entry" landt in de gekozen categorie ("Komt in: …").

### Fixed
- **HS-BUG-010:** TOTP-QR in Instellingen was onzichtbaar (schaalbare SVG zonder maat in een `fit-content`-vak = 0×0 px),
  sinds v0.0.3. `mfa.spec.ts` controleert nu de zichtbare maat.
- Deploy-runbook + `deploy_hc55.sh`: migrate met productie-`.env`, rsync `--delete-excluded` (gevonden bij de 0.3.4-deploy).

### Tests
- node 97/97, Playwright 13/13 (nieuw `vault-groups.spec.ts`), pytest 269/269.

## [0.3.4-Miller] — 2026-10-14 (deel 2 fase A: telefoon koppelen)

Christian wil HorseSafe op de laptop openen zonder YubiKey, alleen met de telefoonvinger. Besluiten en contract:
`docs/HARDWARE_KEYS.md` §11.2 en §13 (WhatIf + akkoord 14-10). Ontgrendelen zelf volgt in Montgomery (0.4.0).

### Added
- **Backend:** migratie 006 (`pairings`, `device_nonces`, `devices.confirmed_at`); `/devices/pairings` (start SU,
  claim, confirm, annuleren), `/devices`, device-API `/device/v1/status` en `/device/v1/keys/{kid}/sealed` met
  K_dev-handtekening (ts ±60 s, nonce-cache). Android key-attestation tegen de gevendorde Google-roots
  (RSA + EC CA1) met revocatielijst (24 u cache), TEE/StrongBox, verified boot + locked, package + signer,
  K_biosig `userAuthType == 2` (geen PIN-terugval). Testvlag `test_device_attestation` met prod-guard.
  Nieuwe dependency-pin `pyasn1==0.6.4`.
- **Web:** "Telefoon koppelen" in het sleutelbeheer: QR (geheim `s` alleen in de browser; server krijgt `k_srv`),
  `mac_web`-controle, SAS van 6 cijfers, Seal_v2 naar de telefoon; telefoons in de sleutellijst, toestel verwijderen.
- **App:** INTERNET alleen naar icthorsecloud.nl (pins ISRG X1/X2/YE/YR), Keystore K_dev/K_biosig/K_wrap,
  `StrongGate` (alleen BIOMETRIC_STRONG), QR-scanner (zxing, hash-gecontroleerd), SAS, status, proef "Kopie openen",
  scherm "Opnieuw koppelen" (M14–M19). PIN-code importeert niets uit `net/` (bronbeleidstest).
- **Testvectoren** `specs/testvectors/pair_v1.json` (Python = JS = Kotlin).

### Changed
- **Eigen release-keystore** (R4): signer `fbd6b151…062e` i.p.v. de debug-keystore. Eenmalig de app verwijderen en
  opnieuw installeren.
- Koppelgeheim in de browser i.p.v. op de server (aanscherping §4.5, §13.0).

## [0.3.3-Miller] — 2026-10-13 (bugfix: gewiste Bio onterecht "al gebruikt")

Gemeld door Christian: na "Sleutel wissen" weigerde "Nieuwe hoofdsleutel" met `KEY_ALREADY_USED` op M11,
zonder dat er een PIN getoond was. WhatIf + akkoord 13-10.

### Fixed — `android/` (versionCode 303)
- **Nieuw-sleutelgate eiste 8 PIN-pogingen ook zonder PIN.** Een gewiste (of nieuwe) Bio meldt zonder PIN geen
  of een ander aantal; dat werd als "al gebruikt" gelezen. Zonder PIN is het nu een oranje regel met het gemeten
  getal; de echte controle blijft 8 pogingen teruglezen direct na setPin (`PIN_READBACK_FAILED`). Met een PIN
  blijft een afwijkend aantal rood.
- **M11 liet de oorzaak van een gate-stop niet zien:** "Beoordeling" toont nu ook de gate-regels (rood eerst),
  M11 toont de sleutelgegevens (o.a. PIN-pogingen) en een stopcode (bv. `KEY_ALREADY_USED`) om door te geven,
  omdat schermafdrukken zwart zijn.

### Tests
- Nep-YubiKey: `retriesWithoutPin` (null/0/3/7); inrichten na wissen; met PIN blijft de regel rood. 272/272.

## [0.3.2-Miller] — 2026-10-13 (bugfix: echte YubiKeys onterecht afgewezen)

Gemeld door Christian bij de eerste echte sleutel: "melding over pin lengte" en daarna "sleutel past niet bij
type rol". WhatIf + akkoord 13-10.

### Fixed — `android/` (versionCode 302)
- **`MAX_PIN_LENGTH_UNKNOWN` bij elke echte YubiKey 5.7:** `maxPINLength` (getInfo 0x1D) bestaat pas sinds
  CTAP 2.2; firmware 5.7 is CTAP 2.1 en meldt het nooit (yubikit vult zelf 63 in). Het standaardbeleid
  (`MaxPinLengthPolicy.ASSUME_CTAP21_MAX`) neemt nu het CTAP 2.1-maximum 63 aan met een oranje regel, ook voor
  Multi-protocol; setPin(63) is de atomaire proef (weigert de sleutel, dan `PIN_POLICY_MPE_PIV`, niets op de
  sleutel). Geldt voor inrichten, hervatten, keuren en PIN wijzigen. Een gemeld maximum < 63 blijft STOP.
  Open vraag 4 gesloten.
- **`CLASS_MISMATCH` zei niet wat er mis was:** de regel noemt nu het aangesloten type en de gekozen rol, M11
  toont beide, en het advies zegt welke menukeuze bij welke sleutel hoort.

### Tests
- Nep-YubiKey meldt 0x1D standaard niet (zoals echte 5.7); nieuwe tests YK5 zonder 0x1D, gemeld 63 = groen,
  MPE zonder 0x1D stopt pas bij setPin zonder schrijfactie, klassefout noemt type + rol. 270/270 groen.

## [0.3.1-Miller] — 2026-10-13 (sleutel wissen in de app)

Aanleiding: een al ingerichte sleutel werd (terecht) afgewezen en kon alleen buiten de app gewist worden.
WhatIf + akkoord Christian 13-10. Backend en web wijzigen functioneel niet (alleen versiestring).

### Added — `android/` (versionCode 301)
- **Sleutel wissen** (M13, flow F8 `ResetFlow`): uitlezen wat erop staat → laatste 4 cijfers van het
  serienummer overtypen → 3 s ingedrukt houden → opnieuw insteken (USB) of opnieuw tegen de telefoon (NFC,
  YubiKey 5) → zelfde-sleutelcontrole op serienummer + AAGUID → `authenticatorReset` + aanraking → nalezen
  (geen PIN, geen vingers) → direct opnieuw inrichten. Ook als knop op M11 bij de afwijzings-stops.
- Nieuwe stops `RESET_NO_SERIAL`, `RESET_OTHER_KEY`, `RESET_READBACK_FAILED`; `KeyError.ResetWindowPassed`
  (CTAP NOT_ALLOWED bij reset = te laat na insteken → opnieuw insteken, bevestiging blijft geldig).
- Tests: `ResetFlowTest` (12) en 4 ViewModel-tests; nep-YubiKey met resetvenster. 267/267 groen.

### Changed
- Bronbeleid: reset alleen in `yubikey/YubikitResetOps.kt` en alleen aangeroepen door `flow/ResetFlow.kt`
  (`YubikeyFlowSourcePolicyTest.resetAlleenInYubikitResetOps`); `deleteCredential`, `deviceReset`,
  `updateDeviceConfig` en `setMode` blijven verboden.
- Adviesteksten van de afwijzings-stops verwijzen naar "Sleutel wissen" i.p.v. "reset buiten de app".
- Wissen is geblokkeerd door dezelfde omgevingsbewaking als de PIN-schermen (a11y, ADB, opname, …).

## [0.3.0-Miller] — 2026-10-12 (Miller deel 1; repo, APK nog niet gepubliceerd)

Android-app voor het inrichten en keuren van de YubiKeys. Bouwplan + kritiekcorrecties: akkoord Christian 12-10
(`docs/HARDWARE_KEYS.md` §11.1). Backend en web wijzigen functioneel niet; geen deploy nodig.

### Added — `android/` (`nl.icthorse.horsesafe`, versionCode 300)
- **Inrichten** van de hoofdsleutel (YubiKey Bio) en de noodsleutel (YubiKey 5 NFC, of Bio zonder vinger):
  PIN van 63 tekens (9 groepen van 7 met controleteken mod 29, alfabet van 29), tonen per groep met
  hold-to-reveal, overschrijven op papier, alle 9 groepen hertypen; attestation-keuring tot de Yubico-roots
  (YK5 vóór setPin; Bio vóór setPin bij alwaysUv=false, anders direct erna en vóór het minimum);
  `setMinPinLength(63, ["icthorsecloud.nl"])` na een expliciete onomkeerbaar-bevestiging; alwaysUv; 2-3 vingers
  met testaanraking (alleen hoofdsleutel). Elke schrijfactie vers teruggelezen; per stap een token met één permissie.
- **Inrichting hervatten** voor een sleutel waarop de PIN al staat maar de rest niet (crash, uittrekken, STOP na setPin).
- **Keuren zonder PIN** (ook via NFC) en **met PIN**, **PIN wijzigen**, **vingers beheren** (toevoegen, hernoemen,
  verwijderen, testaanraking), **oefenen** (papier controleren zonder sleutel; optioneel één echte controle met CM-token).
- **Rapport zonder geheimen** (whitelist; serienummer alleen als HMAC met app-privé Keystore-sleutel), app-privé
  bewaard, export en import via de opslagkiezer; vergelijking met een basis uit het verleden, eigen app-sleutel eerst;
  een inrichtingsrapport wordt de nieuwe basis.
- **Poorten (STOP):** firmware Bio < 5.7.2 / YubiKey 5 < 5.7.0 (YSA-2024-03), geen FIDO 2.1-config, AAGUID niet
  toegestaan of klasse past niet, `maxPINLength` < 63 of onbekend, al gebruikte sleutel, YK5 met alwaysUv al aan
  zonder PIN, vinger op een noodsleutel; nieuwe stops o.a. `PIN_STATE_UNKNOWN`, `UV_BLOCKED`,
  `YK5_ALWAYS_UV_PRESET`, `RECOVERY_KEY_NO_FINGERS`. U2F_V2 na alwaysUv: oranje.
- **Hardening:** geen INTERNET; FLAG_SECURE, overlays verborgen, schermopname-detectie; PIN-schermen geblokkeerd
  bij a11y-dienst, multi-window/DeX/ander display, opname en (release) ontwikkelaarsopties/ADB; eigen
  toetsenblok, hardwaretoetsen geslikt; PIN alleen in een gewiste CharArray; geen logging; "Afsluiten"
  beëindigt het proces; geen back-up; geen USB-intent-filter; `OtpActivity`, `YubiKeyPromptActivity`,
  `InitializationProvider` en `ProfileInstallReceiver` verwijderd.
- **Build:** yubikit 3.0.1 gepind met `:app:verifyYubikitHashes`; `:app:verifyNoSlf4jProvider`; versie uit
  `version.json`; release niet-debuggable en geminificeerd, getekend met de debug-keystore van HC55
  (signer `32491e0f…3f17`); `scripts/verify_apk.sh` (apksigner + aapt2) en `scripts/smoke.sh` (emulator, niet gedraaid).
- **Tests:** 250 JVM-tests (FakeYubiKey + echte yubikit-code via CTAPHID-fake, volgorde per profiel, crash/hervat,
  attestation, whitelist, canary-lektest, bronbeleid, release-manifest).

### Changed
- `version.json` 0.3.0 / Miller, phase 11; `backend/config.py` `app_version` en `backend/tests/test_health.py` → `0.3.0-Miller`;
  footer `frontend/vault.html`.
- `docs/HARDWARE_KEYS.md` §4.1 (inrichten gebeurt nu in de app), §7 (7.1 gebouwd / 7.2 deel 2), §9 (R4 bijgewerkt,
  R16–R21), §10 (Miller in delen, versieregel 0.3.x), §11.1; `THREAT_MODEL.md`, `ROADMAP.md`, `ACTIONS.md`,
  `UI_DESIGN.md` + `docs/screens/M00..M12`, `README.md`.

### Known issues / open
- Niet getest op een toestel of met een echte YubiKey; emulator-smoke en androidTest ontbreken.
- Server dwingt minPinLength/credProtect nog niet af en weigert MPE niet bij het koppelen (THREAT_MODEL R18).
- CI bouwt `android/` nog niet (geen job `android`).

## [0.2.1-Koblitz] — 2026-10-11 (repo; nog niet gedeployed)

Open punten van Koblitz uit `ACTIONS.md`. Geen functionele wijziging aan backend of frontend.

### Fixed
- **e2e raakte productie:** de specs `admin`, `mfa` en `smoke` gebruikten de backend op :3997 — op HC55 is dat LIVE. Ze draaien nu via `frontend/tests/isolated.ts` op een eigen tijdelijke backend per worker (`tests/e2e-stack.ts`); een vangnet breekt elk verzoek naar :3997 af en laat de test falen.
- **Deploy kopieerde dev-bestanden naar de webroot:** `devserver.py`, `README.md`, `tests/`, `package*.json` en `playwright.config.ts` stonden in `/opt/horsesafe/web/` (publiek leesbaar, geen geheimen). `scripts/deploy_hc55.sh` en het runbook sluiten ze uit; ze verdwijnen bij de volgende deploy.
- `backend/app.py` black-conform (CI-stap "Black format check").

### Changed
- **CI:** job "Frontend unit + e2e": `node --test tests/unit/` en Playwright met de WebAuthn virtual authenticator; geen gedeelde backend op :3997 meer.
- **`scripts/deploy_hc55.sh`:** `.env`-sjabloon met `HORSESAFE_SMTP_*`, `HORSESAFE_WEBAUTHN_*` en `HORSESAFE_TEST_ATTESTATION=false`.
- **`DEPLOYMENT.md` + `docs/DEPLOY_HC55_LIVE.md`:** kopie- in plaats van symlinkmodel, verplichte backup vóór elke update-deploy, rollback inclusief DB-backup bij migraties.
- **`PRIVACY_STATEMENT.md` (0.2.1) + `GDPR_COMPLIANCE.md`:** Hostinger als SMTP-subverwerker, Gmail alleen nog uitgeschakelde reserve; sleutelmetadata, verzegelde kopie, challenges en meldingsmails met doel, grondslag en bewaartermijn; vingerafdruk wordt niet verwerkt (DPIA §9).
- **`UI_DESIGN.md` + `docs/screens/`:** S6 uitgebreid met de YubiKey-route; nieuw S14 Sleutelbeheer, S15 Step-up, S16 Wachtwoord/keyfile wijzigen.

## [0.2.0-Koblitz] — 2026-10-10 (LIVE 2026-10-11)

Ontwerp en bindend contract: `docs/HARDWARE_KEYS.md` (§12). Besluiten Christian 10-10-2026: zie §11 daarvan.

### Added — Hardware-sleutels per vault (web + backend)

- **Ontgrendelen met een YubiKey Bio** in Chrome/Edge op de laptop via WebAuthn PRF (hmac-secret). Eén vingerafdruk opent de vault; wachtwoord + keyfile blijven de basis en de KeePassXC-noodroute.
- **Server-geverifieerde WebAuthn** met py_webauthn: `packed`-attestation tot de gevendorde Yubico FIDO-roots (`backend/data/yubico_fido_roots.pem`), AAGUID-allowlist uit FIDO MDS3 (`backend/data/aaguids.json`, reproduceerbaar via `backend/tools/build_aaguids.py` en `build_yubico_roots.py`), UV=1, BE=0/BS=0 (geen gesynchroniseerde passkeys, geen Windows Hello/Touch ID), origin/rpId-controle, signCount-regressie → 409 + audit `vault_key_clone_suspect`. Challenges eenmalig, gehasht opgeslagen en vóór de controles atomair verbruikt.
- **Seal_v2** (P-CRYPT-09): verzegelde ontgrendelkopie `{ph,kh}` per sleutel naar een X25519-publieke sleutel die uit de PRF wordt afgeleid (HKDF-SHA256 → X25519 → HKDF → AES-256-GCM; AAD = `HSv2`, purpose, vault_id, key_id). Server controleert alleen de vorm (`validate_sealed`). Testvectoren in `specs/testvectors/seal_v2.json`, gegenereerd door `specs/testvectors/gen_seal_v2.py` (Python-referentie, vaste invoer); pytest en `node --test` controleren ze zonder overslaan.
- **Noodsleutel** (`kind='recovery'`, reserve-YubiKey met PIN van 63 tekens): vrijgave na 24 uur wachttijd, daarna 24 uur venster, één keer bruikbaar. Annuleren, blokkeren (zonder step-up) en blokkade opheffen (alleen met Bio-step-up, besluit 3). Vrijgave wordt geweigerd zonder meldkanaal (503 `notify_unavailable`) en teruggedraaid als de melding niet afgeleverd kan worden (503 `notify_failed`).
- **Step-up** `POST /auth/stepup` (Bio, of TOTP zolang er geen actieve Bio-sleutel is), 300 s geldig als JWT-claims `stepup_until`/`stepup_method`. Verplicht voor een tweede sleutel, opnieuw verzegelen, rekey en blokkade opheffen.
- **Wachtwoord/keyfile wijzigen** `PUT /vault/{vid}/rekey` (multipart, SU + If-Match): blob en alle verzegelde kopieën in één atomaire stap; YubiKeys niet nodig. **Opnieuw verzegelen** `PUT /vault/{vid}/keys/sealed` voor na een wijziging in KeePassXC ("kopie verouderd").
- **Endpoints:** `POST /webauthn/options`, `GET/POST /vault/{vid}/keys`, `POST /vault/{vid}/keys/{kid}/unlock`, `PUT /vault/{vid}/keys/sealed`, `PUT /vault/{vid}/rekey`, `POST/DELETE …/{kid}/release`, `POST/DELETE …/{kid}/block`, `DELETE /vault/{vid}/keys/{kid}`, `POST /auth/stepup`. Details in `API.md`.
- **Generieke SMTP-mailer** (`backend/services/mail_service.py`, besluit 4): `HORSESAFE_SMTP_HOST/PORT/USER/PASSWORD/FROM/STARTTLS/TIMEOUT_SECONDS`, poort 587 met STARTTLS, From = SMTP-gebruiker. Meldingen (`asyncio.to_thread`, buiten de DB-verbinding) bij koppelen, verwijderen, vrijgave aanvragen/annuleren/gebruiken, blokkeren/opheffen, rekey en clone-vermoeden. De magic-link loopt nu ook via deze mailer; `gmail_*`-settings blijven als fallback (SMTP_SSL 465 werkt niet op HC55).
- **Frontend:** `js/hwkeys.js` (WebAuthn + Seal_v2 + fail-closed clientcontroles), `js/hwkeys-ui.js` (sleutelbeheer met statussen in gewone taal), `js/stepup.js` (step-up-dialoog), ontgrendelscherm met keuze YubiKey/Keyfile, wijzig-wachtwoord/keyfile-flow. `state.secret` = `{ph,kh}` als `ProtectedValue`, nooit strings.
- **Audit-events:** `vault_key_add`, `vault_key_add_rejected`, `vault_key_delete`, `vault_key_unlock`, `vault_key_reseal`, `vault_key_clone_suspect`, `vault_rekey`, `recovery_release_request`, `recovery_release_cancel`, `recovery_key_used`, `recovery_block`, `recovery_unblock`, `recovery_unblock_rejected`, `stepup`, `stepup_fail`, `notify_failed`. Nooit `sealed`, `ph`, `kh`, PRF-uitvoer, challenges, assertions of SMTP-gegevens.
- **`/health`** toont `"test_attestation": <bool>`; `create_app()` weigert te starten als `HORSESAFE_TEST_ATTESTATION` aan staat met rpId `icthorsecloud.nl`.

### Changed

- **Migratie 005 herschreven** (`vault_keys`, `webauthn_challenges`, lege `devices` voor Miller); schema-versie 5; `schema.sql` = alle migraties. De WIP-005 uit commit `9000044` is nooit gedeployed; dev-DB's die hem al hadden opnieuw aanmaken.
- **`GET /vault/{vid}/keys`** geeft een object `{keys, notify_available, stepup_until}` in plaats van een kale lijst. `GET …/{kid}/sealed` (WIP) vervalt; vervangen door `POST …/{kid}/unlock` met assertion.
- **Sealed v1** (`{pw,kf}` als leesbare strings, WIP-concept) vervalt, nooit live geweest.
- **Principes:** nieuw P-CRYPT-09, P-AUTH-07, P-AUTH-08, P-OPS-07; `CLAUDE.md:53` geherformuleerd (besluit 1).
- **ROADMAP:** v0.2.0 Koblitz, v0.3.0 Miller, v0.4.0 Montgomery, v0.5.0 Lange (niet bouwen); Schneier en verdere items schuiven door (besluit 2).
- **Dependency:** `webauthn>=2.2,<3` (py_webauthn; trekt `cbor2`, `pyOpenSSL`, `pyasn1` mee). Getest: 2.7.1 met `cryptography` 45.0.7 binnen de bestaande grens `>=43,<46`.

### Fixed — reviewronde 1 (vóór deploy)

- **TOTP-secret overschrijven met alleen het accountwachtwoord** (sessie met `mfa=false`) gaf S + TOTP-step-up en zo, via een eigen Bio, het opheffen van een blokkade (besluit 3). Nu: bestaand TOTP vervangen → 409 `totp_already_configured`; met hardware-sleutels alleen instellen vanuit een MFA-sessie; mail + audit bij elke TOTP-wijziging.
- **R6 aangescherpt:** TOTP-step-up 24 u geweigerd (`stepup_cooldown`) na het verwijderen van een Bio of het instellen van TOTP met bestaande sleutels; deblokkeren alleen met een Bio die al gekoppeld was vóór de blokkade (JWT-claim `stepup_key`, 403 `stepup_key_too_new`, audit `recovery_unblock_rejected`).
- **Rekey/opnieuw verzegelen:** de client toont elke sleutel die het materiaal krijgt (recent gekoppeld gemarkeerd) en vraagt bevestiging, zodat een door een aanvaller gekoppelde sleutel niet stil de echte `{ph,kh}` krijgt.
- **Rekey verloor stil de keyfile** (of het wachtwoord) als alleen het andere onderdeel werd ingevuld; nu blijft een leeg veld het huidige onderdeel, verwijderen gaat via een expliciet vinkje (`credentialsForRekey`).
- **Kritiek: keyfile van 32 bytes via rekey** — kdbxweb gebruikt die buffer in place; het wissen ervan in `finally` beschadigde `db.credentials`, waarna de eerstvolgende save de kluis onopenbaar maakte. kdbxweb krijgt nu een kopie en de nieuwe Credentials worden uit gekopieerde hashes opgebouwd.
- **Step-up-dialoog** viel in Safari/zonder X25519/op een andere host nooit terug op TOTP; nu wel (niet bij opheffen).

### Fixed — reviewronde 2 (vóór deploy, HS-BUG-008)

- **MFA-omweg via backup-codes** (ook in LIVE v0.1.0-Massey): `POST /auth/backup-codes/generate` werkte met alleen het accountwachtwoord; daarna gaf `/backup-codes/verify` een `mfa=true`-sessie, en daarmee S (sleutels verwijderen, vrijgave aanvragen, blokkeren). Nu 403 `mfa_required` zonder MFA; bestaande codes blijven dan geldig.
- **Magic-link was een volledige login** (mailbox alleen = S; de Koblitz-meldingen gaan naar diezelfde mailbox). Nu uitsluitend een tweede stap: verzilveren vereist een wachtwoordsessie van dezelfde gebruiker in dezelfde browser; anders geweigerd en niet verbruikt (`login.html?error=magic_link_login_first`). Mailtekst, MFA-scherm en loginscherm aangepast. Besluit vastgelegd in THREAT_MODEL en `docs/HARDWARE_KEYS.md` §9 (R14).
- **Verwisselde publieke sleutel** (DB-schrijver, gemanipuleerde back-up): reseal/rekey verzegelde naar `public_key` zoals de server die gaf. Nu legt de client `{key_id: public_key}` bij het koppelen vast in de versleutelde KDBX (CustomData `HorseSafe.KeyPins.v1`, eerst opslaan, dan koppelen) en verzegelt alleen naar sleutels die daar exact zo staan (`key_pin_mismatch`/`key_not_pinned`, niets verzegeld); het sleutelpaneel waarschuwt (R15).
- **Rekey met verloren antwoord** (504/netwerk na de COMMIT): de tab zette de oude credentials terug terwijl de server al op het nieuwe wachtwoord stond. Nu: expliciete serverweigering = niets doorgevoerd; onbekende uitkomst → `rekey_unknown` en controle via de etag (SHA-256 van de verstuurde blob); doorgevoerd → nieuwe credentials overnemen; niet vast te stellen → kluis vergrendelen met uitleg. De rekey-meldmail gaat nu ná het antwoord (`BackgroundTask`).
- **Tweede save op rij gaf 422** (ook in LIVE v0.1.0-Massey): `PUT /vault/{id}` stuurde geen `ETag`-header, de frontend las alleen die en verloor zo de etag. Nu header én body-fallback.
- **Seal_v2-testvectoren toegevoegd** (`specs/testvectors/gen_seal_v2.py` + `seal_v2.json`: 3 PRF-vectoren, `ph+kh`, `alleen ph`, `alleen kh`, negatief: andere vault_id/key_id/purpose, gewijzigde ct). De vectortests worden niet meer overgeslagen.

### Fixed — reviewronde 3 (vóór deploy, HS-BUG-009)

- **TOTP-afkoelperiode omzeilbaar via kluis verwijderen** (R6): `DELETE /vault/{vid}` liet de sleutels via `ON DELETE CASCADE` stil verdwijnen, zonder `vault_key_delete`-audit en zonder mail. Wie wachtwoord + TOTP had, gooide een bijkluis met de enige Bio weg en kreeg direct een TOTP-step-up. Nu: per sleutel audit `vault_key_delete` `{…, via:"vault_delete"}` (telt mee voor `stepup_cooldown`) en mail "sleutel verwijderd".
- **Magic-link onbruikbaar vanuit webmail:** het sessie-cookie is `SameSite=Strict` en gaat bij een klik in webmail (cross-site) niet mee, dus de redeem eindigde altijd in `magic_link_login_first`. Nu linkt de mail naar `mfa.html#ml=<token>`; die pagina verzilvert met een same-site `POST /auth/magic-link/redeem` waarbij het cookie wel meegaat. `GET /auth/magic-link/redeem` stuurt oudere links zonder bijwerkingen door. Bijvangst: de oude link (`<public_url>/auth/magic-link/redeem`) viel in productie onder de statische `/HorseSafe/`-locatie en bereikte de API niet.
- **Save kon een rekey overschrijven:** `PUT /vault/{id}` controleerde de etag buiten een transactie en zette de nieuwe etag zonder `WHERE etag = ?`. Een save tegelijk met `/rekey` kon de gerekeyde blob vervangen door een KDBX onder de oude credentials, terwijl alle verzegelde kopieën al nieuw waren. Nu `BEGIN IMMEDIATE` → etag-controle → `UPDATE … WHERE etag = ?` → blob → `COMMIT`, zoals `/rekey`.

### Fixed — bevindingen uit de verkenning van de WIP (HS-BUG-007)

- Annuleren zonder lopende vrijgave gaf 200; nu 409 `nothing_to_cancel`.
- Audit `vault_key_add` werd geschreven vóór de verificatie; nu pas na de INSERT (afwijzing: `vault_key_add_rejected`).
- Blokkerende SMTP-aanroep in de event-loop; nu `asyncio.to_thread`, buiten de DB-verbinding.
- Client ging fail-open door als `getAuthenticatorData` ontbrak; nu `browser_unsupported`.
- `find()` zonder null-guard in `hwkeys-ui.js`.
- Migratie gebruikte `DELETE FROM schema_version`; nu `INSERT OR REPLACE`.

### Tests

- Te meten (pytest met coverage ≥ 80%, `node --test`, Playwright met CDP virtual authenticator, kdbx-oracle). Uitkomsten worden in `version.json` vastgelegd.

### Notes

- **Zero-knowledge:** de server krijgt alleen `pk_c` en een verzegelde kopie die hij aantoonbaar niet kan openen (P-CRYPT-09). Wachtwoord, keyfile en afgeleide sleutel verlaten de browser nog steeds nooit.
- **Bewust niet in Koblitz:** `kind='phone'`, device-endpoints, pairing, approvals, JWT-claim `sid`, FCM, native kluis (§12.15).
- **Deploy:** nog niet. SMTP-gegevens komen in `/opt/horsesafe/.env` (alleen variabelenamen in docs).


## [0.1.0-Massey] — 2026-07-20

### Added — Public launch

- **Publieke URL `icthorse.nl/HorseSafe/`** — Hostinger subdir-`.htaccess` (302 → `icthorsecloud.nl/HorseSafe/`), subpath behouden. Zelfde geïsoleerde patroon als StaffKennis/VeiligDelen; WordPress-root ongemoeid. Beide casings (`/HorseSafe/` + `/horsesafe/`) geredirect.
- **AGPL-3.0** — repo publiek na schone secret-scan van de volledige git-history.

### Changed — Security-hardening (pen-test-checklist v0.1.0)

- **OpenAPI-docs dicht in productie** (`backend/app.py` + `config.py`): nieuwe setting `docs_enabled` (default `false`) zet `docs_url`/`redoc_url`/`openapi_url` op `None`. Voorheen waren `/docs`, `/redoc` en `/openapi.json` publiek (200) → onthulden de volledige API-oppervlakte van een zero-knowledge dienst. Dev/test kan docs aanzetten via `HORSESAFE_DOCS_ENABLED=true`.

### Verified — Pen-test-checklist (LIVE-probing, geen bevindingen open)

- Security-headers compleet (HSTS, CSP strak, X-Frame DENY, nosniff, referrer no-referrer).
- Auth-bypass geblokt (`/api/vault` zonder cookie → 401).
- Path-traversal in `/vault/{id}` → 401 (geen file-read).
- SQL-injection in login-email → Pydantic email-validatie weigert (422); ORM parametriseert.
- Rate-limit login → 429 na 4 mislukte pogingen.
- Geen cross-origin CORS toegestaan (lege `cors_origins` in productie).
- Geen `Set-Cookie` op mislukte/gerate-limite login.

## [0.0.9-Bellare] — 2026-06-05

### Added — Vault-open met pw én/of keyfile + per-entry live TOTP-renderer

- **Keyfile-input op vault-open** (`frontend/vault.html` unlock-form): `<input type="file" id="vault-keyfile" accept=".keyx,.key,.keyfile,application/octet-stream">`. Wachtwoord óf keyfile is verplicht; beide combineren werkt KeePassXC-compatibel.
- **`openDatabase(blobBuffer, masterPassword, keyFileBuffer)`** (`frontend/js/crypto.js`): uitgebreid met optionele keyfile-arg. Coerced naar `ArrayBuffer`. Wacht expliciet op `credentials.ready` (async Credentials-constructor in kdbxweb 2.1.1).
- **`vault-ui.js` `unlockOrCreate`**: leest `<input type="file">` → `.arrayBuffer()` → geeft door aan `openDatabase`. Strikte input-validatie (pw of keyfile vereist; pw min 6 als gezet).
- **Per-entry live TOTP-renderer** (`frontend/js/totp.js`, ~85 regels nieuw): RFC 6238 via `crypto.subtle.sign('HMAC')`. Default SHA-1 / 6 digits / 30s, override via `otpauth://`-URI-params (`algorithm`, `digits`, `period`). Base32-decoder + dynamic truncation per RFC 4226. Geen externe lib.
- **`listEntries()` extractie van `otp`-veld** (`frontend/js/crypto.js`): KeePassXC-compatibele custom-string `otp` met `otpauth://`-URI; afhandeling van zowel ProtectedValue als plain string.
- **Entry-detail UI** (`frontend/vault.html`): nieuwe rij `TOTP` (initieel hidden) met 6-cijferige code in monospace 1.3em + letter-spacing 0.15em + groep-spatie, seconden-countdown rechts, 📋-copy-button. Toont alleen als entry een geldig otpauth-veld heeft.
- **TOTP-loop lifecycle** (`frontend/js/vault-ui.js`): `state.totpTimer` interval start in `selectEntry` (refresh 1s), stop in `lockVault` en bij entry-wissel.
- **TOTP-copy** (`frontend/js/main.js`): wire-up van `d-totp-copy` event-binding naar `UI.copyTotp()`.

### Changed — Keyfile-format default (cryptografische defaults)

- **Default-keyfile-format gewijzigd** van KeePassXC 2.x XML naar **64-hex-char ASCII** (KeePass 1.x-spec-pad). Reden: kdbxweb 2.1.1 browser-side faalt op XML 2.0 + 32-byte raw keyfiles met `InvalidKey`, terwijl Node-side en pykeepass beide werken (zie HS-BUG-005 + RCA).
- **Live vault-blob** voor `cglebbeek@gmail.com` op HorseCloud55 herversleuteld met pw + 64-hex-ASCII keyfile (etag `99f60239d80c7e04412b8c156ab18c5bd721be596ac92389aa7cb0f46d0864d5`, 6887 B).
- **Lokale Database-pair** (`~/Downloads/Database.{kdbx,keyx}`) overschreven met v5; originelen `.bak-20260605` bewaard.
- **CLAUDE.md "Cryptografische defaults"-tabel** is nu STALE; update gepland voor v0.1.0-Massey.

### Fixed — HS-BUG-005

- 🟡 Geel — kdbxweb 2.1.1 browser-side faalt op XML 2.0 keyfile en op 32-byte raw keyfile. Workaround: format-shift naar 64-hex-ASCII (3-runtime roundtrip bewezen: kdbxweb-browser ↔ kdbxweb-Node ↔ pykeepass).

### Migration

- **Wipe + re-register**: alle LIVE-users + vaults op HorseCloud55 weggegooid (2 users → 0). Nieuwe single-user setup: `cglebbeek@gmail.com` met account-pw `[REDACTED-ACCOUNT-PW]` (account-laag) + vault-master-pw `[REDACTED-VAULT-PW]` + keyfile `Database.keyx` (vault-laag).
- **KeePass-import als upstream**: 33 entries uit `~/Downloads/Database.kdbx` (gegenereerd via pykeepass uit oorspronkelijke `SECURITY_CREDENTIALS_2026-04-12.md` + MCP-credentials + Tuya API-keys + TOTP-seeds + SSH-pointers + Gmail-recovery-codes) als initiele HorseSafe-vault-blob.

### Notes

- **Zero-knowledge ongebroken**: keyfile-bytes en master-pw verlaten browser nooit; Node-resave was lokaal op Mac; server zag alleen ciphertext-blobs en etag-hashes.
- **Backend ongewijzigd**: alleen frontend-files gepatcht; SQLite-schema, FastAPI-routes en systemd-unit identiek aan v0.0.8-Rogaway.
- **CI-eis "KDBX4-roundtrip groen"** is NIET gerund vóór deze deploy — gepland voor v0.0.10/v0.1.0-Massey met uitgebreide keyfile-format-fixture (XML 2.0 + 32-byte raw + 64-hex-ASCII).
- **api/health version-string** toont nog `0.0.8-Rogaway` (backend hardcoded) — gepland voor v0.0.10.

## [0.0.8-Rogaway] — 2026-05-18

### Added — XLSX-import + XLSX-export

- **SheetJS Community 0.18.5 vendored** (`frontend/vendor/sheetjs/xlsx.mini.min.js`, 245 KB, Apache-2.0). Mini-build zonder styling/codepage — voldoet voor plaintext import/export.
- **`parseXlsx(arrayBuffer)`** in `frontend/js/import-export.js`: leest eerste sheet, header-row case-insensitive op `Title|Username|Password|URL|Notes` (`Title` + `Password` verplicht).
- **`buildXlsx(entries)`** in `frontend/js/import-export.js`: schrijft één sheet `HorseSafe` met dezelfde 5 kolommen, retourneert `Uint8Array` (browser-friendly download).
- **`import.html`** dropdown: optie `xlsx — XLSX (Excel-werkblad)` + `<script src="vendor/sheetjs/xlsx.mini.min.js">`.
- **`export.html`** dropdown: optie `xlsx — XLSX (Excel-werkblad, PLAINTEXT)` + zelfde script-include.
- **`page-import.js` + `page-export.js`** branches voor `fmt === 'xlsx'`: arraybuffer → entries (import) en entries → arraybuffer met MIME `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` (export).
- **`frontend/vendor/README.md`**: sheetjs-sectie toegevoegd met versie/licentie/bron/doel.

### Notes

- XLSX-export is **PLAINTEXT** — zelfde audit-log + reden vereist als CSV/JSON (audit-import endpoint blijft ongewijzigd, format-string `xlsx`).
- Zero-knowledge ongewijzigd: parsing/building gebeurt volledig client-side; server ziet alleen ciphertext (KDBX4) + audit-events.
- Geen back-end-mutaties; geen migratie; geen versiebump van schema.

## [0.0.7-Bellare] — 2026-05-22

### Added — Productie-deploy HorseCloud55 LIVE

**LIVE op:** `https://icthorsecloud.nl/HorseSafe/`

**Server-state op HC55:**
- `/opt/horsesafe/` met `repo/`, `venv/`, `db/`, `vaults/`, `logs/`, `tmp/`, `web/`
- System-user `horsesafe` (no-login, no-shell)
- systemd-unit `/etc/systemd/system/horsesafe.service` → **active, enabled**
- nginx-snippet `/etc/nginx/snippets/horsesafe.conf` met `auth_basic off` voor beide HorseSafe-locations (eigen JWT+MFA)
- nginx-include in horsecloud-server-block (port 443)
- `/etc/cron.d/horsesafe-backup` — nightly 03:00 rsync naar Storagebox (skip indien target niet gezet)
- `.env` met random JWT_SECRET + TOTP_ENCRYPTION_KEY (32 bytes hex elk) + bcrypt-rounds=12

**Repo-artefacten:**
- `scripts/deploy_hc55.sh` — idempotente bootstrap
- `scripts/horsesafe.service` — systemd-unit met full hardening
- `scripts/nginx_snippet.conf` — appendable include met `auth_basic off`
- `scripts/backup_to_storagebox.sh` — nightly rsync + sqlite-snapshot-tar + retentie
- `scripts/post_deploy_smoke.sh` — curl-only roundtrip-test
- `docs/DEPLOY_HC55_LIVE.md` — runbook

**Live-smoke-test (uitgevoerd, groen):**
- ✓ GET /health → {"status":"ok","version":"0.0.6-Adleman","db":"ok","vaults_dir":"ok"}
- ✓ POST /auth/register → user_id
- ✓ POST /auth/login → JWT-cookie + mfa_required=false
- ✓ GET /vault → []
- ✓ GET /auth/me → has_keypair=false
- ✓ POST /auth/logout → ok

**Updates:**
- `Meta_Master/SHARED_INFRASTRUCTURE.md` — poort 3997 "gereserveerd" → LIVE
- `version.json` + `backend/config.py` `app_version` → 0.0.7-Bellare

### Decided

- **URL**: `icthorsecloud.nl/HorseSafe/` (intern, achter LE-TLS); `icthorse.nl/HorseSafe/` v0.1.0
- **`auth_basic off`** voor /HorseSafe/* (eigen JWT+MFA)
- **Deploy-strategie**: optie (c) uit WhatIf — AI provisioneert + dry-run; gebruiker approve't laatste 2 stappen
- **Eerste admin**: niet automatisch — handmatig promote na eerste-user-registratie
- **Backup-target**: nog niet geconfigureerd in .env (HORSESAFE_BACKUP_TARGET leeg)

### Operationele stappen tijdens deploy

1. ✅ Pre-check: Python 3.12, port 3997 vrij, geen pre-existing /opt/horsesafe
2. ✅ Bootstrap als root op HC55
3. ✅ Git clone via PAT in `/root/.git-credentials`
4. ✅ Dry-run validatie: nginx -t OK, systemd-analyze OK
5. ⚠️ Snippet-bug ontdekt + gefixed: `auth_basic off` toegevoegd voor beide locations (eerste run gaf 401 wegens basic-auth)
6. ✅ Include in horsecloud-server-block (1 regel toegevoegd na server_name)
7. ✅ nginx -t && systemctl reload nginx
8. ✅ systemctl enable --now horsesafe → active (running)
9. ✅ Smoke-test live: full register/login/vault/me/logout roundtrip
10. ✅ Cleanup smoke-account

### Not Yet (v0.1.0-Massey)

- icthorse.nl/HorseSafe/ (Hostinger DNS)
- Externe pen-test
- Open-source-beslissing (AGPL-3.0 voorgesteld)
- Dashboard-tile health-monitoring
- Public launch + LinkedIn-aankondiging

### Niet kritiek (v1.0-Bernstein of later)

- HORSESAFE_BACKUP_TARGET configureren
- HORSESAFE_GMAIL_USER/PASSWORD voor magic-link
- Eerste admin promoveren bij echte first-user
- Argon2id KDF re-evaluatie

## [0.0.6-Adleman] — 2026-05-21

### Added — Vault-sharing tussen users via ECDH-P256

**Backend (+13 tests, 67/67 ✅):**
- `routes/shares.py` — 7 nieuwe endpoints:
  - POST /keypair — set pubkey + encrypted_privkey
  - POST /keypair/rewrap — vervang encrypted_privkey bij pw-change
  - GET /keypair — haal eigen keypair op
  - GET /users/by-email/{email}/pubkey — lookup pubkey voor share-encryptie
  - POST /shares — encrypted share-payload naar ontvanger
  - GET /shares/inbox — pending ontvangen shares
  - GET /shares/sent — verzonden shares (alle statussen)
  - POST /shares/{id}/accept + /decline
- `services/share_service.py` — keypair-CRUD + share-CRUD + pubkey-lookup-by-email
- `models/share.py` — KeypairSet/Rewrap, ShareCreate, ShareInboxItem, PubkeyResponse
- `models/audit.py` — +4 events: keypair_generated, share_create, share_accept, share_decline
- `models/admin.py` — MeResponse.has_keypair toegevoegd
- `routes/auth.py` — /auth/me returnt nu has_keypair
- `db/migrate.py` + `migrations/004_sharing.sql` — ALTER users (+pubkey, +encrypted_privkey) + CREATE shares
- `db/schema.sql` — schema-version bumped naar 4 (fresh-install bevat alle migrations)
- `tests/test_sharing.py` — 13 tests

**Frontend:**
- `js/sharing.js` — ECDH-P256 (WebCrypto native, geen externe lib):
  - generateKeypair(masterPw, userId) — random ECDH-P256 + AES-GCM-wrapped private via PBKDF2-key
  - unwrapPrivateKey(masterPw, userId, encryptedPrivkey)
  - encryptForRecipient(pubkey, plaintext) — ephemeral ECDH + AES-GCM
  - decryptFromSender(myPriv, encryptedPayload) — ECDH-shared-secret + AES-GCM
- `shares.html` (S14) — Inbox + Verzonden + decryptie-pane voor inkomende shares
- `settings.html` — Keypair-status + generate-form + "Shares-inbox"-link
- `vault.html` — "📥 Shares" knop in top-bar + "🤝 Deel" knop in detail-pane
- `js/main.js` — share-flow in detail-pane: prompt email → lookup pubkey → encrypt entry → POST /shares
- `js/settings.js` — loadKeypairStatus + keypair-generate-form

**Crypto-ontwerp:**
- ECDH **P-256** (WebCrypto native; Curve25519 zou vendor 50KB vereisen)
- Private-key at-rest: AES-GCM-encrypted met PBKDF2-SHA256(vault-master-pw + user-id, 100k iter) → 256-bit AES-key
- Share-payload: ephemeral ECDH-keypair-bij-elke-share + AES-GCM-256 met ECDH-shared-secret
- Server ziet: pubkey (plain), encrypted_privkey (opaque), encrypted_payload (opaque)
- Server ziet NIET: private-key, share-content, master-pw, shared-secret

**Schema-migratie:**
- Migration 004: ALTER users + CREATE shares
- schema.sql bumped naar versie 4 (alle migrations 001-004 in fresh-install-blob — voorkomt ALTER-failure in nieuwe DBs)

### Decided

- **ECDH-P256** ipv Curve25519 (native in WebCrypto)
- **PBKDF2-SHA256 100k** voor private-key wrap-key derivation
- **Per-entry share-eenheid** (hele-vault sharing = v0.0.7+)
- **Per-email ontvanger** (multi-recipient = meerdere shares)
- **Lazy keypair-gen** via settings (niet automatisch bij login)
- **GEEN revocation** in v0.0.6 (zou re-encryption van alle bestaande shares vereisen)
- **GEEN multi-recipient** per share-actie
- **GEEN invite-naar-niet-bestaand-account** (404 + UI-melding)

### Changed
- `version.json` + `backend/config.py` `app_version` → 0.0.6-Adleman
- `schema_version` 3 → 4

### Not Yet
- Revocation, hele-vault sharing, multi-recipient, invite → v0.0.7+
- Curve25519 → v1.0-Bernstein (samen met PQC-overweging)

## [0.0.5-Shamir] — 2026-05-21

### Added — Import/Export + KeePassXC-CLI oracle + Admin-CSV + Account-pw-change

**Backend (+14 tests, 54/54 ✅):**
- `routes/vault.py` — 2 nieuwe endpoints:
  - `POST /vault/{id}/audit-import` `{format, count}` — server doet GEEN parse (client-side); audit-stamp na succesvolle frontend-merge
  - `POST /vault/{id}/audit-export` `{format, reason}` — reden VERPLICHT min 10 chars voor csv/json/xlsx; geen reden voor kdbx (encrypted)
- `routes/admin.py` — `GET /admin/audit/export?...` streaming CSV-response met filters (gelijk aan /admin/audit-query) + Content-Disposition: attachment
- `routes/auth.py` — `POST /auth/password` `{old_password, new_password}` — vereist JWT + oude-pw-verificatie + nieuwe-pw min 12 chars; event `account_password_changed`
- `services/pw_service.py` — `change_account_password()` met argon2id-verify + rehash
- `models/audit.py` — 2 nieuwe events: `account_password_changed`, `admin_audit_csv_export`
- Nieuwe pytest-tests:
  - `test_password_change.py` — 5 tests (unauth/happy/wrong-old/weak-new/missing-fields)
  - `test_import_export_audit.py` — 6 tests (kdbx-no-reason/csv-requires-reason/other-user-404/...)
  - `test_audit_csv.py` — 3 tests (admin-only/streaming/filter)

**Frontend:**
- `import.html` (S9) — wizard: format-select + bestand + KDBX-pw + vault-pw + conflict-strategie → preview-tabel → bevestig + merge + upload
- `export.html` (S10) — wizard: format-select + vault-pw + reden (bij plaintext) + ROOD warning-dialog voor csv/json
- `js/import-export.js` — library met `parseBitwardenJson()` + `parseKeePassCsv()` + `parseCSV()` (RFC 4180) + `buildCSV()` + `buildJSON()` (Bitwarden-compat) + `mergeEntriesInto()` (3 strategieën) + `extractEntries()` + `downloadBlob()`
- `vault.html` — "↓ Importeer" + "↑ Exporteer" buttons in top-bar
- `settings.html` — nieuwe sectie "Account-wachtwoord wijzigen" boven TOTP
- `js/settings.js` — pw-change-form met confirm-veld + error-mapping
- `admin.html` — "Exporteer CSV"-button naast filter
- `js/admin.js` — `f-export-csv` triggert browser-download van `/admin/audit/export`

**CI:**
- Nieuwe job `kdbx-oracle` na `backend`-job
- `apt-get install keepassxc` op ubuntu-runner
- Python-script: maakt KDBX4-vault via `keepassxc-cli db-create` + voegt entry toe + assert `keepassxc-cli ls` toont entry
- Bewijst dat KeePassXC-CLI in CI werkt voor latere import/export-validatie

**Docs:**
- `BUGS.md` HS-001 — Definitief deferred naar v1.0-Bernstein productie-pre-release (retry-vector blijft via devserver.py)
- `docs/screens/S09_import.md` + `S10_export.md`

### Decided

- **Client-side only**: server doet GEEN parsing van import-bestanden of export-content. Audit-endpoints registreren alleen event + reden. Zero-knowledge intact.
- **XLSX uitgesteld** naar v0.0.7+ (SheetJS is 700KB, weinig meerwaarde t.o.v. CSV)
- **Plaintext-export reden**: VERPLICHT (min 10 chars) + ROOD confirm-dialog + audit-log-event
- **KeePassXC-CLI oracle**: in CI als sanity-check; bewijst KDBX4-AES-KDF-roundtrip
- **Vault-pw-reset**: NIET geïmplementeerd — onmogelijk in zero-knowledge architectuur
- **Account-pw-vergeet**: magic-link → log in → settings → wijzig pw (geen e-mail-link-met-embed-token)
- **Argon2id-default**: definitief deferred naar v1.0-Bernstein (AES-KDF bewezen geverifieerd via CI-oracle)

### Changed
- `version.json` + `backend/config.py` `app_version` → 0.0.5-Shamir

### Not Yet
- XLSX import/export → v0.0.7+ (op user-request)
- Sharing tussen users → v0.0.6-Adleman (volgende)
- E-mail-link-met-embed-token voor reset → niet (security-risk vermijden)
- WebAuthn/FIDO2 → v0.5.0-Rogaway

## [0.0.4-Rivest] — 2026-05-21

### Added — Admin-paneel + MFA-backup-codes + /auth/me

**Backend (40/40 pytest ✅, +15 tests):**
- `routes/admin.py` — 6 nieuwe endpoints:
  - `GET /admin/users` — lijst met email/created/last_login/vault_count/storage_bytes/has_totp/backup_codes_remaining
  - `DELETE /admin/users/{id}` — cascade-delete (user + vault-blobs + magic-links + backup-codes), **reden verplicht** (min 10 chars), zelf-delete blokkering
  - `POST /admin/users/{id}/disable-mfa` — admin-rescue: TOTP + backup-codes weg
  - `POST /admin/users/{id}/send-magic-link` — naar USER's e-mail, niet admin's
  - `GET /admin/stats` — totaal users/vaults/storage + logins-24u + failed-24u + top10-by-storage
  - `GET /admin/audit?user=&event=&from=&to=&limit=&offset=` — paginated audit-log
  - `_require_admin()` dependency: vereist JWT + admin + MFA pass
- `services/admin_service.py` — user-CRUD-helpers + stats-aggregator + paginated audit-query
- `services/backup_codes_service.py` — bcrypt-hashed codes met look-alike-free alphabet (geen 0/O/1/I/L), single-use, generate-N + consume-by-plaintext + count_remaining
- `routes/auth.py` — 3 nieuwe endpoints:
  - `GET /auth/me` → `{id, email, is_admin, has_totp, backup_codes_remaining, mfa_pass, last_login_at}` (vervangt /vault-probe-hack)
  - `POST /auth/backup-codes/generate` → 10 plaintext codes show-once
  - `POST /auth/backup-codes/verify` → MFA-bypass via single-use backup-code (zelfde upgrade-pad als TOTP-verify)
- `models/admin.py` — Pydantic `AdminDeleteRequest`, `AdminRescueRequest`, `BackupCodeVerify`, `MeResponse`
- `models/audit.py` — 4 nieuwe events: `admin_user_disable_mfa`, `admin_user_send_magic_link`, `backup_codes_generate`, `backup_codes_consume`
- `db/migrate.py` — versie-gestuurde migration-runner (idempotent)
- `db/migrations/002_backup_codes.sql` — nieuwe tabel `users_backup_codes(id, user_id, code_hash, created_at, used_at)`
- `db/migrations/003_audit_log_no_check.sql` — verwijder hardcoded CHECK-constraint op audit_log.event (validatie via Pydantic AuditEvent)
- `db/promote_admin.py` — CLI: `python -m backend.db.promote_admin <email>` om eerste admin te maken
- `app.py` lifespan — run_migrations() bij startup; admin-router gemount op `/admin`
- `requirements.txt` — bcrypt>=4,<6 toegevoegd; passlib[argon2,bcrypt]-extras
- Nieuwe pytest-tests:
  - `tests/test_admin.py` — 7 tests (admin-required, list, delete, self-delete-forbidden, disable-mfa, stats, audit)
  - `tests/test_backup_codes.py` — 5 tests (generate, /me-reflects, consume-as-mfa, invalid-code, regenerate-invalidates-old)
  - `tests/test_auth_me.py` — 2 tests (unauth, after-login)
- conftest: `HORSESAFE_BCRYPT_ROUNDS=4` voor snelle test-runs

**Frontend (5/5 e2e ✅, +2 tests):**
- `admin.html` (S11) — stats-grid + users-tabel met inline actions (MFA-reset/magic-link/delete) + audit-viewer met filters/pagination
- `backup-codes.html` (S13) — show-once flow met checkbox-acknowledge + copy-all + beforeunload-warning
- `js/admin.js` — fetch-helpers met 401/403-handling + user-actions (reden-prompt + delete-confirm-by-email-typ) + stats + audit-paginated
- `js/backup-codes.js` — show-once + ack-checkbox + copy-to-clipboard + reload-warning bij niet-bevestigd
- `settings.html` — backup-codes-link sectie + admin-link in navigatie + footer-version-bump
- `js/settings.js` — gebruikt `/auth/me` ipv /vault-probe-hack; toont admin-link bij `is_admin: true` en backup-codes-link bij `has_totp: true`
- `mfa.html` + `js/mfa.js` — derde tab "Backup-code" met form (XXXXX-XXXXX input) en submit naar /auth/backup-codes/verify
- `tests/admin.spec.ts` — 2 nieuwe e2e: admin.html-redirect-niet-admin + settings.html /auth/me-probe

### Security
- **bcrypt-hashed backup-codes** met productie-default rounds=12 (env-var `HORSESAFE_BCRYPT_ROUNDS` voor test-versnelling)
- **Reden verplicht (min 10 chars)** voor alle destructive admin-acties (delete-user, disable-MFA, send-magic-link)
- **Self-delete blokkering**: admin kan eigen account niet via /admin/users/{id} verwijderen (HTTP 400)
- **Admin-magic-link naar USER's geregistreerde e-mail**, niet admin's (voorkomt mailbox-takeover via rescue)
- **Audit-events**: admin_user_delete, admin_user_disable_mfa, admin_user_send_magic_link, backup_codes_generate, backup_codes_consume

### Changed
- `version.json` + `backend/config.py` `app_version` → 0.0.4-Rivest
- Schema-version 1 → 3 (na migrate.py)
- `backup_codes_service.py` gebruikt directe `bcrypt`-library (niet via passlib — incompatibel met bcrypt 5.x)
- `audit_log.event` heeft geen DB-CHECK meer (Pydantic AuditEvent enum validates)

### Not Yet
- CSV-export audit-log → v0.0.5-Shamir
- Account-pw-reset flow → v0.0.5+
- Import/export vault-data → v0.0.5-Shamir
- Argon2id-default-re-enable → v0.0.5+
- WebAuthn/FIDO2 → v0.5.0-Rogaway

## [0.0.3-Merkle] — 2026-05-21

### Added — MFA-integratie

**Backend:**
- `services/mfa_service.py` — TOTP setup/verify/disable + AES-GCM-encrypted TOTP-secret at-rest (12-byte nonce || ciphertext || tag, base64-urlsafe) + base32 generate + provisioning_uri voor QR-render
- `services/magic_link_service.py` — Gmail SMTP_SSL via App Password + 32-byte urlsafe token + 10 min ttl + single-use redemption + EmailSender Protocol voor test-mocking
- `routes/auth.py` — 5 nieuwe endpoints: `/auth/totp/{setup,verify,disable}` + `/auth/magic-link` + `/auth/magic-link/redeem`
- `routes/vault.py` — `_user()` upgraded naar MFA-gate: weigert 403 als `users.totp_secret IS NOT NULL` + `jwt.mfa = false`
- `services/jwt_service.py` — JWT-payload bevat `mfa: bool` claim + `reissue_with_mfa()` helper voor cookie-upgrade na MFA-pass
- `routes/auth.py` POST /auth/login — antwoord bevat `mfa_required: bool` op basis van TOTP-status
- `config.py` — 6 nieuwe env-vars: `HORSESAFE_TOTP_ENCRYPTION_KEY`, `HORSESAFE_TOTP_ISSUER`, `HORSESAFE_GMAIL_USER`, `HORSESAFE_GMAIL_APP_PASSWORD`, `HORSESAFE_MAGIC_LINK_TTL_MINUTES`, `HORSESAFE_PUBLIC_URL`, `HORSESAFE_MFA_REQUIRED`
- 10 nieuwe pytest-tests over 2 files:
  - `tests/test_mfa_totp.py` — setup/verify-happy/verify-invalid/challenge-flow/disable/vault-block (7 tests)
  - `tests/test_mfa_magic_link.py` — unknown-email-no-leak/happy-roundtrip/grants-mfa-pass (3 tests)
- Backend pytest: **25/25 ✅**, lint: ✅, black: ✅

**Frontend:**
- `mfa.html` (S4 MFA-challenge) — 2 tabs: TOTP-code + magic-link request
- `settings.html` (S12) — TOTP enable/disable + QR-code render + status-display
- `js/mfa.js` — TOTP-challenge UI + magic-link request UI + tab-switching
- `js/settings.js` — TOTP setup-flow (genereer secret → render QR → verify → opslaan) + disable-flow + status-probe
- `js/auth.js` — login redirect: `mfa_required: true` → `mfa.html`; anders `vault.html`
- `js/vault-ui.js` — 403 mfa_required detection → redirect naar `mfa.html`
- `vault.html` — extra "⚙ Instellingen"-button in top-bar
- `frontend/devserver.py` — alternative dev-server met COOP/COEP + WASM-MIME headers (BUG-001-retry-vector)
- E2E playwright: 3 tests (was 2): S1 landing + vault-roundtrip + **MFA setup/re-login-challenge** in 6.6s

**Vendored:**
- `vendor/qrcode/qrcode.js` v2.0.4 (MIT, ~55KB) — QR-Code generator voor TOTP otpauth://-URL render
- `vendor/qrcode/LICENSE.MIT`

**Docs:**
- `BUGS.md` — HS-BUG-001 status update: retry-vector `devserver.py` toegevoegd; cross-browser test verschoven naar v0.0.5+ (samen met KeePassXC-CLI oracle-test)

### Changed
- `version.json`: 0.0.2 → 0.0.3-Merkle
- `backend/config.py`: `app_version` 0.0.1-Diffie → 0.0.3-Merkle (was nog niet bumped in v0.0.2)
- Default `HORSESAFE_MFA_REQUIRED = false` — opt-in via settings-pagina

### Security
- **AES-GCM at-rest encryptie van TOTP-secrets** — server-master-key uit env (`HORSESAFE_TOTP_ENCRYPTION_KEY`, 32-byte hex). Bij key-rotation moeten alle TOTP-secrets opnieuw worden ingesteld (gepland Fase 4).
- **Failed MFA-pogingen throttle**: hergebruikt `failed_logins`-tabel; 5 in 15 min → 423 Locked
- **Audit-log events**: `mfa_setup_totp`, `mfa_pass_totp`, `mfa_pass_magic_link`, `mfa_fail`

### Not Yet
- Argon2id-KDF re-enable voor nieuwe vaults → deferred naar v0.0.5+ (samen met KeePassXC-CLI oracle-test). Bridge staat klaar.
- MFA-backup-codes (10 recovery-codes) → v0.0.4-Rivest met admin-pagina
- Admin-rescue voor user-account-recovery → v0.0.4-Rivest
- iCt_Horse magic-link bridge hergebruik → v0.0.7+ deploy (huidige Gmail SMTP werkt out-of-the-box)
- /auth/me endpoint voor frontend-status-probe → v0.0.4+

## [0.0.2-Hellman] — 2026-05-21

### Added — Frontend POC LIVE (vanilla ES2022 + vendored libs)

**Frontend:**
- `frontend/index.html` (S1 landing + inline register-form met ack-checkbox)
- `frontend/login.html` (S2 account-login)
- `frontend/vault.html` (S6 unlock/create + S7 entries-CRUD single-page)
- `frontend/assets/horsesafe.css` — dark-theme uit DESIGN_TOKENS.md (~200 regels, geen framework)
- `frontend/assets/horsesafe.svg` — placeholder-logo
- `frontend/js/api.js` — fetch-wrappers naar backend met `credentials: 'include'`
- `frontend/js/auth.js` — register + login UI met error-mapping (Nederlands)
- `frontend/js/crypto.js` — kdbxweb-wrapper + argon2-bridge + best-effort 10s clipboard-wipe + password-generator
- `frontend/js/vault-ui.js` — state-management + entries-table + detail-paneel + entry-edit
- `frontend/js/main.js` — event-wiring vault.html

**Vendored (geen npm in productie):**
- `frontend/vendor/kdbxweb/kdbxweb.min.js` — 2.1.1 MIT (135 KB UMD)
- `frontend/vendor/argon2/argon2-bundled.min.js` + `argon2.wasm` — 1.18.0 MIT (45+25 KB)
- `frontend/vendor/README.md` met update-procedure

**Backend updates:**
- `CORSMiddleware` toegevoegd (env-var driven, leeg = uit voor productie)
- `SecurityHeadersMiddleware` uitgebreid met COOP+COEP voor crossOriginIsolated
- `RateLimitMiddleware` nu opt-out via `HORSESAFE_RATE_LIMIT_ENABLED=false` (dev/test)
- Middleware-order: CORS outermost (zodat 429/423-responses ook ACAO-header krijgen)

**Tests:**
- `frontend/package.json` + `playwright.config.ts` + `tests/smoke.spec.ts`
- E2E: registreer + login + vault aanmaken (in browser!) + entry toevoegen + detail-pane + pw-toggle + lock + reopen-roundtrip + verkeerd-wachtwoord
- 2/2 tests groen in 4.1s (Chromium headless)

**Documentatie:**
- `docs/screens/S01_landing.md` + `S02_login.md` + `S06_unlock.md` + `S07_content.md` (gedetailleerd per scherm)
- `frontend/README.md` uitgebreid van placeholder naar live run-instructies + e2e how-to

### Decided

- **KDF in v0.0.2 = AES-KDF** (`kdbxweb.Consts.KdfId.Aes`) voor nieuwe vaults. Reden: argon2-browser-WASM is in headless Chromium niet stabiel (hangt op eerste hash-call). AES-KDF is KDBX-spec-conform en opent in KeePassXC-desktop — disaster-recovery garantie blijft intact. Argon2id-bridge staat klaar voor v0.0.3+.
- **Hostname dev:** frontend en backend beide via `localhost` (niet 127.0.0.1) voor cross-origin-cookie-werking.
- **CORS-config** alleen actief met expliciete `HORSESAFE_CORS_ORIGINS` env-var. Productie via nginx zelfde-origin.

### Not Yet

- MFA (TOTP + magic-link) → v0.0.3-Merkle
- Admin-pagina → v0.0.4-Rivest
- Import/export → v0.0.5-Shamir
- Argon2id-KDF voor nieuwe vaults → v0.0.3+ (na browser-cross-test in echte Chrome/Firefox/Safari)
- Browser-extensie + échte clipboard-wipe → v0.2.0-Schneier

### Notes

- Lokaal getest: backend Python 3.14 + frontend Chromium headless via playwright
- Backend tests 15/15 ✅ + ruff ✅ + black ✅ na alle backend-wijzigingen
- E2E smoke 2/2 ✅ in 4.1s

## [0.0.1-Diffie] — 2026-05-21

### Added — Backend FastAPI-skeleton LIVE

**Code:**
- `backend/app.py` — FastAPI-app met lifespan + 2 middlewares + 3 routers
- `backend/config.py` — Pydantic-Settings met HORSESAFE_*-env-prefix
- `backend/db/`: schema.sql (5 tabellen) + connection.py (aiosqlite) + init.py (CLI-init)
- `backend/middlewares/`: SecurityHeadersMiddleware (CSP+HSTS+X-Frame+nosniff) + RateLimitMiddleware (in-memory sliding-window)
- `backend/models/`: user/vault/audit Pydantic-models met EmailStr-validatie + pw min-12-tekens
- `backend/services/`:
  - `auth_service.py` — Argon2id-hash + verify + create_user + authenticate + throttle-check + record_failed_login (passlib[argon2])
  - `jwt_service.py` — JWT-issue/decode + HttpOnly/Secure/SameSite-cookie + require_auth-dep
  - `storage_service.py` — vault-CRUD met SHA-256-etag + atomic-write (tmp+rename) + 3-pass secure-delete
  - `audit_service.py` — append-only audit_log writes
- `backend/routes/`:
  - `health.py` — GET /health (publiek, version + db + vaults_dir status)
  - `auth.py` — register (ack-vereist) + login (JWT-cookie) + logout (audit)
  - `vault.py` — list/create/read/update/delete met JWT-gate + If-Match optimistic lock
- `backend/tests/`: 15 tests over 3 files met `tmp_path` per test
- `backend/pyproject.toml` — ruff + black + mypy strict + pytest + coverage 80%-gate
- `backend/requirements.txt` — 9 prod + 6 dev dependencies, allemaal MIT/BSD/Apache (AGPL-compatibel)
- `backend/.env.example` — env-template (geen secrets)
- `backend/README.md` — uitgebreid van placeholder naar run+test-instructies

**Test-resultaten (Python 3.14.3 lokaal):**
- 15/15 tests groen
- 96% line-coverage (642 statements, 25 missed)
- Smoke-test uvicorn: health + register + login + vault-list met cookie allemaal ok
- Security headers verified (CSP / HSTS / X-Frame / nosniff)

**Cardinale architectuur-eigenschappen bewaard:**
- ✅ Zero-knowledge: backend ziet vault enkel als opaque KDBX4-bytes (geen parse, geen master-pw, geen keyfile)
- ✅ Optimistic locking: PUT zonder If-Match → fail; PUT met stale If-Match → 412
- ✅ Cross-user isolation: getest dat user 2 user 1's vault niet kan zien
- ✅ Secure-delete: 3-pass random overschrijf vóór unlink

### Not Yet
- MFA (TOTP + magic-link) → Fase 3 (v0.0.3-Merkle)
- Admin-routes → Fase 4 (v0.0.4-Rivest)
- Import/export → Fase 5 (v0.0.5-Shamir)
- Frontend kdbxweb POC → Fase 2 (v0.0.2-Hellman, volgende)

### Notes
- Build/test draait op Python 3.14.3 (lokaal); requirements specificeren >=3.12 (CI gebruikt 3.12)
- RateLimitMiddleware is in-memory (verloren bij restart); Redis-backend vanaf v0.1.0
- JWT-secret moet 32+ bytes zijn (RFC 7518 §3.2) — productie via openssl rand -hex 32

## [0.0.0-Rijndael] — 2026-05-21

### Added
- Repo-skeleton + git init
- 19+ doc-set: README, CLAUDE, ARCHITECTURE, UI_DESIGN, PRINCIPLES, DEPENDENCIES, THREAT_MODEL, BUGS, ACTIONS, API, CHANGELOG, COMPONENT_DIAGRAM, DATA_MODEL, DEPLOYMENT, DESIGN_TOKENS, DPIA, ENGINE_INPUT_CONTROL, GDPR_COMPLIANCE, MONITORING, PRIVACY_STATEMENT, ROADMAP, RUNBOOK, SECURITY, SEQUENCE_DIAGRAMS, version.json
- Sub-dirs: backend/, frontend/, extension/, docs/, prompts/, specs/ (allen met README placeholder)
- Sessie-MD `prompts/2026-05-21_newp_horsesafe.md` + Meta_Master crossref
- Codenaam-thema: Cryptografen (v0.0.0 = Rijndael)
- WhatIf-akkoord 22 punten (alle defaults)

### Decided
- Ecosysteem: iCt Horse Diensten (Meta_iCt_Horse_Diensten)
- Repo-zichtbaarheid: PRIVATE → open-source overweging vanaf v0.1.0
- Backend: Python 3.12 + FastAPI
- Frontend: Vanilla ES2022 + kdbxweb (MIT)
- Storage: SQLite + `/opt/horsesafe/vaults/<u-uuid>/<v-uuid>.kdbx`
- Crypto: KDBX4 + Argon2id(t=12, m=128MiB, p=2)
- MFA: Gmail magic-link (hergebruik iCt_Horse stack) + TOTP RFC 6238
- Vaults/user: 1 in v0.0.x, meerdere in v0.1.x
- Sharing: solo in v0.0.x, re-encryptie in v0.2.x
- Clipboard-wipe: best-effort browser v0.0.x; échte wipe via extensie v0.2.x
- Browser-compat: Chrome + Edge + Firefox + Safari
- Hosting: HC55:3997 + nginx `/HorseSafe/` (intern); `icthorse.nl/HorseSafe/` (dienst v0.1.x)

### Not Yet
- Geen code (skeleton-only)
- Geen GitHub-remote (wacht op akkoord)
- Geen nginx-edit / systemd / DNS / deploy
- KeePassXC 2.7.12 src tarball nog in ClaudeBug-inbox (read-only, niet geconsumeerd)
