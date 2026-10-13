---
date: 2026-10-12
repo: HorseSafe
session: miller_deel1
status: open
resume: "verder met HorseSafe Miller deel 1: commit, emulator-smoke, hardwaretest testsleutel, publicatie HorseAPK"
project: HorseSafe
ecosystem: iCt Horse Diensten
linked_actions: [Miller deel 1]
---

# Sessie 2026-10-12 — v0.3.0-Miller deel 1: YubiKey inrichten en keuren (Android)

## Verzoeken van Christian (chronologisch)
1. Een eigen app om de YubiKeys (Bio en noodsleutel) voor HorseSafe in te richten, in plaats van Yubico
   Authenticator / `ykman`.
2. Eerst een ontwerp voor een laptopversie ("keykeur"): ontwerp en adversariële kritiek in de scratchpad
   (`keykeur_ontwerp.md`, `keykeur_kritiek.md`).
3. "het moet .apk android app worden" — koers naar een Android-app in `android/` van deze repo.
4. Keuze 2: "eerste deel van Miller" — alleen inrichten en keuren; koppelen, telefoon-credential en
   ontgrendelen op de telefoon komen in Miller deel 2.
5. Akkoord op het bouwplan "HorseSafe 0.3.0-Miller deel 1: YubiKey inrichten en keuren", inclusief de
   correcties uit de adversariële kritiek. Daarbij akkoord om Gradle op de openclaw-box te draaien
   (`~/Meta_Master/tools/remote-gradle.sh`, HC55 overbelast); alleen de eind-release-build lokaal op HC55.

## Wat er gebouwd is
- **`android/`** (`nl.icthorse.horsesafe`, één module `:app`, yubikit 3.0.1, geen INTERNET):
  inrichten nieuw + hervatten (Bio-hoofdsleutel, YK5-noodsleutel, Bio-noodsleutel zonder vinger),
  keuren zonder/met PIN, PIN wijzigen, vingers beheren, oefenen, rapport zonder geheimen
  (whitelist, serial-HMAC, export/import via SAF). Schermen M0..M12.
- **Kritiekcorrecties verwerkt:** getPinToken altijd met permissie (CM bij oefenen); flow "Inrichting
  hervatten"; geen `verification-metadata.xml` maar `:app:verifyYubikitHashes`; geldige `configChanges`
  zonder `fold`; geen USB-intent-filter/device_filter; firmwaregrens Bio < 5.7.2 / YK5 < 5.7.0 STOP;
  U2F_V2 na alwaysUv oranje; serienummer als HMAC; rapport-import; attestation vóór PIN bij YK5 en bij
  Bio met alwaysUv=false, anders direct na setPin en vóór min-63.
- **Review-fixes (2e ronde):** PRACTICE niet meer uitgezonderd van de omgevingscontrole; release blokkeert
  ook bij ontwikkelaarsopties/draadloze ADB; import weigert rapporten uit de toekomst; vergelijkingsbasis
  alleen uit het verleden; F7b na echte poging alleen Afsluiten; hardwaretoetsen geslikt; schermafbeelding-
  melding; `verifyNoSlf4jProvider`; setPin-retry → `PIN_STATE_UNKNOWN`; UV_BLOCKED herstel met BE-token;
  YK5 met alwaysUv al aan → `YK5_ALWAYS_UV_PRESET`; geen vingers op een noodsleutel; InitializationProvider
  verwijderd; `scripts/verify_apk.sh`, `scripts/smoke.sh`, `android/README.md`.
- **Versie en documentatie:** `version.json` 0.3.0 / Miller (phase 11, regel 0.3.x = deel 2+, test_results),
  `backend/config.py` + `backend/tests/test_health.py` 0.3.0-Miller, footer `frontend/vault.html`;
  `docs/HARDWARE_KEYS.md` §4.1, §7, §9 (R4, R16–R21), §10, §11.1; `THREAT_MODEL.md`, `ROADMAP.md`,
  `ACTIONS.md`, `CHANGELOG.md` [0.3.0-Miller], `UI_DESIGN.md` + `docs/screens/M00..M12`, `README.md`,
  `PRINCIPLES.md` (P-OPS-03 versieregel, P-CRYPT-09-verwijzing).

## Uitkomsten
- `:app:testDebugUnitTest` 250/250, `:app:lintRelease` 0 errors (16 warnings), `verifyYubikitHashes` 4/4,
  `verifyNoSlf4jProvider` groen (build-box).
- Release-APK lokaal op HC55: `android/app/build/outputs/apk/release/app-release.apk`,
  versionCode 300, versionName 0.3.0-Miller,
  sha256 `1efcec3b86d1270f8fab80833b65d20f214e922cdb5ca53d7720260b0cd26cfd`,
  signer `32491e0f87f46daea0fe2fc048994c9902df4725ec82f3b536dc23d933e73f17`; `verify_apk.sh` GROEN.
- Backend pytest 196/196 (test_health 5/5) met `/opt/horsesafe/venv`.
- CI-structuuraudit (`.github/workflows/ci.yml`, alleen gelezen): controleert alleen vaste top-level docs en de
  dirs backend/frontend/extension/docs/specs/prompts met README; `android/` breekt de audit niet.
  CI bouwt `android/` niet.

## Niet gedaan / open
- Niets gecommit, gepusht, gepubliceerd of gedeployed. `.github/workflows/ci.yml` stond al lokaal gewijzigd
  (CI-jobs 0.2.1, wacht op `gh auth refresh -s workflow`) en is niet aangeraakt.
- Emulator-smoke, androidTest, test op een toestel of met een echte YubiKey: niet gedaan.
- Hardwaretest door Christian met eerst de wisbare testsleutel (checklist in `android/README.md`).
- Publicatie via HorseAPK na akkoord; server-side minPinLength/credProtect/MPE-patch; Miller deel 2.
- Zie `ACTIONS.md` § "2026-10-12 — v0.3.0-Miller deel 1".

## 13-10 — Toegewezen aan Fairphone 6
- Christian: "zorg dat deze ook op de fairphone staat" → WhatIf → "akkoord".
- HorseAPK-prod: ProjectGrant `HorseSafe` voor `cglebbeek+residio@gmail.com` (Fairphone 6) via server-shell; auditregel `grant_added` (via=server-shell); wekbericht `grants_changed` synchroon afgeleverd (ntfy ok).
- Installeren gebeurt door Christian in HorseAPK op de Fairphone. Ontwikkelaarsopties aan ⇒ PIN-schermen geblokkeerd.

## 13-10 — 0.3.1-Miller: sleutel wissen in de app
- Christian: "een bestaande ingerichte sleutel wordt nu afgewezen. deze moet ook gewist kunnen worden" → WhatIf (M13, bevestiging laatste 4 cijfers serienummer + 3 s vasthouden, opnieuw insteken, zelfde-sleutelcontrole, nalezen, R-nummer) → "akkoord".
- Gebouwd: `yubikey/api/ResetOps.kt`, `yubikey/YubikitResetOps.kt` (enige reset-aanroep; NOT_ALLOWED → `KeyError.ResetWindowPassed`), `flow/ResetFlow.kt` (F8), `ui/screens/ResetScreens.kt` (M13), ViewModel-koppeling, knop "Sleutel wissen" op M11 bij afwijzings-stops, M0-menukaart. Stops `RESET_NO_SERIAL`, `RESET_OTHER_KEY`, `RESET_READBACK_FAILED`; adviesteksten verwijzen naar "Sleutel wissen". Wissen geblokkeerd door de omgevingsbewaking.
- Gemeten: 267/267 JVM-tests (build-box), lint 0 errors/16 warnings (lint moest geforceerd: `lintAnalyzeRelease` stond onterecht UP-TO-DATE), release-APK HC55 vc 301 sha256 `4dcfd09a…2250`, `verify_apk.sh` GROEN, emulator-smoke Android 16 + 14 groen incl. M13.
- Docs: CHANGELOG, android/README §Wissen, HARDWARE_KEYS, THREAT_MODEL R22 + §8, UI_DESIGN, docs/screens/M13_reset.md.
- Niet getest: echte sleutel. Grootste onzekerheid: het resetvenster (± 5 s na insteken) met de Android-USB-toestemmingsvraag ertussen.

## 13-10 — 0.3.2-Miller: bugfix na eerste echte sleutel
- Christian: "eest melding over pin lengte wordt niet gemeld daarna sletel past niet bij type rol".
- RCA: (1) `MAX_PIN_LENGTH_UNKNOWN` — getInfo 0x1D maxPINLength bestaat pas sinds CTAP 2.2 (yubikit `RESULT_MAX_PIN_LENGTH = 0x1D`, standaard 63 als afwezig); YubiKey 5.7 = CTAP 2.1 meldt het nooit; mijn gate (open vraag 4 = STOP tot meting) blokkeerde dus elke echte sleutel. (2) `CLASS_MISMATCH` — wordt vóór de PIN-lengte gecontroleerd, dus bij de tweede poging een andere rol gekozen; melding noemde type en rol niet.
- WhatIf → "akkoord". Fix: `MaxPinLengthPolicy.ASSUME_CTAP21_MAX` standaard (oranje, setPin(63) is de proef, ook MPE); typemelding met aangesloten type + gekozen rol (check + M11 + advies). Nep-YubiKey meldt 0x1D standaard niet.
- Gemeten: 270/270, lint 0 errors, release vc 302 sha256 `496c431f…b71e`, verify_apk GROEN, smoke Android 16 + 14 groen.
