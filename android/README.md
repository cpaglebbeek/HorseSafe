# HorseSafe Android — 0.3.0-Miller deel 1

YubiKey inrichten en keuren op de telefoon. Geen INTERNET-permissie, geen server, geen back-up.
Ontwerp en eisen: `docs/HARDWARE_KEYS.md` (§4.1, §7) en het bouwplan Miller deel 1.

## Wat de app doet (deel 1)

- Sleutel herkennen (alleen lezen) met een oordeel groen/oranje/rood per eis.
- Hoofdsleutel (YubiKey Bio) en noodsleutel (YubiKey 5 NFC, of een Bio zonder vinger) inrichten:
  PIN van 63 tekens, attestation-keuring, minimum PIN-lengte 63, alwaysUv, vingers (alleen hoofdsleutel).
- Inrichting hervatten, keuren zonder en met PIN, PIN wijzigen, vingers beheren, oefenen.
- Sleutel wissen (sinds 0.3.1): FIDO-reset met bevestiging (laatste 4 cijfers serienummer + 3 s
  vasthouden) en zelfde-sleutelcontrole na opnieuw insteken.
- Rapport zonder geheimen (whitelist), in de app en via de opslagkiezer te exporteren en te importeren.

Niet in deel 1: ontgrendelen, koppelen, de device-API, Keystore-sleutels, applets of NFC uitzetten.

## Bouwen

```bash
cd android
./gradlew :app:verifyYubikitHashes :app:verifyNoSlf4jProvider \
          :app:assembleDebug :app:assembleRelease :app:testDebugUnitTest :app:lintRelease
```

- JDK 21 (`JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64`), Android SDK in `~/Android/Sdk`
  (`local.properties.example`).
- Op HC55 bij voorkeur via `~/Meta_Master/tools/remote-gradle.sh ~/projects/HorseSafe/android <taken>`
  (bouwt op de build-box). Het release-artefact voor publicatie bouw je alleen lokaal op HC55, want
  alleen daar tekent de juiste sleutel.
- `verifyYubikitHashes`: SHA-256 van de vier yubikit-3.0.1-artefacten (geen `verification-metadata.xml`).
- `verifyNoSlf4jProvider`: de build faalt als een afhankelijkheid een slf4j-provider binnenhaalt (A-13).
- Versie komt uit `../version.json`: `versionName` = `X.Y.Z-Codenaam`, `versionCode` = `X*10000 + Y*100 + Z`.

## Testen

```bash
# op HC55 via de build-box
~/Meta_Master/tools/remote-gradle.sh ~/projects/HorseSafe/android :app:testDebugUnitTest :app:lintRelease
```

- **JVM-unit (`app/src/test`)**, zonder sleutel en zonder netwerk:
  - PIN-generator en controletekens (uitputtend);
  - `flow/fake/FakeYubiKey` (CTAP 2.1-gedrag op ops-niveau, met `crashAfter`): volgorde van de
    aanroepen per profiel, alle stops, hervatten na uittrekken na elke stap (`CrashResumeTest`);
  - `yubikey/FakeKey` (CTAPHID-framing): de echte yubikit-3.0.1-code (`FidoProtocol`, `Ctap2Session`,
    `ClientPin`, `Config`) draait mee met de eigen adapters en `RawInfo`;
  - attestation (positief en negatief), rapport-whitelist, import en vergelijkingsbasis, ViewModel-flows,
    omgevingsbewaking, lektest met een sentinel-PIN (`FlowCanaryTest`, `ReportCanaryTest`).
- **Bronbeleid:** `SourcePolicyTest` en `YubikeyFlowSourcePolicyTest` (geen `DEVICE_CREDENTIAL`, geen
  logging, geen netwerk/bestanden in `yubikey/` en `flow/`, reset alleen in `yubikey/YubikitResetOps.kt`
  (aangeroepen door `flow/ResetFlow.kt`), geen `deleteCredential`/`updateDeviceConfig`/`setMode`, geen `getCachedInfo`; `icthorsecloud.nl` alleen in `ConfigOps.kt` en
  gelijk aan `backend/config.py`).
- **Release-manifest:** `ReleaseManifestTest` leest de merged release-manifest (AGP
  `SingleArtifact.MERGED_MANIFEST`) en eist de exacte permissieset, geen provider/service en precies één
  exported activity (MAIN/LAUNCHER).
- **Nog niet:** `androidTest` (instrumented, met fake-`KeyLink`) bestaat niet; de emulator-smoke is niet
  gedraaid; niets is op een echt toestel of een echte sleutel getest.

## Signer controleren

Het release-APK is getekend met `~/.android/debug.keystore` op HC55 (E8). Verwachte SHA-256 van het
certificaat (ook op scherm M12 "Over"):

```
32491e0f87f46daea0fe2fc048994c9902df4725ec82f3b536dc23d933e73f17
32:49:1E:0F:87:F4:6D:AE:A0:FE:2F:C0:48:99:4C:99:02:DF:47:25:EC:82:F3:B5:36:DC:23:D9:33:E7:3F:17
```

Restrisico: het wachtwoord van die keystore is publiek bekend (kritiek 13, THREAT_MODEL).

Controle van een gebouwd APK (signer, manifest, versie, sha256):

```bash
android/scripts/verify_apk.sh android/app/build/outputs/apk/release/app-release.apk
```

Een APK van CI of de build-box heeft een andere signer: daar `HS_SKIP_SIGNER=1` zetten.

## Emulator-smoke (zonder sleutel)

`android/scripts/smoke.sh` installeert het artefact, start de app en controleert dat het proces leeft,
`logcat -b crash` leeg is en FLAG_SECURE op het venster staat. Alleen na WhatIf en akkoord, want de
emulator is gedeelde infrastructuur.

## Papierformulier

9 rijen, elk 7 vakjes voor de tekens en 1 omkaderd vakje voor het controleteken. Alfabet (29 tekens):
`abcdefghjkmnpqrstuvwx23456789`. Schrijf met pigmentpen, maak geen foto en geen kopie. Het
controleteken vangt elke verschreven letter en elke omwisseling van twee buren.

- Elke sleutel krijgt een eigen formulier. De PIN van de noodsleutel is een andere dan die van de
  hoofdsleutel; de app kan dat tussen twee sessies niet controleren (restrisico).
- Is een poging afgebroken vóór de PIN op de sleutel stond, vernietig dan dat formulier; de app maakt
  een nieuwe PIN.

## Publiceren (HorseAPK) — alleen na akkoord van Christian

Voorwaarden: tests en lint groen, `verify_apk.sh` GROEN op het **lokaal op HC55** gebouwde release-APK,
emulator-smoke gedaan (na WhatIf/akkoord), en expliciet akkoord op publicatie.

```bash
cd ~/projects/HorseSafe/android && ./gradlew :app:assembleRelease
cp app/build/outputs/apk/release/app-release.apk /tmp/HorseSafe-v0.3.0-Miller-release.apk
android/scripts/verify_apk.sh /tmp/HorseSafe-v0.3.0-Miller-release.apk     # vanuit de repo-root
bash ~/Meta_Master/tools/apk-publish.sh HorseSafe /tmp/HorseSafe-v0.3.0-Miller-release.apk
```

- De bestandsnaam moet `HorseSafe-vX.Y.Z-Codenaam-release.apk` zijn (regex in `apk-publish.sh`); het
  script controleert ook dat het pakket `nl.icthorse.horsesafe` het segment `horsesafe` bevat.
- Publiceer het **release**-artefact (niet-debuggable, geminificeerd), nooit de debug-APK: een
  debuggable build geeft JDWP- en `run-as`-toegang tot het geheugen met de PIN.
- De app heeft geen INTERNET en dus geen eigen update-module: updates lopen via de HorseAPK-app. Nog te
  meten: of HorseAPK het nieuwe project HorseSafe oppakt en de update aanbiedt (signer `32491e0f…`).
- Een APK van de build-box (`remote-gradle.sh`) is met een wegwerp-keystore getekend en komt niet terug
  naar HC55: nooit publiceren.

## Checklist voor Christian (hardware)

Volgorde is verplicht: **eerst een wisbare testsleutel**, pas daarna de echte sleutels.

1. **Testsleutel** (zelfde type als de echte, die je mag resetten): alle stappen doorlopen
   (nieuwe sleutel, hervatten na uittrekken, keuren zonder en met PIN, PIN wijzigen, vingers beheren,
   oefenen, rapport exporteren en importeren) en daarna resetten **buiten de app**.
2. Op de testsleutel meten en noteren (resultaten in `version.json` → `test_results`):
   - [ ] **minimum 63:** accepteert de sleutel `setMinPinLength(63)` (gelijk aan het maximum)? Leest
         de app daarna `minPinLength=63` terug?
   - [ ] **`maxPINLength` (0x1D):** meldt de sleutel het veld? Zonder dat veld stopt de app nu altijd
         (`MAX_PIN_LENGTH_UNKNOWN`, open vraag 4).
   - [ ] **firmware:** Bio ≥ **5.7.2**, YubiKey 5 ≥ **5.7.0** (YSA-2024-03; daaronder STOP). Klopt de
         firmware die de app via Management toont met Yubico Authenticator?
   - [ ] **USB op de Fold6:** wordt de Bio direct in USB-C herkend (ook als hij al vóór het openen van de
         app was aangesloten)? Blijft de verbinding staan tijdens een vingercapture?
   - [ ] **U2F na alwaysUv (YK5):** verdwijnt `U2F_V2` uit `versions` na alwaysUv? De app meldt het nu
         oranje "afwijkend, vastgelegd".
   - [ ] **NFC-timeouts:** werkt "keuren zonder PIN" met de 5 NFC tegen de achterkant zonder time-out?
         Werkt de OTG-adapter (USB-A → USB-C) met Auto Blocker aan?
   - [ ] **FLAG_SECURE:** met een dummy-PIN op M4 controleren dat Link to Windows / Phone Link,
         DeX-mirroring, Smart View, Circle to Search en Smart Select een zwart vlak tonen.
   - [ ] **ontwikkelaarsopties:** blokkeert de release-build M4/M6/M8 zodra ze aan staan, en is
         `adb_wifi_enabled` leesbaar met targetSdk 35?
3. Pas daarna de echte **hoofdsleutel (Bio)**, dan de **noodsleutel**.
4. Vliegtuigmodus aan, geen DeX / Link to Windows / Smart View, ontwikkelaarsopties uit (de release-build
   blokkeert anders de PIN-schermen), niemand kijkt mee, pigmentpen en het formulier klaar.
5. Na elke inrichting, PIN-wijziging of keuring met PIN: **"Afsluiten"** (wist de PIN en beëindigt de app).
6. Koppel de sleutel daarna in Chrome op de laptop (scherm S14).

## PIN-opslag (regels)

- **Bio-PIN (hoofdsleutel):** op het papieren formulier én in de HorseSafe-kluis.
- **Noodsleutel-PIN:** **alleen op papier**, op een andere plek dan de noodsleutel en dan het Bio-formulier.
  Niet in de kluis: de noodsleutel is juist de route als de kluis niet open kan.
- **Nooit** in ClaudeSecrets, niet in een foto, scan, notitie-app, klembord of chat.
- Elke sleutel een eigen formulier en een eigen PIN; nooit het papier van de andere sleutel hergebruiken.
- Een formulier van een afgebroken poging (vóór de PIN op de sleutel stond) vernietigen.

## Wissen (reset)

Sinds 0.3.1 kan de app een sleutel wissen: M0 "Sleutel wissen", of de knop op M11 als een al ingerichte
sleutel wordt afgewezen. Een reset wist alle FIDO-credentials (ook voor andere sites), de PIN, de vingers,
het minimum en alwaysUv; PIV, OATH en OpenPGP blijven. Volgorde:

1. aansluiten; de app leest uit wat erop staat en toont de laatste 4 cijfers van het serienummer;
2. die 4 cijfers overtypen (vergelijk met de achterkant van de sleutel) en 3 s ingedrukt houden;
3. sleutel eruit en meteen weer in (bij USB direct OK op de toestemmingsvraag), of bij een YubiKey 5 opnieuw
   tegen de telefoon: een YubiKey accepteert reset alleen in de eerste seconden na het aansluiten;
4. de app controleert serienummer + AAGUID (andere sleutel = `RESET_OTHER_KEY`, niets gewist), stuurt de
   reset en vraagt een aanraking (Bio: sensor);
5. nalezen: geen PIN en geen vingers meer; daarna direct inrichten. Verwijder de oude koppeling in HorseSafe (S14).

Te laat, geen aanraking of los tijdens het wissen: terug naar stap 3, de bevestiging blijft geldig. Zonder
leesbaar serienummer (`RESET_NO_SERIAL`) wis je buiten de app met Yubico Authenticator of `ykman fido reset`.
Alleen `yubikey/YubikitResetOps.kt` roept de reset aan (bronbeleidstest). Hardwaretest: venster na insteken
op de Fold6/Fairphone met de USB-toestemmingsvraag ertussen; NFC-reset op de YubiKey 5.
