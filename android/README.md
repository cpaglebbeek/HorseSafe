# HorseSafe Android — 0.3.0-Miller deel 1 + 0.3.4-Miller deel 2

Deel 1: YubiKey inrichten en keuren op de telefoon, zonder netwerk en zonder back-up.
Deel 2 (0.3.4): deze telefoon koppelen aan HorseSafe (QR + twee vingeraanrakingen + SAS van 6 cijfers),
met INTERNET alleen naar `icthorsecloud.nl`.
Ontwerp en eisen: `docs/HARDWARE_KEYS.md` (§4.1, §7; deel 2: **§13 is bindend**, plus §2, §7.2 en §12.5).

## Wat de app doet (deel 1)

- Sleutel herkennen (alleen lezen) met een oordeel groen/oranje/rood per eis.
- Hoofdsleutel (YubiKey Bio) en noodsleutel (YubiKey 5 NFC, of een Bio zonder vinger) inrichten:
  PIN van 63 tekens, attestation-keuring, minimum PIN-lengte 63, alwaysUv, vingers (alleen hoofdsleutel).
- Inrichting hervatten, keuren zonder en met PIN, PIN wijzigen, vingers beheren, oefenen.
- Sleutel wissen (sinds 0.3.1): FIDO-reset met bevestiging (laatste 4 cijfers serienummer + 3 s
  vasthouden) en zelfde-sleutelcontrole na opnieuw insteken.
- Rapport zonder geheimen (whitelist), in de app en via de opslagkiezer te exporteren en te importeren.

Niet in deel 1: ontgrendelen, koppelen, de device-API, Keystore-sleutels, applets of NFC uitzetten.

## Wat de app doet (deel 2, 0.3.4 — telefoon koppelen, §13.3 stap 2, 5, 6)

- M0 "Telefoon koppelen" → M14-M19 (`docs/screens/M14..M19`).
- Vooraf `canAuthenticate(BIOMETRIC_STRONG)`; anders blokkerend scherm M18. Geen toestel-PIN als alternatief.
- QR `hs1p:<pairing_id>.<b64u(s)>` scannen (zxing, zonder GMS, als view onder FLAG_SECURE; CAMERA pas bij
  het scannen gevraagd). Daaruit k_srv, k_web en att_challenge (§13.1); `s` en de afgeleide sleutels worden na
  de claim gewist.
- Keystore (§13.2): K_dev (EC P-256, geen UV, unlockedDeviceRequired), K_biosig (EC P-256, per gebruik alleen
  BIOMETRIC_STRONG, invalidated-by-enrollment), K_wrap (AES-256-GCM, idem + unlockedDeviceRequired); StrongBox
  eerst, bij `StrongBoxUnavailableException` of een andere `ProviderException` tijdens de StrongBox-generatie
  terugval op de TEE; attestation met att_challenge; een software-sleutel wordt geweigerd. Twee sleutelsets
  (A/B): een nieuwe koppeling maakt haar sleutels in de vrije set en wisselt pas na een geslaagde claim (201)
  om; mislukt de claim, dan worden alleen de nieuwe sleutels gewist en blijft de oude koppeling staan.
- Label/model: stuurtekens, Unicode-opmaaktekens (Cf), losse surrogaten en U+2028/U+2029 eruit (§13.5 stap 1).
- sk_c = 32 willekeurige bytes (X25519 via platform-XDH); vinger 1 wikkelt sk_c met K_wrap, vinger 2 tekent het
  transcript met K_biosig; claim met mac_srv + mac_web + sig_biosig + beide attestatieketens. De app rekent
  de SAS zelf en breekt af als de server een andere SAS meldt.
- Daarna `GET /device/v1/status` (device-handtekening D met K_dev, §13.6) elke 2 s, max 10 min, tot `active`
  → M17 "Gekoppeld". Alleen `revoked` (200) → alles lokaal wissen. 401/404/netwerkfout = tijdelijk: melding,
  niets gewist; bij 401 met een `Date`-header > 60 s naast de toestelklok een klokwaarschuwing.
- Proef "Kopie openen" (stap 6): sealed ophalen → vinger → sk_c uitpakken → Seal_v2 openen met de eigen
  vault_id/key_id → alleen vormcontrole {ph,kh} → buffers wissen. Niets getoond of bewaard.
- `KeyPermanentlyInvalidatedException` (vingerafdrukken gewijzigd) → koppelbestand en sleutels lokaal gewist,
  scherm M19 "Opnieuw koppelen".
- Toestelopslag: `noBackupFilesDir/device/device.json` (device_id, SAS, label, sleutels, sk_c ALLEEN gewikkeld);
  allowBackup=false en de data-extraction-rules sluiten alles uit.
- **Omgevingsbewaking:** de blokkade van deel 1 (a11y, ADB/ontwikkelaarsopties, multi-window, extern scherm,
  opname) geldt alleen voor de PIN-schermen M4/M5/M6/M8/M13. Koppelen toont geen PIN en wordt er niet door
  geblokkeerd (bewuste keuze: het ontwerp eist het niet; de SAS is geen geheim, het QR-geheim staat niet in
  beeld). FLAG_SECURE geldt wel overal, ook voor het camerabeeld.

### Pakketten (deel 2)

| Pakket | Inhoud |
|---|---|
| `crypto/` | `B64u` (strikt, canoniek), `Hkdf` (HKDF-SHA256/HMAC), `X25519` (platform-XDH; Tink niet nodig), `SealV2` (openen; verzegelen alleen voor tests), `PairV1` (k_srv, k_web, att_challenge, transcript, MAC's, SAS) |
| `net/` | `HttpsTransport` (platform-HttpsURLConnection; alleen https://icthorsecloud.nl, geen redirects/cache, max 64 KiB), `DeviceAuth` (handtekening D), `DeviceApi` (claim, status, sealed; strikte JSON) |
| `keystore/` | `PhoneKeys` (contract), `AndroidPhoneKeys` (K_dev, K_biosig, K_wrap volgens §13.2) |
| `biometric/` | `StrongGate` (alleen BIOMETRIC_STRONG, altijd CryptoObject, "Annuleren"), `StrongGateFinger` |
| `pairing/` | `PairingQr`, `PairingFlow` (claim, awaitActive, refresh, trialOpen, keysValid, wipeLocal), `DeviceStore`, `QrScanner` |
| `ui/` | `PairingViewModel`, `screens/PairingScreens.kt` (M14-M19) |

`MainActivity` is sinds deel 2 een `FragmentActivity` (nodig voor de vingerprompt van androidx.biometric).

### Permissies en netwerk (deel 2)

- Nieuw: `INTERNET`, `USE_BIOMETRIC`, `CAMERA` (feature `android.hardware.camera` met `required=false`).
  Blijven weg: `ACCESS_NETWORK_STATE`, `USE_FINGERPRINT`, `REQUEST_INSTALL_PACKAGES`, `POST_NOTIFICATIONS`, FCM.
- `res/xml/network_security_config.xml`: base-config zonder vertrouwensankers en zonder cleartext (elke andere
  host faalt bij TLS); domain-config `icthorsecloud.nl` (zonder subdomeinen) met systeemankers en pin-set
  (vervalt 2028-12-31) op de SPKI-SHA-256 van ISRG Root X1 `C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=` en
  ISRG Root X2 `diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=` (14-10-2026 berekend uit
  `letsencrypt.org/certs/isrgrootx1.pem` en `isrg-root-x2.pem`). Geen debug-overrides.
- Basis-URL vast in BuildConfig: `API_BASE_URL = https://icthorsecloud.nl/HorseSafe/api`; de device-handtekening
  tekent PATH vanaf `/api` (bv. `/api/device/v1/status`).
- **Let op (pins):** icthorsecloud.nl serveert nu de Let's Encrypt-"Gen Y"-keten
  (leaf → YE1 → ISRG Root YE, kruislings getekend door X2 → X2 door X1). Zolang Root YE geen systeemanker is,
  eindigt de gecontroleerde keten bij X2 of X1 en klopt de pin. Neemt Android Root YE (of YR) op in de
  systeemankers, dan eindigt de keten daar en faalt de pin. Mogelijke contractwijziging: Root YE
  `sCkq5UWXjg+7mKu9lMhhYF5bGLsy7VI/UNW3tccdR7w=` en Root YR `fk6IOKit1ild5647BH06ujSIq5XbCgqlbYl6ANhhi88=`
  aan de pin-set toevoegen. Nu bewust NIET gedaan (§13.9 noemt alleen X1 + X2).

### Open punten in het contract (deel 2)

- §13 noemt de JSON-namen van de attestatieketens in het claim-request niet; de app gebruikt `k_dev_chain` en
  `k_biosig_chain`, gelijk aan `PairingClaim` in `backend/models/device.py`. Graag in §13.4/§13.5 vastleggen.
- §7.2 noemt bij `KeyPermanentlyInvalidatedException` ook "server-status `revoked`"; §13 heeft geen
  device-eigen intrekking. De app wist alleen lokaal en vraagt de gebruiker het toestel op de laptop te
  verwijderen (M19).
- `androidx.biometric:1.2.0-alpha05` (§7.2) is een alpha-versie en haalt appcompat 1.2.0 binnen. De platform-
  `android.hardware.biometrics.BiometricPrompt` (API 30+) zou zonder extra bibliotheek kunnen; nu contract gevolgd.

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
- `verifyZxingHashes` (deel 2, hangt ook aan `preBuild`): SHA-256 van `zxing-android-embedded-4.3.0.aar`
  (`4ab03353…1a33`) en `zxing core-3.4.1.jar` (`acfa3033…f8d`), gekruist met de `.sha1` van Maven Central.
- Nieuwe afhankelijkheden deel 2: `androidx.biometric:biometric:1.2.0-alpha05` (haalt o.a. appcompat 1.2.0
  binnen), `androidx.fragment:fragment-ktx:1.8.5`, `com.journeyapps:zxing-android-embedded:4.3.0`,
  `com.google.zxing:core:3.4.1`. Geen OkHttp, geen Tink, geen WorkManager, geen GMS/FCM.
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
  `SingleArtifact.MERGED_MANIFEST`) en eist de exacte permissieset (sinds deel 2 met INTERNET, USE_BIOMETRIC,
  CAMERA), `networkSecurityConfig`, camera niet verplicht, geen provider/service, geen zxing-`CaptureActivity`
  en precies één exported activity (MAIN/LAUNCHER).
- **Deel 2 (JVM, zonder netwerk, nooit productie):**
  - `crypto/PairV1VectorTest`: alle vectoren uit `specs/testvectors/pair_v1.json` (k_srv, k_web, QR,
    att_challenge, transcript, mac_srv, mac_web, sas) plus de negatieve vector en de transcript-codering;
  - `crypto/SealV2VectorTest`: `seal_v2.json` (PRF → sleutelpaar, AAD/pt/k/sealed byte voor byte, openen,
    alle negatieve vectoren `unseal_failed`) plus extra vorm- en lage-orde-punt-gevallen; `B64uTest`;
  - `net/DeviceAuthTest` (exacte getekende tekst §13.6, ECDSA-controle), `net/DeviceApiTest` (nep-transport:
    paden, headers, strikte antwoorden, foutcodes, alleen eigen host);
  - `pairing/PairingQrTest`, `pairing/DeviceStoreTest`, `pairing/PairingFlowTest` (end-to-end met
    nep-Keystore, nep-vinger en een nep-server die mac_srv, sig_biosig, att_challenge en de
    device-handtekening narekent; annuleren, andere SAS, intrekken, ongeldige sleutels);
  - `PairingSourcePolicyTest`: `yubikey/`, `pin/`, `flow/` importeren niets uit `net/` (of `pairing/`,
    `keystore/`, `biometric/`) en geen java.net/okhttp; netwerkcode alleen in `net/`; `BiometricPrompt` alleen
    in `biometric/` met BIOMETRIC_STRONG, "Annuleren" en CryptoObject; Keystore-eigenschappen; de
    network-security-config (host, cleartext, pins, vervaldatum); host gelijk in BuildConfig, `net/` en rpId.
  - `SourcePolicyTest` (DEVICE_CREDENTIAL nergens; INTERNET alleen als één manifestregel) en
    `YubikeyFlowSourcePolicyTest` (domeinnaam alleen in `ConfigOps.kt`, `net/HttpTransport.kt` en
    `network_security_config.xml`) zijn bijgewerkt.
- **Niet automatisch getest (deel 2):** echte Keystore/StrongBox/attestation, BiometricPrompt, de camera,
  Conscrypt-XDH op het toestel en TLS/pinning tegen de echte server. Dat is de toesteltest (Fold6) met de
  backend van 0.3.4; tot dan geen release.
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
- De app heeft (ook met INTERNET in deel 2) geen eigen update-module: updates lopen via de HorseAPK-app. Nog
  te meten: of HorseAPK het nieuwe project HorseSafe oppakt en de update aanbiedt.
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
   - [x] **`maxPINLength` (0x1D):** gemeten 13-10-2026: de sleutel (firmware 5.7, CTAP 2.1) meldt het veld
         niet (het bestaat pas sinds CTAP 2.2). Sinds 0.3.2: CTAP 2.1-maximum 63 aangenomen (oranje), setPin(63)
         is de proef; weigert de sleutel, dan `PIN_POLICY_MPE_PIV` en staat er niets op.
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

## Checklist deel 2 (telefoon koppelen, Fold6) — na de backend van 0.3.4

1. Release-build van HC55 (debug-pakket `.debug` wordt door de server zonder testvlag geweigerd, §13.5).
2. M18: zonder vingerafdruk blokkeert de app; met alleen gezichtsherkenning ook.
3. Koppelen: QR scannen, twee vingers, SAS gelijk op laptop en telefoon, "Klopt" → M17. Controleer in de
   web-UI `security_level` (verwacht StrongBox op de Fold6) en `strongbox`.
4. Proef "Kopie openen" → "Kopie klopt".
5. Annuleren bij vinger 1 en vinger 2: niets blijft achter (opnieuw openen toont M14).
6. Nieuwe vingerafdruk toevoegen in Android → app openen → M19; oude toestel op de laptop verwijderen.
7. Toestel op de laptop verwijderen → M17 "Status verversen" → melding en lokaal gewist.
8. Pinning: met een proxy/eigen CA (gebruikers-CA) moet elke verbinding falen; vliegtuigmodus → nette melding.
9. FLAG_SECURE op M15 (camerabeeld) met Link to Windows / schermopname: zwart.

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
