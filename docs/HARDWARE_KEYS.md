# HorseSafe: hardware-sleutels, telefoon-app en biometrisch ontgrendelen

Status: ontwerp, vastgesteld op 10-10-2026 (besluiten Christian, zie §11). Geldig voor v0.2.0-Koblitz tot en met v0.5.0-Lange.
**Bouwscope nu: alleen v0.2.0-Koblitz (web + backend).** Miller, Montgomery en Lange staan hier als ontwerp, zodat Koblitz er niet mee botst; ze worden nu niet gebouwd.

Verwijzingen: `backend/routes/vault_keys.py`, `backend/services/vault_key_service.py`, `backend/db/migrations/005_vault_keys.sql`, `frontend/js/hwkeys.js`, `frontend/js/hwkeys-ui.js`, `frontend/js/vault-ui.js`, `PRINCIPLES.md` (P-CRYPT-01, -06, -09; P-AUTH-02), `THREAT_MODEL.md`.

**Voor bouwers:** §12 (*Koblitz API-contract*) is de enige bindende bron voor de backend- en frontendbouw van v0.2.0. Waar §1-§10 iets anders lijken te zeggen, wint §12.

---

## 1. Context en eisen

HorseSafe is een zero-knowledge KDBX4-vault. De server bewaart alleen ciphertext, en ontsleutelen gebeurt alleen bij de client. Tot v0.1.0 ontgrendel je met het master-wachtwoord en/of de keyfile (64-hex).

Christian wil de keyfile op een USB-stick vervangen door iets dat alleen met zijn vinger werkt. Daarbij gelden deze eisen.

**Harde eisen** (besloten 10-10-2026):
- **E1.** Alleen biometrie die door hardware wordt afgedwongen telt:
  - Android `BIOMETRIC_STRONG`
  - WebAuthn met UV op een losse security key
  - Gezichtsherkenning van Samsung (Class 2), webcams en Windows Hello vallen af.
- **E2.** Op de telefoon nooit een pincode, patroon of apparaatwachtwoord als alternatief (geen `DEVICE_CREDENTIAL`). Keystore-sleutels gebruiken `setInvalidatedByBiometricEnrollment(true)`, zodat wie de toestel-PIN kent geen eigen vinger kan toevoegen.
- **E3.** Device-bound: passkeys die synchroniseren (BE=1) worden geweigerd, en **de server dwingt dat af**. Passkeys in de telefoonbrowser vallen af; op de telefoon ontgrendel je altijd via de app.
- **E4.** De KDBX4-basis (wachtwoord + keyfile) blijft ongewijzigd. KeePassXC-desktop blijft de noodroute (P-CRYPT-02). Hardware-sleutels openen alleen verzegelde kopieën van het ontgrendelmateriaal.
- **E5.** Er wordt per credential gewikkeld naar een X25519-publieke sleutel. Wie keyfile of wachtwoord wisselt, hoeft niet langs de kluis of de reservesleutel.
- **E6.** YubiKey Bio:
  - vingerafdrukken inschrijven via de app (Miller)
  - FIDO2-PIN van 63 ASCII-tekens
  - minimale PIN-lengte vastgezet op 63
  - always-uv aan
- **E7.** Reserve-YubiKey (noodsleutel):
  - alleen de lange PIN, geen vinger
  - ligt in de fysieke kluis
  - wachttijd van 24 uur, met melding en audit
  - blokkeren kan via het web (Koblitz) en vanaf de telefoon (Miller)
  - een blokkade blijft staan tot expliciet opheffen met step-up via Bio-YubiKey of telefoonvinger — nooit met alleen een wachtwoord (besluit 3)
- **E8.** De Android-APK staat in deze repo (`android/`, Miller):
  - publicatie via HorseAPK (`/APKDeploy`)
  - update in de app
  - ondertekend met de debug-keystore (SHA-256 `32:49:1E:0F…3F:17`)
- **E9.** Webversie op de laptop: ontgrendelen met de YubiKey Bio (WebAuthn PRF/hmac-secret, BE=0) of (Montgomery) met goedkeuring via de vingerafdruk in de telefoon-app na het overtypen van een code van 6 cijfers (§11.2).

**Principe-aanpassing (besluit 1):** nieuw principe **P-CRYPT-09**:

> **P-CRYPT-09 — Verzegelde ontgrendelkopie naar gebruikershardware.** De server mag een kopie van het ontgrendelmateriaal alleen bewaren als die verzegeld is naar een publieke sleutel per credential. Het privédeel bestaat alleen in hardware van de gebruiker: YubiKey-PRF of een biometrie-gebonden Android Keystore-sleutel. De server kan zo'n kopie aantoonbaar niet openen. De inhoud is `{ph,kh}` en nooit het leesbare wachtwoord of de keyfile.

`CLAUDE.md:53` wordt:

> ❌ Server-side pw/keyfile-opslag in een vorm die de server kan openen (ook niet versleuteld met een serversleutel) → verbreekt zero-knowledge. Enige uitzondering: P-CRYPT-09 (verzegeld naar gebruikershardware).

P-CRYPT-01 (de server ziet nooit pw, keyfile of afgeleide sleutel) en P-CRYPT-06 (geen escrow) blijven gelden. De kopie is bezit van de gebruiker; de server bewaart hem alleen.

## 2. Sleutelhiërarchie en wikkelschema

```
KDBX4-basis (ongewijzigd; KeePassXC-noodroute)
  pw (in het hoofd) + keyfile 64-hex (offline)
    ph = SHA-256(UTF-8(pw))        kh = keyFileHash (kdbxweb-regels; bij 64-hex = de 32 gedecodeerde bytes)
    composite = SHA-256(ph || kh) -> KDF (AES-KDF, HS-BUG-001) -> KDBX4
  CK := {ph, kh}   "ontgrendelmateriaal"; alleen in client-RAM als ProtectedValue / ByteArray

Per credential c: X25519-paar (sk_c, pk_c). Server bewaart alleen pk_c en sealed_c = Seal_v2(pk_c, CK)
  bio       YubiKey Bio     sk_c = HKDF-SHA256(ikm=PRF(cred_c, prf_salt_c), salt=0^32, info="HorseSafe v2 X25519")
  recovery  YubiKey 5/Bio   idem, eigen credential en eigen prf_salt; UV = PIN van 63 tekens
  phone     Android-app     (Miller) sk_c = 32 willekeurige bytes, op het toestel alleen gewikkeld opgeslagen:
                            AES-256-GCM met K_wrap (Keystore, StrongBox als die er is, timeout 0,
                            AUTH_BIOMETRIC_STRONG, setInvalidatedByBiometricEnrollment(true),
                            setUnlockedDeviceRequired(true)); alleen via CryptoObject(Cipher)

Overige telefoonsleutels (Miller; Android Keystore, EC P-256, met key attestation):
  K_dev     ondertekenen; geen UV; unlockedDeviceRequired  -> authenticatie van elk device-request
  K_biosig  ondertekenen; BIOMETRIC_STRONG, timeout 0, invalidated-by-enrollment -> step-up / deblokkeren

Tijdelijk (Montgomery, goedkeuring via de telefoon):
  e_L       X25519 in WebCrypto (extractable:false) in de laptop-tab, per verzoek; weg na gebruik of na 120 s
```

**Seal_v2** moet in JS (`hwkeys.js`), Python (referentie in de tests) en later Kotlin (`crypto/Seal.kt`) byte voor byte gelijk werken. De exacte definitie staat in §12.5; de testvectoren in `specs/testvectors/seal_v2.json`.

- De server controleert alleen de vorm: lengtes, b64url, en dat `kid` gelijk is aan de sleutel-id.
- De client opent met een AAD-controle. Na het openen bewijst de header-HMAC van de KDBX dat CK klopt.
- Sealed v1 (het eerste Koblitz-concept, `{pw,kf}` als leesbare strings) vervalt. Het is nooit live geweest.

**Rotatie:**
- Wachtwoord of keyfile wijzigen gaat in de webapp via `PUT /vault/{vid}/rekey`. De server vervangt dan in één atomaire stap de blob (If-Match) en alle sealed-kopieën, verzegeld naar de bekende `pk_c`. YubiKeys en telefoon zijn daarvoor niet nodig (E5).
- Na een wijziging in KeePassXC gaat het zo:
  1. Ontgrendelen met een sleutel lukt wel (de kopie gaat open), maar de KDBX weigert met `InvalidKey`.
  2. De UI meldt: "Kopie verouderd. Ontgrendel één keer met wachtwoord/keyfile en klik Bijwerken."
  3. Daarna volgt `PUT /vault/{vid}/keys/sealed` met step-up.

## 3. Credential-types

| Type | Hardware | UV | Gebruik | Restrisico |
|---|---|---|---|---|
| `bio` | YubiKey Bio (alleen USB) | vinger. Na 3 mislukte pogingen valt de sleutel terug op de PIN van 63 tekens. Dit zit in de sleutel zelf en is niet uit te zetten. | direct ontgrendelen op de laptop; step-up | PIN-terugval (R3) |
| `recovery` | YubiKey 5 (of een tweede Bio zonder vingers) | PIN van 63 tekens | na 24 uur wachttijd, 24 uur venster, één keer bruikbaar | wachttijd wordt alleen door de server afgedwongen (R2) |
| `phone` (Miller) | Z Fold6, Keystore (StrongBox als die er is) | alleen BIOMETRIC_STRONG-vinger | in de app ontgrendelen, de laptop goedkeuren, step-up | sk_c staat kort in app-RAM (R8) |
| basis | pw + keyfile | — | altijd, ook in KeePassXC | ongewijzigd |

**Toegestane authenticators:** zie §12.4 (attestation tegen de vendored Yubico-roots + AAGUID-allowlist uit FIDO MDS3). `kind=bio` vereist een Bio-AAGUID; `kind=recovery` accepteert YubiKey 5-serie of Bio. Windows Hello, Touch ID en telefoon-passkeys vallen af door `cross-platform`, `hints:["security-key"]`, attestation-allowlist en BE=0 samen.

**Recovery-statusmachine** (exacte afleiding in §12.7):
```
idle --release--> waiting (release_at = nu+24u) --tijd--> released [release_at, release_at+24u)
released --geldige unlock--> consumed        released --tijd--> expired
idle|expired|consumed --release--> waiting   waiting|released --cancel--> idle
elke status --block--> blocked --unblock (step-up bio/telefoonvinger)--> idle
```
Een blokkade blijft staan tot er expliciet wordt gedeblokkeerd (besluit 3). Er is geen automatisch verval.

## 4. Sequences

### 4.1 YubiKey inrichten (app, Miller deel 1 — GEBOUWD in v0.3.0-Miller)

Inrichten gebeurt sinds v0.3.0-Miller **in de Android-app** (`android/`, zie §7 en `android/README.md`),
niet meer met Yubico Authenticator / `ykman`. Sinds v0.3.1 kan de app ook **wissen** (FIDO-reset, M13; zie
`android/README.md` §Wissen); Yubico Authenticator / `ykman` blijven nodig om applets (PIV) uit te zetten en als
terugval zonder leesbaar serienummer. De app heeft geen INTERNET en praat niet met de server.

**Profielen:** `BIO_MAIN` (hoofdsleutel, YubiKey Bio, 2-3 vingers), `RECOVERY_YK5` (noodsleutel, YubiKey 5
NFC, geen vinger), `RECOVERY_BIO` (noodsleutel op een Bio zonder vinger). Inrichten alleen via USB (de 5 NFC
met één OTG-adapter); NFC alleen voor "keuren zonder PIN". NFC blijft aan; "NFC uitzetten" (oude stap 6)
vervalt.

1. **Herkennen (alleen lezen):** firmware, vormfactor en serienummer via Management (`DeviceInfo`; firmware
   niet uit getInfo), ruwe getInfo in een eigen verbinding (`RawInfo`: aanwezigheid van 0x0C/0x0D/0x0E/0x1D)
   en een verse `Ctap2Session.getInfo()` (nooit `getCachedInfo`). Elke stap in een eigen
   `requestConnection`. Oordeel groen/oranje/rood per eis (scherm M3). **STOP** bij:
   - geen `FIDO_2_1`, of `setMinPINLength`/`authnrCfg`/`alwaysUv` ontbreekt, of maxRpids < 1;
   - firmware onbekend, Bio < **5.7.2**, YubiKey 5 < **5.7.0** (YSA-2024-03);
   - AAGUID niet in de allowlist (`backend/data/aaguids.json`, MDS) of klasse past niet bij de rol;
   - `maxPINLength` < 63 (`MAX_PIN_LENGTH_TOO_SHORT`). **Afwezig** is sinds 0.3.2 oranje: 0x1D bestaat pas
     sinds CTAP 2.2 en YubiKey 5.7 meldt het niet (gemeten 13-10-2026); CTAP 2.1-maximum 63, setPin(63) is de proef
     (open vraag 4 gesloten);
   - meer dan één sleutel, of de sleutel wordt losgekoppeld.
2. **Nieuw-sleutelgate:** STOP als er al een PIN staat (dan PIN wijzigen of "Inrichting hervatten"), als
   `bioEnroll=true`, `forcePinChange=true`, resident credentials > 0, of (YubiKey 5) alwaysUv al aan zonder
   PIN (`YK5_ALWAYS_UV_PRESET`). PIN-pogingen zonder PIN zijn sinds 0.3.3 **geen** stop (een gewiste Bio meldt
   geen of een ander aantal, gemeten 13-10-2026); oranje regel, en na setPin moeten het er 8 zijn.
3. **PIN:** de app genereert 63 ASCII-tekens (alfabet van 29, `SecureRandom`) in 9 groepen van 7 met elk een
   controleteken (Σ(i+1)·v_i mod 29). Tonen per groep zolang je de kaart ingedrukt houdt (M4, FLAG_SECURE,
   Canvas uit een CharArray, geen String), overschrijven op het papieren formulier (M5) en **alle 9 groepen**
   hertypen op een eigen toetsenblok (M6). Geen systeemtoetsenbord, geen klembord.
4. **Attestation-keuring** (makeCredential met rpId `keuring.horsesafe.invalid`, `rk=false`, MC-token als
   er een PIN is): packed + x5c tot de gevendorde Yubico-roots, AAGUID in het leaf gelijk aan authData,
   rpIdHash, vlaggen, ES256. **Volgorde:** YubiKey 5 altijd vóór setPin; Bio vóór setPin als alwaysUv=false,
   anders direct na setPin en vóór het minimum.
5. **`ClientPin.setPin`**, daarna vers teruglezen: `clientPin=true`, 8 pogingen. Een verloren antwoord bij
   opnieuw proberen geeft `PIN_STATE_UNKNOWN` (formulier bewaren, hervatten).
6. **Tellen:** resident credentials = 0 (CM-token, alleen `getMetadata`), vingers = 0.
7. **Onomkeerbaar (M6b, vinkje):** `Config.setMinPinLength(63, ["icthorsecloud.nl"], false)` met een ACFG-token;
   vers teruglezen: `minPinLength=63`, `forcePinChange=false`.
8. **alwaysUv:** alleen `toggleAlwaysUv()` als vers gelezen `false`; daarna vers teruglezen = `true`.
9. **YubiKey 5:** U2F-controle — staat `U2F_V2` nog in `versions` na alwaysUv, dan oranje "afwijkend,
   vastgelegd" (geen STOP tot de meting op de testsleutel).
10. **Alleen `BIO_MAIN`:** 2 of 3 vingers inschrijven (BE-token; `FEEDBACK_FP_*` in het Nederlands; namen
    zoals `R-wijs`, lengte uit `getMaxTemplateFriendlyName`), elk met een testaanraking. Op een noodsleutel
    nooit een vinger (`RECOVERY_KEY_NO_FINGERS`, `RECOVERY_BIO_HAS_FINGER`).
11. **Eindkeuring en rapport** zonder geheimen (whitelist; serienummer alleen als HMAC met een app-privé
    sleutel), bewaard in app-privéopslag en te exporteren/importeren via de opslagkiezer (SAF). Een
    inrichtingsrapport wordt de nieuwe vergelijkingsbasis.
12. **Afsluiten:** wist de PIN en beëindigt het proces (A-12).

**Per stap een eigen token met precies één permissie** (ACFG 0x20, BE 0x08, CM 0x04, MC 0x01); vooraf
`isTokenSupported`, nooit stil terugvallen op subcommand 0x05; na elke schrijfactie een verse getInfo.

**Inrichting hervatten (F2r/F3r):** voor een sleutel waarop de PIN al staat maar de inrichting niet af is
(app gecrasht, sleutel uitgetrokken, STOP na setPin). Toegang alleen als `clientPin=true`, resident = 0 en
(minimum < 63 of alwaysUv false of — hoofdsleutel — 0 vingers). De PIN komt van papier (M8, met
controletekens; een fout controleteken kost geen poging) en daarna volgt de rest van de vaste volgorde met
dezelfde terugleescontroles.

**Verder in de app:** keuren zonder PIN (elk kwartaal, ook via NFC), keuren met PIN (vingerlijst, resident
credentials, attestation), PIN wijzigen, vingers beheren (toevoegen, hernoemen, verwijderen, testaanraking;
alleen hoofdsleutel), oefenen (papier controleren zonder sleutel; optioneel één echte PIN-controle met een
CM-token).

Er wordt **geen credential voor `icthorsecloud.nl`** vanuit de app aangemaakt. Registreren gebeurt in de
laptopbrowser (4.2), zodat de PRF van één client komt.

### 4.2 YubiKey koppelen (laptop, vault geopend met pw/keyfile, dus CK in RAM) — Koblitz
Zie §12.6.1 voor het exacte contract. In het kort: server-opties (twee challenges, `key_id`, `prf_salt`) → `credentials.create` → `credentials.get` met PRF → client verzegelt en controleert zelf → `POST /vault/{vid}/keys` → server verifieert attestation, UV, BE, AAGUID, assertion en sealed-vorm.

### 4.3 Ontgrendelen met de Bio (laptop) — Koblitz
Zie §12.6.2. Eén `credentials.get` (één vinger) → `POST …/unlock` met de assertion → server verifieert en geeft pas dan `sealed` terug → client opent met AAD-controle → `credentialsFromHashes` → KDBX open.

### 4.4 Noodsleutel — Koblitz
1. `POST …/{kid}/release`. Uitkomsten: 409 `recovery_blocked`; 503 `notify_unavailable` (geen meldkanaal geconfigureerd); 503 `notify_failed` (mail niet afgeleverd, aanvraag teruggedraaid); anders `release_at = nu + 24u`, mail, audit.
2. Binnen 24 uur kan Christian annuleren of blokkeren (web; in Miller ook vanuit de app).
3. In het venster: 4.3 met de noodsleutel en de PIN van 63 tekens → status `consumed`, mail "noodsleutel gebruikt", audit `recovery_key_used`.

### 4.5 Telefoon koppelen (Miller — niet in Koblitz)
1. Web, met de vault open en zo nodig step-up: `POST /devices/pairings` levert `{id, secret(128 bit), exp=5 min}` op, getoond als QR `hs1p:<id>.<b64u(secret)>`.
2. De app controleert `canAuthenticate(BIOMETRIC_STRONG)==SUCCESS`. Anders: "Stel eerst een vingerafdruk in".
3. De app maakt K_dev, K_biosig en K_wrap aan, plus sk_c. sk_c wordt met K_wrap gewikkeld (één vingerafdruk).
4. `POST /devices/pairings/{id}/claim` met `pk_c`, `k_dev_pub`, `k_biosig_pub`, de attestatieketens, `label`, `model`, `app_version`, `mac = HMAC-SHA256(secret, transcript)` en `sig_biosig(transcript)`.
5. De server controleert de mac, verloop/eenmaligheid, de key-attestation-keten tot de Google hardware-attestation-root (vendored) plus revocatielijst, `attestationSecurityLevel` ≥ TEE, `attestationApplicationId` = `nl.icthorse.horsesafe[.debug]` met de digest van het debug-certificaat, `verifiedBootState=VERIFIED`, en bij K_biosig: biometrie, `authTimeout=0`, geen `noAuthRequired`.
6. Beide schermen tonen een SAS van 6 cijfers: `H(id‖pk_c‖k_dev_pub‖k_biosig_pub) mod 10^6`. "Klopt" op de laptop → `POST …/confirm`.
7. Het web verzegelt `Seal_v2(pk_c, CK, store)` en stuurt `POST /vault/{vid}/keys {kind:"phone", device_id, public_key, sealed}`.

### 4.6 Ontgrendelen in de app (Montgomery, v0.4.0)
- De app toont de webapp in een WebView op `https://icthorsecloud.nl/HorseSafe/` (account-login + TOTP; WebAuthn in de WebView uit).
- "Ontgrendel met deze telefoon" start het goedkeuringsprotocol (§5); de hash gaat via `WebViewCompat.addWebMessageListener` (origin-regel alleen `https://icthorsecloud.nl`) in plaats van via een QR-code.
- Native kluis in de app: v0.5.0-Lange, gepland na de veldtest van v0.4 (besluit 7).

## 5. Goedkeuring via de telefoon (Montgomery — niet in Koblitz)

> **Herzien 14-10-2026 (§11.2):** de QR-code in stap 2-3 vervalt. In plaats daarvan toont de laptop een code van
> 6 cijfers die de gebruiker op de telefoon intypt (BB-001-stijl), met een commitment-SAS zodat de server
> `epk_L` niet ongemerkt kan verwisselen. Het schema hieronder wordt in fase Montgomery herschreven; tot dan
> geldt §11.2 waar het afwijkt.

```
Laptop-tab (JWT+MFA, sid)                 Server (alleen doorgifte)                Telefoon (app)
1 e_L <- X25519 (niet extraheerbaar), nonce_L (32 B)
  POST /vault/{vid}/approvals {epk_L, nonce_L}
                                          R=uuid, exp=120 s, sid_hash, ip, ua,
                                          status=pending; max 1 open, 10/uur
  <- {R, exp}
2 toont QR  hs1a:<R>.<b64u(SHA-256("HSv2 approve"||epk_L||nonce_L))>
                                                                                   3 scant QR; GET /device/v1/approvals/R
                                                                                     (K_dev-getekend) -> epk_L, nonce_L,
                                                                                     vault-label, IP/plaats, browser, tijd
                                                                                     hash klopt niet -> weigeren + melden
                                                                                   4 vinger: BiometricPrompt(CryptoObject
                                                                                     Cipher K_wrap) -> sk_c -> eigen sealed
                                                                                     (GET /device/v1/keys/{kid}/sealed) -> CK
                                                                                     resp = Seal_v2(epk_L, CK, relay,
                                                                                       bind = R || nonce_L)
                                          <- POST /device/v1/approvals/R {decision, resp}
                                          sig klopt; pending->approved atomair, binnen exp
5 GET /vault/{vid}/approvals/R?wait=25 (alleen dezelfde sid)
  <- resp; approved->consumed; resp gewist uit DB; daarna 410
6 open met e_L, AAD controleren -> CK -> KDBX; e_L en CK-tussenbuffers weg
```

- **End-to-end:** de server ziet alleen `epk_L`, `resp` en metadata.
- **Binding:** `sid` (nieuwe JWT-claim, Montgomery) en R, `nonce_L`, `vault_id` in de AAD (purpose `relay`, §12.5).
- **Replay:** R is één keer bruikbaar en verloopt na 120 s; device-requests getekend met `ts` binnen ±60 s en een nonce-cache van 120 s.
- **Phishing:** de QR-code is een authentiek optisch kanaal; een server die `epk_L` verwisselt valt door op de hash. "Niet ik" → `denied`, sessie van dat `sid` ingetrokken, 15 minuten afkoelen.
- **Meldingen naar de telefoon:** polling (`/device/v1/status?wait=25` + WorkManager), geen FCM (besluit 6).

## 6. API-overzicht per fase (alles onder `/HorseSafe/api`)

Afkortingen: **S** = JWT+MFA (cookie); **SU** = S plus geldige step-up (§12.8); **D** = device-handtekening (Miller).

| Fase | Methode en pad | Auth |
|---|---|---|
| K | POST `/webauthn/options` | S |
| K | POST `/auth/stepup` | S |
| K | GET / POST `/vault/{vid}/keys` | S / S of SU |
| K | POST `/vault/{vid}/keys/{kid}/unlock` | S + assertion |
| K | PUT `/vault/{vid}/keys/sealed` | SU |
| K | PUT `/vault/{vid}/rekey` | SU + If-Match |
| K | DELETE `/vault/{vid}/keys/{kid}` | S |
| K | POST / DELETE `/vault/{vid}/keys/{kid}/release` | S |
| K | POST / DELETE `/vault/{vid}/keys/{kid}/block` | S / SU (bio) |
| M | `/devices/pairings…`, `/devices`, `/device/v1/status`, `/device/v1/keys/{kid}/sealed`, `/device/v1/recovery/{kid}/block`, `/app/latest`, `/app/download` | SU, S, D, publiek |
| Mo | `/vault/{vid}/approvals…`, `/device/v1/approvals/{id}` | S + sid, D |

Het exacte Koblitz-contract staat in §12. Miller- en Montgomery-endpoints worden in hun eigen fase vastgelegd.

**Audit-events Koblitz:** zie §12.10. Een audit-regel bevat nooit `sealed`, `ph`, `kh`, PRF-uitvoer, challenges of assertions.

**Meldingen (besluit 4):** generieke SMTP-mailer (§12.11), afzender = SMTP-gebruiker (info@icthorse.nl). Ook de magic-link loopt via deze mailer. Vanaf Miller komt daar de inbox van de telefoon bij (polling).

## 7. Android-app (`android/`, Miller)

### 7.1 Deel 1 — GEBOUWD in v0.3.0-Miller (2026-10-12): YubiKey inrichten en keuren

Bouwen, testen, publiceren en de hardwarechecklist: `android/README.md`.

**Basis:** `nl.icthorse.horsesafe` (debug `.debug`); één Gradle-module `:app`; Gradle 8.10.2, AGP 8.7.3,
Kotlin 2.0.21, Compose BOM 2024.11.00; minSdk 33, compile/target 35; `versionName`/`versionCode` uit
`../version.json` (`X.Y.Z-Codenaam`, `X*10000+Y*100+Z`, patch < 100). Release: niet-debuggable,
geminificeerd (R8), ondertekend met `~/.android/debug.keystore` op HC55 (signer `32491e0f…3f17`, E8).

**Bibliotheken:** alleen `com.yubico.yubikit:android|core|fido|management:3.0.1` (3.1/3.2.x vragen Kotlin 2.2),
AndroidX core/lifecycle/activity-compose, Compose Material3 en kotlinx-coroutines. **Geen**
netwerkbibliotheek, geen biometric, geen WorkManager, geen Crashlytics/ACRA. Toeleveringsketen: geen
`verification-metadata.xml` (zou elk artefact moeten dekken); in plaats daarvan
`:app:verifyYubikitHashes` (SHA-256 van de vier yubikit-artefacten) en `:app:verifyNoSlf4jProvider`
(hangt aan `preBuild`, faalt bij een slf4j-provider op de classpath).

**Manifest (minimaal, bewaakt door `ReleaseManifestTest` en `scripts/verify_apk.sh`):**
- permissies: NFC, `HIDE_OVERLAY_WINDOWS`, `DETECT_SCREEN_CAPTURE`, `DETECT_SCREEN_RECORDING` (plus de
  interne `DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION` van AndroidX); **geen INTERNET**,
  `ACCESS_NETWORK_STATE`, `USE_BIOMETRIC`, `USE_FINGERPRINT` of `REQUEST_INSTALL_PACKAGES`
  (`tools:node="remove"`);
- `usb.host` en `nfc` met `required=false`; **geen** USB-intent-filter en geen `device_filter.xml` (kritiek
  12: detectie alleen via `startUsbDiscovery` zolang de app open is);
- yubikit-`OtpActivity` en `YubiKeyPromptActivity`, `androidx.startup.InitializationProvider` en
  `ProfileInstallReceiver` verwijderd; precies één exported component (MainActivity, MAIN/LAUNCHER);
  geen provider of service;
- `allowBackup=false`; `fullBackupContent` (`backup_rules.xml`) en `dataExtractionRules` (cloud-backup én
  device-transfer) sluiten elk domein uit;
  `usesCleartextTraffic=false`;
- `configChanges="orientation|screenSize|smallestScreenSize|screenLayout|density|keyboard|keyboardHidden|uiMode|navigation|fontScale"`
  (geen `fold`: geen geldige waarde; vouwen valt onder screenSize/smallestScreenSize/screenLayout).

**Hardening (A-1..A-22 uit het bouwplan):** FLAG_SECURE en `setRecentsScreenshotEnabled(false)` vóór
`setContent`; overlays verborgen en `filterTouchesWhenObscured`; schermopname-callbacks (API 34/35);
PIN-schermen (M4, M5, M6, M8) geblokkeerd bij een niet-toegestane toegankelijkheidsdienst, multi-window/PiP,
een ander display of DeX, schermopname, en in de release-build ook bij ingeschakelde
ontwikkelaarsopties of ADB (USB of draadloos); eigen toetsenblok zonder IME, hardwaretoetsen geslikt op
schermen met een geheim; PIN alleen in een CharArray (`SecretBuffer`) en gewist bij `onStop`/`onCleared`;
geen logging in productiecode (bronbeleidstest + R8 `-assumenosideeffects`); `CrashGuard` voorkomt
dropbox en crashdialoog (de platform-pre-handler schrijft nog wel naar `logcat -b crash`); "Afsluiten"
beëindigt het proces.

| Pakket | Inhoud (deel 1) |
|---|---|
| `app/` | `MainActivity` (één activity, Compose), `ServiceLocator` (koppeling, vertrouwensankers uit assets met hash uit BuildConfig, fail-closed) |
| `secure/` | `SecureWindow`, `EnvironmentGuard`, `CrashGuard`, `ProcessEnd`, `SecretRegistry` |
| `pin/` | `Alphabet` (29 tekens), `PinGenerator` (`SecureRandom`), `GroupCheck` (controleteken mod 29), `PinCompare` (constante tijd), `SecretBuffer` |
| `yubikey/` | `RawInfo`, `Inspector`, `MgmtOps`, `Tokens`, yubikit-adapters voor PIN, Config, BioEnroll, CredMgmt en attestation; `transport/` (`YubiKitKeyDiscovery`, `YubiKeyLink`, `ConnectionRunner`: één fase per `requestConnection`, buiten de main thread) |
| `attest/` | `AttestationVerifier` (Kotlin-port van `webauthn_service.py` stap 5-8), `AaguidAllowlist`, `TrustRoots`, `AuthDataParser` — ankers `yubico_fido_roots.pem` + `aaguids.json` bij de build uit `../backend/data` gekopieerd |
| `flow/` | `DefaultSetupMachine` (nieuw + hervatten), `KeuringFlow`, `ChangePinFlow`, `FingerFlow`, `PracticeFlow`, `ResetFlow` (0.3.1), `Policy`/`Checks` (gates), `Stop` (Nederlandse reden + advies) |
| `report/` | `Report` + `ReportSchema` (whitelist, faalt op onbekend veld), `ReportStore` (app-privé, `baselineFor`), `ReportCompare`, `SafReportIo` (export/import), `SerialHasher` (HMAC van het serienummer, Keystore-sleutel) |
| `ui/` | Schermen M0..M12 (zie `UI_DESIGN.md` en `docs/screens/M00..M12`), `PinKeypad`, `GroupReveal`, `HorseSafeViewModel` |

**Niet in deel 1:** INTERNET en elke servercommunicatie, telefoon-credential en Keystore-sleutels
(K_wrap/K_dev/K_biosig), `StrongGate`/`USE_BIOMETRIC`, koppelen (QR + SAS), device-API, migratie 006,
meldingen (polling), in-app update (updates via de HorseAPK-app), `deleteCredential`/
`updateDeviceConfig`/`setMode` (reset wel sinds 0.3.1, alleen via `ResetFlow`), applets of NFC uitzetten, test-emulator `hb-horsesafe`, CI-job `android`.

### 7.2 Deel 2 en verder (v0.3.x-Miller) — gepland

Zoals ontworpen op 10-10-2026; de pakketten hieronder komen er in deel 2 bij.

**Extra bibliotheken:** `androidx.biometric:1.2.0-alpha05`, `fragment-ktx:1.8.5`; OkHttp, WorkManager;
`zxing-android-embedded` (zonder GMS), `androidx.webkit`; Tink 1.8.0 alleen als de platform-XDH-vectortest
faalt. **Extra hardening:** INTERNET met network-security-config en pins op ISRG Root X1 en X2, geen
cleartext; geen FCM (besluit 6).

| Pakket | Inhoud |
|---|---|
| `biometric/StrongGate` | alleen `BIOMETRIC_STRONG`, altijd met CryptoObject, negatieve knop "Annuleren". Unit-test + lint-check: `DEVICE_CREDENTIAL` komt nergens voor (die bronbeleidstest bestaat al in deel 1). Afgeleid van `iCtHorseKey`. |
| `keystore/` | K_wrap, K_dev, K_biosig volgens §2, StrongBox eerst. `KeyPermanentlyInvalidatedException` → lokaal wissen, server-status `revoked`, scherm "Opnieuw koppelen". |
| `crypto/` | `Seal` v2, HKDF, X25519; vectortests op `specs/testvectors/seal_v2.json`. Let op: WebAuthn-PRF hasht de salt (`SHA-256("WebAuthn PRF" ‖ 0x00 ‖ prf_salt)`) vóór hmac-secret; de app moet dat zelf doen als hij hmac-secret direct aanspreekt. |
| `net/` | K_dev-interceptor, inbox (long-poll / WorkManager 15 min), lokale meldingen |
| `pairing/`, `approve/` | QR-scan, SAS, goedkeuringskaart, WebMessageListener (v0.4.0) |
| `update/` | port van `ClaudeWeb/android/.../update/` (ApkVerifier: sha256, package, certificaat, alleen eigen host) |

Test-emulator `hb-horsesafe` (besluit 5) komt in deel 2 (deel 1 heeft geen biometrie).

## 8. Webversie (Koblitz)

- **`hwkeys.js`:** opties en challenges komen van de server; rpId uit de serveropties (productie `icthorsecloud.nl`), op een andere host een melding met link. Controle vooraf fail-closed (§12.13). Seal_v2 met AAD; `credentialsFromHashes`.
- **`vault-ui.js`:** `state.secret` = `{ph, kh}` als `kdbxweb.ProtectedValue` (of `null`), nooit strings; het wachtwoordveld wordt direct na het openen geleegd; automatisch vergrendelen bij inactiviteit.
- **Nieuw:** `stepup.js` (dialoog: Bio of TOTP); een "Wijzig wachtwoord/keyfile"-flow via `/rekey`.
- **Ontgrendelscherm** met de knoppen YubiKey en Keyfile (Telefoon vanaf Montgomery). De laatst gebruikte methode komt bovenaan (localStorage in try/catch).
- **`hwkeys-ui.js`:** null-guards rond `find()`; statussen in gewone taal (klaar, wacht nog 13 u 20 m, vrijgegeven tot …, gebruikt, verlopen, geblokkeerd, kopie verouderd); blokkeren, deblokkeren met step-up; banner als `notify_available=false`.
- **Deploy:** `rsync` met `--exclude tests/ --exclude 'package*.json' --exclude node_modules/`. De CSP blijft ongewijzigd.

## 9. Dreigingen en mitigaties

| # | Dreiging | Mitigatie / restrisico |
|---|---|---|
| R1 | Een gecompromitteerde server serveert kwaadaardige web-JS en vangt CK bij webontgrendeling (P-CRYPT-05; geldt ook voor de WebView). | Expliciet in THREAT_MODEL. Hoogste zekerheid: native kluis (v0.5.0), op termijn een getekende bundel of de extensie. |
| R2 | De 24-uurswachttijd wordt alleen door de server afgedwongen. | Wie de server overneemt heeft nog steeds de fysieke noodsleutel en de PIN van 63 tekens nodig. Melding, blokkade en audit. |
| R3 | De Bio valt na 3 vingers terug op de PIN. | Niet uit te zetten. PIN van 63 tekens, minimumlengte 63, 8 pogingen tot reset. |
| R4 | De debug-keystore op HC55 tekent de release-APK (Miller). Het wachtwoord van een debug-keystore is publiek bekend (`android`): wie `~/.android/debug.keystore` kan lezen, kan een update maken die Android en HorseAPK accepteren (supply-chain-pad naar een app die PIN's maakt). | Eis E8 accepteert dit voorlopig. Signer-digest `32491e0f…3f17` op M12 en in `scripts/verify_apk.sh`; publiceren alleen vanaf een lokale build op HC55. Deel 1 heeft geen in-app update (geen INTERNET): updates via de HorseAPK-app. Open vraag: eigen release-keystore buiten de repo, of bewust aanvaarden (kritiek 13). |
| R5 | Een aanvaller met alleen een account-sessie kan DoS plegen (sleutels verwijderen, blokkeren). | Uitbreidende acties vragen step-up; defensieve acties niet. Alles wordt gemeld en gelogd. De keyfile-route blijft werken. |
| R6 | Account-sessie + TOTP + verwijderen van alle bio-sleutels geeft TOTP-step-up, en daarmee een eigen (echte) Bio koppelen. | TOTP-step-up pas 24 uur (`recovery_delay_hours`) na het verwijderen van een Bio (los of samen met haar kluis) of na het instellen van TOTP terwijl er al sleutels waren (403 `stepup_cooldown`, met meldingen). TOTP kan niet worden vervangen zonder de huidige code (409 `totp_already_configured`). Deblokkeren kan nooit met TOTP en alleen met een Bio die al gekoppeld was vóór de blokkade (`stepup_key`, 403 `stepup_key_too_new`). Vóór rekey/opnieuw verzegelen toont de client elke ontvangende sleutel (recent gekoppeld gemarkeerd) en vraagt bevestiging. Daarna is voor de noodsleutel nog steeds de fysieke sleutel met PIN nodig, plus 24 uur met meldingen. Restrisico: zonder TOTP is het accountwachtwoord genoeg voor S; de mailbox alleen niet (R14). |
| R7 | Diefstal van de telefoon met kennis van de toestel-PIN (Miller). | Een vinger toevoegen maakt K_wrap en K_biosig ongeldig. Intrekken via het web. |
| R8 | sk_c van de telefoon staat kort in app-RAM (software-X25519). | Direct `fill(0)`. Pas weg met `CryptoObject(KeyAgreement)` (SDK 36.1). `verifiedBootState`-controle. |
| R9 | `kh` is bij een 64-hex keyfile gelijk aan de keyfile. | Een geopende kopie staat gelijk aan wachtwoord-hash plus keyfile. Openen vereist PRF of K_wrap. |
| R10 | XSS in de webapp leest CK. | Strikte CSP (self), geen inline-JS. Risico gelijk aan v0.1.0. |
| R11 | Meldingen zonder push kunnen door Doze uren vertraagd worden (Miller). | Ruim binnen 24 uur, en mail loopt parallel. |
| R12 | Attestation-uitzondering voor tests (virtuele authenticator). | Alleen via `HORSESAFE_TEST_ATTESTATION=1`; `/health` toont dit; de app weigert te starten als de vlag aan staat met rpId `icthorsecloud.nl` (§12.4). |
| R13 | Mailserver onbereikbaar → noodsleutel-vrijgave zonder dat Christian het merkt. | Vrijgave geweigerd zonder geconfigureerd kanaal (503) en teruggedraaid als de melding niet afgeleverd kon worden (§12.6.6). |
| R14 | Magic-link of backup-codes als omweg om MFA (reviewronde 2): de magic-link gaf zonder wachtwoord een `mfa=true`-sessie (mailbox = S, en alle Koblitz-meldingen gaan naar diezelfde mailbox); backup-codes aanmaken kon met alleen het wachtwoord en gaf via `/backup-codes/verify` `mfa=true`. | Besluit (reviewronde 2, 10-10-2026): de magic-link is uitsluitend een **tweede stap** bovenop een wachtwoordsessie van dezelfde gebruiker in dezelfde browser; zonder die sessie wordt hij geweigerd en niet verbruikt (`login.html?error=magic_link_login_first`); hij geeft nooit zelf een sessie. Reviewronde 3: de link wijst naar `mfa.html#ml=<token>`, dat same-site `POST /auth/magic-link/redeem` doet; het `SameSite=Strict`-cookie gaat bij een klik vanuit webmail (cross-site) namelijk niet mee. `POST /auth/backup-codes/generate` vereist een sessie met MFA (403 `mfa_required`); bestaande codes blijven dan geldig. S = wachtwoord + tweede factor (TOTP, magic-link of een eerder met MFA aangemaakte backup-code). |
| R15 | Wie `vault_keys.public_key` kan wijzigen (DB-schrijftoegang, gemanipuleerde back-up, injectie elders) laat bij de volgende reseal/rekey het echte `{ph,kh}` naar zijn eigen sleutel verzegelen; een verwisselde sleutel ziet er in de bevestigingsdialoog hetzelfde uit. | De client legt bij het koppelen `{key_id: public_key}` vast **in de versleutelde KDBX** (Meta/CustomData `HorseSafe.KeyPins.v1`, beschermd door de KDBX-HMAC; eerst vastleggen en opslaan, dan pas `POST …/keys`). `resealAll`/`rekey` verzegelen alleen naar sleutels die daar exact zo staan; anders `key_pin_mismatch`/`key_not_pinned` vóór er iets verzegeld wordt, en het sleutelpaneel waarschuwt. Restrisico: een sleutel waarvan de pin ontbreekt (kluis buiten HorseSafe zonder CustomData opgeslagen, of koppelen afgebroken) moet opnieuw gekoppeld worden; R1 (kwaadaardige JS) blijft. |
| R16 (B-17) | PIN-kopieën in de yubikit-heap: `ClientPin.preparePin` geeft bytes terug die yubikit niet wist (`setPin`: 64 opgevulde bytes; `changePin`: nieuwe en huidige PIN; `getPinToken`: huidige PIN als SHA-256-invoer); het gedeelde ECDH-geheim wordt niet gewist. yubikit maakt géén String van de PIN. `Ctap2Session.clientPin` is package-private, dus een eigen wisbare implementatie kan niet via de publieke API. | De app zelf houdt de PIN alleen in een CharArray en wist die; "Afsluiten" beëindigt het proces na elke stap met een PIN (A-12), zodat de heap verdwijnt. Release niet-debuggable (geen JDWP/`run-as`). Geaccepteerd restrisico; een shim in het yubikit-package is te breekbaar bij een update (open vraag 13). |
| R17 | Slechts 8 PIN-pogingen bij een PIN van 63 tekens: typfouten op de laptop kosten pogingen; na 3 fouten op rij opnieuw insteken, bij 0 is de PIN geblokkeerd en is alleen een reset (alles weg) mogelijk. | Controleteken per groep (vangt elke enkele fout en elke omwisseling van buren) zodat de app een fout op papier vangt zonder poging; "Oefenen" zonder sleutel; M8 blokkeert bij ≤ 3 resterende pogingen (`PIN_RETRIES_LOW`); advies op de laptop: groep voor groep typen, na 2 fouten stoppen. Noodsleutel-PIN wordt zelden gebruikt: periodiek oefenen. Een geblokkeerde noodsleutel = opnieuw inrichten en koppelen. |
| R18 | MPE-gat aan de serverkant: de server dwingt bij het koppelen geen `minPinLength=63` of `credProtect` af en weigert een Bio Multi-protocol Edition (PIN max. 8 bij PIV aan) niet. Een sleutel die níet via de app is ingericht, kan dus met een korte PIN gekoppeld worden. | De app weigert MPE met PIV (setPin(63) faalt, `PIN_POLICY_MPE_PIV`) en elke sleutel die `maxPINLength` < 63 meldt. Server-side patch gepland (minPinLength/credProtect afdwingen, MPE weigeren via een nog toe te voegen veld `variant` in `aaguids.json`; de app leidt de variant nu af uit de MDS-beschrijving), afhankelijk van een meting van de Chrome-ondersteuning (open vraag 14). Tot dan: alleen sleutels koppelen die met de app zijn ingericht en gekeurd. |
| R19 | Gecompromitteerde telefoon (root, malware, kwaadaardige toegankelijkheidsdienst, overlay) leest de PIN tijdens het tonen of invoeren, of vervalst het oordeel van de app. | FLAG_SECURE, overlays verborgen, toegankelijkheidsdiensten buiten de (lege) allowlist geven STOP, multi-window/DeX/ander display/schermopname blokkeren de PIN-schermen, release blokkeert ook bij ontwikkelaarsopties of ADB; geen INTERNET (de app kan niets wegsturen); vliegtuigmodus in de checklist. De server verifieert bij het koppelen opnieuw zelf de attestation (§12.4), los van de telefoon. Restrisico: tegen root-malware met geheugentoegang beschermt de app niet (buiten scope, zoals malware op de laptop). |
| R20 | Verschillende PIN's tussen sessies (kritiek 7): hoofdsleutel en noodsleutel worden in aparte processen ingericht, dus de app kan niet controleren dat de twee PIN's verschillen. | Elke inrichting genereert een nieuwe willekeurige PIN (kans op gelijkheid verwaarloosbaar); papierregel "elke sleutel een eigen formulier, nooit het papier van de andere sleutel" en de oranje melding `DIFFERENT_PINS` op M3/M10. Geaccepteerd restrisico. |
| R21 | Crash-buffer: bij een onverwachte crash schrijft de pre-handler van het platform de stacktrace naar `logcat -b crash`, ook met eigen `UncaughtExceptionHandler`. | Exception-berichten bevatten nooit PIN-data (canary-test); `CrashGuard` voorkomt dropbox en de crashdialoog; geen logging in productiecode. Restrisico: type en stapnaam van de fout zijn in de crash-buffer zichtbaar voor wie ADB-toegang heeft. |

## 10. Fasering en acceptatiecriteria

Elke fase is +0.1.0 (design-impact). Bugfixes zijn +0.0.1. Codenamen (besluit 2): v0.2.0 **Koblitz**, v0.3.0 **Miller**, v0.4.0 **Montgomery**, v0.5.0 **Lange**. Schneier (browserextensie) en de verdere ROADMAP-items (Daemen, Rijmen, Bellare, Rogaway, Bernstein) schuiven door; Rogaway (FIDO2) gaat grotendeels op in deze reeks.

**v0.2.0-Koblitz: hardware-sleutels in het web, server-geverifieerd** — NU

Werk:
- 005 herschrijven (§12.9)
- py_webauthn met de Yubico-roots en de AAGUID-allowlist (§12.4)
- Seal_v2 met `{ph,kh}` + testvectoren (§12.5)
- step-up, `/rekey`, recovery met block/unblock (§12.6-§12.8)
- fail-closed client (§12.13) en de generieke SMTP-mailer, ook voor de magic-link (§12.11)
- bugs uit de verkenning: cancel zonder lopend verzoek → 409; audit pas na verificatie; blokkerende SMTP in de event-loop; fail-open bij ontbrekende `getAuthenticatorData`; `find()` zonder null-guard; migratiepatroon `DELETE FROM schema_version`
- P-CRYPT-09 in `PRINCIPLES.md` en `CLAUDE.md:53` (§1); ROADMAP-codenamen (besluit 2)
- dit document en de documentenset (README, THREAT_MODEL, CHANGELOG, version.json)
- CI-jobs voor `node --test` en Playwright-WebAuthn

Acceptatie:
1. pytest groen met coverage ≥ 80%, inclusief de gevallen in §12.14.
2. `node --test` groen: Seal_v2-vectoren slagen; een afwijkende AAD (vault, kid of purpose) faalt; `credentialsFromHashes` opent dezelfde KDBX als pw+kf.
3. Playwright met een CDP virtual authenticator (`ctap2`, `hasPrf`, `hasUserVerification`, `isUserVerified`, `HORSESAFE_TEST_ATTESTATION=1`, rpId `localhost`): koppelen, vergrendelen, ontgrendelen, rekey, en na rekey opent de oude kopie niet meer.
4. De kdbx-oracle-job blijft groen: KeePassXC opent de vault met pw+keyfile.
5. Er is aantoonbaar een mail afgeleverd vanaf HC55 via SMTP 587/STARTTLS.
6. Live geeft `/api/health` `0.2.0-Koblitz` terug, met `test_attestation:false`.
7. Veldtest: Bio in Chrome op de laptop koppelen en ontgrendelen. Een Windows Hello-passkey wordt geweigerd.

**v0.3.0-Miller deel 1: Android-app, YubiKey inrichten en keuren** — GEBOUWD 2026-10-12 (niet gepubliceerd)
Werk: `android/` met README (§7.1, §4.1); geen INTERNET, geen server, geen backend-wijziging (alleen
`app_version`). Versieregel: deel 1 = 0.3.0, latere Miller-delen = 0.3.1, 0.3.2, … (de ontwerpimpact is op
10-10 al genomen; besluit 2 blijft intact).
Acceptatie deel 1:
1. `:app:testDebugUnitTest` groen (250/250 op 12-10), `:app:lintRelease` 0 errors, `verifyYubikitHashes` en
   `verifyNoSlf4jProvider` groen — ✅ 2026-10-12.
2. Release-APK lokaal op HC55: `scripts/verify_apk.sh` GROEN (signer `32491e0f…`, versionCode 300, geen INTERNET,
   niet debuggable, geen provider/service, één exported component) — ✅ 2026-10-12.
3. Emulator-smoke zonder sleutel (`scripts/smoke.sh`: start, `logcat -b crash` leeg, FLAG_SECURE) — open (WhatIf/akkoord).
4. Hardware-veldtest door Christian volgens `android/README.md`: eerst de wisbare testsleutel met alle
   metingen, daarna de echte Bio en de noodsleutel, en koppelen + ontgrendelen in Chrome (Koblitz-acceptatie 7) — open.
5. Publicatie via HorseAPK (`apk-publish.sh HorseSafe HorseSafe-v0.3.0-Miller-release.apk`) en het
   update-aanbod in de HorseAPK-app aangetoond — open (na akkoord).

**v0.3.x-Miller deel 2 en verder: koppelen, telefoon-credential, blokkeren, update** — later
Werk: INTERNET + network-security-config; CI-job `android`; migratie 006 (`pairings`, `device_nonces`), device-API, `/app/*`; in-app update; `/APKDeploy`; test-emulator `hb-horsesafe` (besluit 5); polling-inbox (besluit 6).
Acceptatie: zoals in het ontwerp van 10-10-2026 (JVM-vectortests gelijk aan JS, `StrongGate == BIOMETRIC_STRONG`, geen `DEVICE_CREDENTIAL`; pytest op mac/attestation/D-handtekening; apksigner-digest `32491e0f…`; rooktest; `/api/app/latest`-sha256; veldtest Fold6 + Bio; release-alarm binnen 15 min en blokkeren uit de app → web 409 `recovery_blocked`). Deblokkeren via `DELETE /device/v1/recovery/{kid}/block` met `sig_biosig` (telefoonvinger).

**v0.4.0-Montgomery: laptop ontgrendelen via telefoon-QR + vinger, en ontgrendelen in de app (WebView)** — later
Migratie 007 (`approvals`, `revoked_sessions`, JWT-claim `sid`). Acceptatie: andere sid 404; tweede GET 410; na 120 s 410; tweede open verzoek 429; `deny` → sessie ingetrokken; `resp` na consume uit de DB; gemanipuleerde `epk_L` geeft hash-mismatch; relay-AAD met andere nonce/R opent niet; Playwright met nepdevice; veldtest Fold6 + laptop-Chrome en WebView-zelfgoedkeuring.

**v0.5.0-Lange: native read-only kluis in de app** — GEPLAND na de veldtest van v0.4, niet bouwen (besluit 7).

## 11. Besluiten 10-10-2026

Vastgesteld door Christian; bindend.

1. **P-CRYPT-09** wordt opgenomen met de tekst uit §1, en `CLAUDE.md:53` wordt: "❌ Server-side pw/keyfile-opslag in een vorm die de server kan openen (ook niet versleuteld met een serversleutel) → verbreekt zero-knowledge. Enige uitzondering: P-CRYPT-09 (verzegeld naar gebruikershardware)."
2. **Codenamen:** v0.2.0 Koblitz, v0.3.0 Miller (Android-app), v0.4.0 Montgomery (laptop ontgrendelen via telefoon-QR + vinger), v0.5.0 Lange (native kluis in de app; gepland na de veldtest van v0.4, niet bouwen). Schneier (browserextensie) en de verdere ROADMAP-items schuiven door.
3. **Blokkade van de noodsleutel** blijft staan tot expliciet opheffen met step-up via Bio-YubiKey of telefoonvinger — nooit met alleen een wachtwoord (ook niet met alleen TOTP). Audit en mail bij blokkeren en opheffen.
4. **Mail:** generieke SMTP-mailer (host, poort 587 STARTTLS, user, password, from via settings, §12.11); From = SMTP-gebruiker (info@icthorse.nl); ook de magic-link gaat via deze mailer (Gmail SMTP_SSL 465 werkt niet op HC55, poort 465 is dicht). De oude `gmail_*`-settings blijven als fallback. Noodsleutel-vrijgave wordt geweigerd als geen meldkanaal geconfigureerd is.
5. **Test-emulator** `hb-horsesafe` komt later (Miller), niet in deze fase.
6. **Telefoonmeldingen:** polling, geen FCM (Miller).
7. **v0.5.0-Lange** niet bouwen.

**Scope 10-10:** alleen v0.2.0-Koblitz (web + backend), volgens §12.

### 11.1 Akkoord 12-10-2026: bouwplan Miller deel 1

Christian gaf akkoord op het bouwplan "HorseSafe 0.3.0-Miller deel 1: YubiKey inrichten en keuren", inclusief
de correcties uit de adversariële kritiek. Gebouwd volgens dat plan:

1. **Versie:** 0.3.0-Miller = deel 1; latere delen 0.3.x.
2. **Scope deel 1:** geen INTERNET, geen server, geen Keystore-sleutels, geen in-app update (updates via HorseAPK).
3. **Volgorde attestation:** YubiKey 5 vóór setPin; Bio vóór setPin als alwaysUv=false, anders direct na setPin en vóór het minimum.
4. **Firmwaregrens per klasse:** Bio < 5.7.2 en YubiKey 5 < 5.7.0 → STOP (YSA-2024-03).
5. **U2F_V2 na alwaysUv:** oranje "afwijkend, vastgelegd", geen STOP (tot meting).
6. **Flow "Inrichting hervatten"** voor een gedeeltelijk ingerichte sleutel.
7. **Oefencontrole op de sleutel** altijd met een token met permissie (CM), nooit zonder.
8. **Geen `verification-metadata.xml`**, wel een eigen SHA-256-controle op de vier yubikit-artefacten.
9. **Geen USB-intent-filter/device_filter**; geldige `configChanges` zonder `fold`.
10. **Serienummer** alleen als HMAC in het rapport; **rapport-import** via SAF voor de kwartaalvergelijking.

Gebouwd volgens het **advies** bij de open vragen van het plan; een expliciet antwoord van Christian per vraag
staat nog open (zie `ACTIONS.md`):
- alle 9 groepen hertypen in plaats van 3 willekeurige (vraag 8); alfabet van 29 tekens met controleteken mod 29 (vraag 9);
- het release-artefact publiceren, niet de debug-APK (vraag 3);
- noodsleutel inrichten via USB, NFC alleen voor "keuren zonder PIN", NFC blijft aan (vraag 6); de app zet geen applets uit (vraag 7);
- harde STOP bij een toegankelijkheidsdienst buiten de lege allowlist (vraag 10);
- PIN-opslag: Bio-PIN papier + kluis, noodsleutel-PIN alleen papier apart, nooit ClaudeSecrets (vraag 11);
- rapporten app-privé plus export/import (vraag 12).

Keuzes die bij de bouw/review zijn gemaakt en nog een bevestiging van Christian vragen:
- de release-build blokkeert de PIN-schermen ook als alleen de ontwikkelaarsopties aan staan (niet alleen bij USB-ADB);
- `maxPINLength` afwezig: sinds 0.3.2 oranje en doorgaan (open vraag 4 gesloten, gemeten 13-10-2026), setPin(63) is de proef;
- `androidx.startup.InitializationProvider` is uit het manifest verwijderd (geen providers, A-15); op een toestel te controleren;
- YubiKey 5 met alwaysUv al aan zonder PIN wordt geweigerd (`YK5_ALWAYS_UV_PRESET`);
- kritiek 7 variant 2: geen controle "verschillende PIN's", wel papierregel + restrisico (R20);
- restrisico's R4 (debug-keystore) en R16 (B-17) bewust aanvaarden of anders oplossen (open vragen 13 en kritiek 13).

---

### 11.2 Akkoord 14-10-2026: telefoon-ontgrendelen naar voren (Miller deel 2 + Montgomery)

Christian wil HorseSafe in de laptopbrowser openen **zonder YubiKey, alleen met de vingerafdruk op de telefoon**.
Besluiten (WhatIf + "akkoord" per vraag, 14-10-2026):

1. **Volgorde omgedraaid:** Miller deel 2 (0.3.4) en daarna Montgomery (0.4.0) gaan vóór de Bio-veldtest
   (Koblitz-acceptatie 7). De Bio-route blijft ongewijzigd. Elke fase blijft een eigen akkoord voor bouwen, deploy
   en publicatie vragen.
2. **Eén app:** de telefoonfunctie komt in de bestaande app `nl.icthorse.horsesafe`; INTERNET alleen naar
   `icthorsecloud.nl` (network-security-config, pins ISRG Root X1/X2, geen cleartext). Advies was een aparte app
   (inrichtingsapp zonder netwerk); Christian koos bewust voor één app. Nieuw restrisico: de PIN-schermen van
   deel 1 draaien in een app met netwerkrechten (THREAT_MODEL, nieuw R-nummer bij de bouw).
3. **Ontgrendelen zoals ClaudeWeb (BB-001), maar zero-knowledge:** geen QR-scan; de laptop toont een code, de
   gebruiker typt die op de telefoon en legt de vinger op de sensor. Afwijkingen van BB-001:
   - code van **6 cijfers** (BB-001: 2), omdat hier ook de server de aanvaller kan zijn;
   - de **telefoon** controleert de code, de server ziet hem nooit;
   - **commitment-SAS:** laptop stuurt eerst `C = H(epk_L ‖ r)`; telefoon antwoordt met eigen `n_P` (32 B); pas
     daarna onthult de laptop `epk_L, r` en toont `SAS = trunc6(H("HSv2 sas" ‖ epk_L ‖ r ‖ n_P ‖ R))`. De server
     legt zich vast vóór hij `n_P` kent, dus kan hij geen `epk` met dezelfde code zoeken (kans ≤ 10^-6 per poging,
     één poging);
   - foute code → verzoek `denied`, melding, geen tweede poging; geen PIN-terugval (E2);
   - meldingen: pollen, ntfy als versnelling (past binnen besluit 6: geen FCM).
   Exacte hash-invoer, domeinscheiding en testvectoren (JS = Kotlin = Python) worden in het Montgomery-contract
   vastgelegd.
4. **Telefoon koppelen** (§4.5) blijft: eenmalig QR + SAS van 6 cijfers.

5. **Release-keystore (R4): eigen keystore** (keuze a, 14-10). Nieuwe RSA/EC-keystore op HC55 buiten de repo,
   wachtwoord + back-up in ClaudeSecrets; `verify_apk.sh`, HorseAPK-publicatie en de server-allowlist
   (`attestationApplicationId`) krijgen de nieuwe digest. Eenmalig: app op Fold en Fairphone verwijderen en opnieuw
   installeren (lokale keuringsrapporten eerst exporteren). Vervangt E8 "debug-keystore".

## 12. Koblitz API-contract (v0.2.0)

Dit contract is bindend voor de backend- en frontendbouwers die parallel werken. Alles wat hier niet staat, hoort niet bij Koblitz.

### 12.1 Algemeen

- **Basis-URL:** productie `/HorseSafe/api` (nginx strip het voorvoegsel; FastAPI ziet de paden hieronder). Dev: `http://localhost:3997`.
- **Auth:** het bestaande JWT-cookie (`horsesafe_session`, HttpOnly, SameSite=Strict). Alle Koblitz-endpoints eisen **S** = geldig JWT met `mfa=true` (zoals `routes/vault.py::_user`). Zonder cookie 401 `not_authenticated`; ongeldig 401 `invalid_token`; `mfa=false` 403 `mfa_required`.
- **Foutformaat:** zoals de bestaande code: `HTTPException(detail={...})`, dus de body is
  `{"detail": {"error": "<code>", ...extra velden}}`. De frontend leest altijd `body.detail.error`.
  Pydantic-validatiefouten blijven FastAPI-standaard: **422** met `{"detail": [ ... ]}` (lijst). De frontend behandelt 422 als `invalid_request`.
- **Codering:** alle binaire velden zijn **base64url zonder padding** (`[A-Za-z0-9_-]`), hieronder "b64u". Tijden zijn Unix-seconden (int, UTC).
- **Eigendom:** een `vault_id` of `key_id` die niet van de ingelogde gebruiker is, of niet bestaat, geeft altijd **404 `not_found`** (geen onderscheid).
- **Rate-limits:** de bestaande `RateLimitMiddleware` (`/vault` 60/min/IP) blijft; `/webauthn` en `/auth/stepup` vallen onder de default (300/min). Daarbovenop de applicatielimieten in 12.6.
- **Content-Type:** JSON tenzij anders vermeld (`/rekey` is multipart).

### 12.2 Settings (nieuw in `backend/config.py`; env-prefix `HORSESAFE_`)

| Setting | Env | Default | Betekenis |
|---|---|---|---|
| `webauthn_rp_id` | `HORSESAFE_WEBAUTHN_RP_ID` | `icthorsecloud.nl` | rpId; vast, ook als de site via een alias bereikt wordt |
| `webauthn_rp_name` | `HORSESAFE_WEBAUTHN_RP_NAME` | `HorseSafe` | |
| `webauthn_origin` | `HORSESAFE_WEBAUTHN_ORIGIN` | `https://icthorsecloud.nl` | enige toegestane `clientDataJSON.origin` |
| `webauthn_challenge_ttl_seconds` | `…_WEBAUTHN_CHALLENGE_TTL_SECONDS` | `300` | |
| `webauthn_timeout_ms` | `…_WEBAUTHN_TIMEOUT_MS` | `120000` | doorgegeven aan de browser |
| `stepup_ttl_seconds` | `HORSESAFE_STEPUP_TTL_SECONDS` | `300` | geldigheid step-up |
| `test_attestation` | `HORSESAFE_TEST_ATTESTATION` | `false` | alleen tests; zie 12.4 |
| `aaguid_allowlist_path` | `…_AAGUID_ALLOWLIST_PATH` | `backend/data/aaguids.json` | |
| `attestation_roots_path` | `…_ATTESTATION_ROOTS_PATH` | `backend/data/yubico_fido_roots.pem` | |
| `vault_keys_max` | bestaand | `10` | per vault, telt `status != 'revoked'` |
| `recovery_delay_hours` | bestaand | `24` | |
| `recovery_window_hours` | bestaand | `24` | |
| SMTP-settings | zie 12.11 | | |

Paden zijn relatief aan de package-map `backend/` (`Path(__file__).parent / "data" / …`). Bewust **niet** `backend/config/`: dat botst met de module `backend/config.py`.

### 12.3 Afhankelijkheden

- Backend: `webauthn` (py_webauthn) `>=2.2,<3` in `backend/requirements.txt`. Eerst in de scratch-venv controleren dat het samengaat met `cryptography>=43,<46`; zo niet, de cryptography-grens in requirements aanpassen en dat in CHANGELOG noemen. Niet installeren in `/opt/horsesafe/venv`.
- Python-referentie voor Seal_v2 (tests + vectorgenerator) gebruikt alleen `cryptography` (X25519, HKDF, AESGCM).
- Frontend: geen nieuwe bibliotheken. WebCrypto X25519 (Chrome ≥ 133, Edge, Firefox ≥ 130).

### 12.4 Attestation, AAGUID-allowlist en vlagcontroles

**Vendored bestanden** (in de repo, publiek materiaal, geen secrets):
- `backend/data/yubico_fido_roots.pem`: de Yubico FIDO-attestation-roots, opgehaald van `https://developers.yubico.com/PKI/` tijdens de bouw. In de kop van het bestand per certificaat: onderwerp, bron-URL, ophaaldatum, SHA-256-vingerafdruk. Niet uit het geheugen invullen.
- `backend/data/aaguids.json`, opgebouwd uit de FIDO MDS3-blob (`https://mds3.fidoalliance.org/`) tijdens de bouw, met dit formaat:

```json
{
  "source": "FIDO MDS3",
  "mds_no": 0,
  "fetched_at": "2026-10-10",
  "aaguids": {
    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx": { "class": "bio", "description": "YubiKey Bio Series - FIDO Edition" },
    "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy": { "class": "yubikey5", "description": "YubiKey 5 Series with NFC" }
  }
}
```

  - `class: "bio"`: Yubico-entries met `fingerprint_internal` in `userVerificationDetails` (YubiKey Bio Series, FIDO Edition en Multi-protocol Edition, alle firmwareversies in MDS).
  - `class: "yubikey5"`: Yubico YubiKey 5-serie (incl. 5Ci, 5 NFC, 5C NFC, Nano, FIPS-varianten) met FIDO2.
  - Andere AAGUIDs komen er niet in. Een script `backend/tools/build_aaguids.py` (leest een gedownloade MDS3-blob, schrijft dit bestand) hoort erbij, zodat de lijst reproduceerbaar is.

**Toegestane combinaties:**

| `kind` | toegestane `class` | anders |
|---|---|---|
| `bio` | `bio` | 400 `not_bio_authenticator` (AAGUID wel in lijst) of 400 `authenticator_not_allowed` (niet in lijst) |
| `recovery` | `bio`, `yubikey5` | 400 `authenticator_not_allowed` |

**Controles bij registratie (`create`), in deze volgorde; eerste fout wint:**
1. `clientDataJSON.type == "webauthn.create"` → anders 400 `bad_client_data`.
2. `SHA-256(b64u-decode(clientDataJSON.challenge))` == `challenge_hash` van de `create`-challenge (12.6.1) → anders 400 `invalid_challenge`.
3. `clientDataJSON.origin == webauthn_origin` → anders 400 `origin_mismatch`. `crossOrigin` moet afwezig of `false` zijn → anders 400 `origin_mismatch`.
4. `rpIdHash == SHA-256(webauthn_rp_id)` → anders 400 `rp_id_mismatch`.
5. Vlaggen: UP=1 (anders 400 `up_missing`), UV=1 (anders 400 `uv_missing`), BE=0 én BS=0 (anders 400 `not_device_bound`), AT=1 (anders 400 `bad_authenticator_data`).
6. Algoritme in `{-8 (EdDSA), -7 (ES256)}` → anders 400 `alg_not_allowed`.
7. Attestation: `fmt == "packed"` met `x5c`, keten geldig tot een root uit `yubico_fido_roots.pem`, AAGUID-extensie in het leafcertificaat gelijk aan de AAGUID in authData (py_webauthn doet dit bij `pem_root_certs_bytes_by_fmt={PACKED: roots}`). `fmt` `none`, self-attestation of andere formaten → 400 `attestation_invalid`.
8. AAGUID tegen de allowlist en `kind` (tabel hierboven).
9. `credential_id` nog niet bij deze gebruiker → anders 409 `credential_exists`.

**Testuitzondering** (`test_attestation=true`): stap 7 accepteert ook `fmt=none`, en stap 8 wordt overgeslagen (AAGUID wordt wel opgeslagen). Stappen 1-6 en 9 blijven. Bij app-start: als `test_attestation` aan staat **en** `webauthn_rp_id == "icthorsecloud.nl"`, weigert `create_app()` te starten (`RuntimeError`, duidelijke logregel). `/health` toont altijd `"test_attestation": <bool>`.

**Controles bij elke assertion (`get`):** register-assert, unlock en step-up:
1. `clientDataJSON.type == "webauthn.get"` → 400 `bad_client_data`.
2. challenge-hash zoals hierboven, tegen de bij de purpose horende challenge → 400 `invalid_challenge`.
3. origin en `crossOrigin` → 400 `origin_mismatch`; rpIdHash → 400 `rp_id_mismatch`.
4. UP=1 (`up_missing`), UV=1 (`uv_missing`), BE=0 en BS=0 (`not_device_bound`).
5. Handtekening met de opgeslagen `cose_public_key` → 400 `assertion_invalid`.
6. signCount: py_webauthn aanroepen met `credential_current_sign_count=0` en zelf vergelijken: als `opgeslagen > 0` of `nieuw > 0`, en `nieuw <= opgeslagen` → **409 `sign_count_regression`** (plus audit `vault_key_clone_suspect` en mail). Anders `sign_count = nieuw` opslaan.

**Challenge-verbruik:** een challenge wordt **vóór** de controles atomair als gebruikt gemarkeerd (`UPDATE … SET used_at=? WHERE id=? AND used_at IS NULL AND expires_at>?`; 0 rijen → 400 `invalid_challenge`). Elke mislukte poging vraagt dus nieuwe opties. Een challenge hoort bij precies één `user_id`, `purpose` en (waar van toepassing) `vault_id`/`kind`/`key_id`; afwijking → 400 `invalid_challenge`.

### 12.5 Seal_v2 (sealed-formaat versie 2)

**Sleutelafleiding uit PRF** (bio en recovery):
```
prf     = 32 bytes uit getClientExtensionResults().prf.results.first,
          met eval.first = b64u-decode(prf_salt) (32 bytes; de browser hasht zelf met "WebAuthn PRF")
seed    = HKDF-SHA256(ikm=prf, salt=32 nulbytes, info=UTF-8("HorseSafe v2 X25519"), L=32)
sk_c    = X25519-privésleutel met ruwe scalar = seed (geïmporteerd als PKCS#8; clamping volgens RFC 7748)
pk_c    = ruwe 32-byte publieke sleutel; op de server als b64u (43 tekens) in vault_keys.public_key
```

**Verzegelen** `Seal_v2(P, CK, purpose, vault_id, bind)`:
```
e        = nieuwe X25519-sleutel;  epk = ruwe publieke sleutel van e (32 B)
ss       = X25519(e, P)            (weigeren als ss uit 32 nulbytes bestaat)
k        = HKDF-SHA256(ikm=ss, salt=epk || P, info=UTF-8("HorseSafe v2 seal"), L=32)
iv       = 12 willekeurige bytes
AAD      = UTF-8("HSv2") || 0x00 || UTF-8(purpose) || 0x00 || UTF-8(vault_id) || 0x00 || UTF-8(bind)
pt       = UTF-8 van exact  {"ph":<v>,"kh":<v>}   (deze sleutelvolgorde, geen spaties;
           <v> = "<b64u van 32 bytes>" of null; minstens één van beide niet-null)
ct       = AES-256-GCM(k, iv, pt, AAD)   (ciphertext || tag van 16 B)
sealed   = JSON-string  {"v":2,"kid":"<kid>","epk":"<b64u 32>","iv":"<b64u 12>","ct":"<b64u>"}
```

| purpose | `bind` | `kid` | Fase |
|---|---|---|---|
| `store` | `key_id` (UUID v4, kleine letters, met streepjes) | = `key_id` | Koblitz |
| `relay` | `approval_id` + `"\x00"` + b64u(`nonce_L`) | = `approval_id` | Montgomery (gereserveerd, nu niet bouwen) |

`vault_id` is de UUID-string van de vault zoals in de API. Gebonden velden voor `store` dus: **versie (`HSv2`), purpose, vault_id, key_id**, en via de HKDF-salt ook **epk en pk_c**. Een kopie verplaatsen naar een andere sleutel, vault of purpose faalt bij openen.

**Openen:** het omgekeerde; de client bouwt de AAD zelf uit de verwachte `vault_id` en `key_id` (nooit uit `sealed.kid` alleen), controleert `v==2` en `kid == key_id`, en gooit `HwKeyError('unseal_failed')` bij een GCM-fout. Na het openen: `pt` parsen, ph/kh decoderen naar 32 bytes, de buffers met `fill(0)` wissen.

**Servercontrole (alleen vorm), functie `validate_sealed(sealed: str, kid: str) -> bool`:**
- geldige JSON, object met **exact** de sleutels `v, kid, epk, iv, ct`;
- `v == 2` (int); `kid == key_id` van het pad/item;
- `epk`: b64u, 43 tekens; `iv`: b64u, 16 tekens; `ct`: b64u, 40 t/m 400 tekens;
- totale stringlengte ≤ 1024.
- Fout → 400 `invalid_sealed`.

**Testvectoren** `specs/testvectors/seal_v2.json`, gegenereerd door `specs/testvectors/gen_seal_v2.py` (Python, `cryptography`, vaste invoer), gebruikt door `node --test` en pytest (en later JVM):
```json
{
  "format": "HorseSafe Seal_v2 testvectors",
  "version": 1,
  "prf_vectors": [ { "prf": "<b64u 32>", "sk": "<b64u 32>", "pk": "<b64u 32>" } ],
  "seal_vectors": [ {
    "name": "ph+kh",
    "recipient_sk": "<b64u>", "recipient_pk": "<b64u>",
    "ephemeral_sk": "<b64u>", "ephemeral_pk": "<b64u>",
    "iv": "<b64u 12>", "purpose": "store", "vault_id": "<uuid>", "bind": "<uuid>", "kid": "<uuid>",
    "ph": "<b64u>|null", "kh": "<b64u>|null",
    "aad_hex": "…", "pt_utf8": "{\"ph\":…,\"kh\":…}", "k_hex": "…",
    "sealed": "{\"v\":2,…}"
  } ],
  "negative": [ { "name": "andere vault_id", "based_on": "ph+kh", "open_with": { "vault_id": "<andere uuid>" }, "expect": "unseal_failed" } ]
}
```
Minimaal: seal-vectoren voor `ph+kh`, `alleen ph`, `alleen kh`; negatieve gevallen voor andere `vault_id`, andere `key_id`, andere purpose, gewijzigde `ct`. De JS-module biedt daarvoor een testingang `_crypto.sealWith({ephemeralSk, iv, …})`.

**kdbxweb-koppeling (frontend):**
- `secretFromCredentials(cred)`: na `await cred.ready` → `{ph: cred.passwordHash ? kopie : null, kh: cred.keyFileHash ? kopie : null}` als `kdbxweb.ProtectedValue`. Leeg wachtwoord = geen wachtwoord = `ph:null` (zelfde regel als `crypto.js::openDatabase`).
- `credentialsFromHashes({ph, kh})`: `c = new kdbxweb.Credentials(null, null)`; `c.passwordHash = ph ? ProtectedValue.fromBinary(ph) : undefined`; `c.keyFileHash = kh ? ProtectedValue.fromBinary(kh) : undefined`. kdbxweb rekent daarmee `SHA-256(ph || kh)`, identiek aan pw+keyfile.

### 12.6 Endpoints

#### 12.6.0 `POST /webauthn/options` — S

Nieuwe router `routes/webauthn.py`, prefix `/webauthn`. Ruimt bij elke aanroep verlopen challenges ouder dan 1 dag op. Maximaal 10 onverbruikte, niet-verlopen challenges per gebruiker → 429 `too_many_challenges`.

Request:
```json
{ "purpose": "register" | "unlock" | "stepup",
  "vault_id": "<uuid>",          // verplicht bij register en unlock, verboden bij stepup
  "kind": "bio" | "recovery" }   // alleen en verplicht bij register
```
Ontbrekende/verboden velden → 422.

**purpose = `register`** — controles: vault van gebruiker (404); aantal sleutels (`status != 'revoked'`) in de vault < `vault_keys_max` (409 `too_many_keys`); step-up-eis van 12.6.1 (403 `stepup_required`, vroeg gemeld zodat de gebruiker niet voor niets aanraakt). Maakt **twee** challenge-rijen: `register` (create) en `register_assert` (met `parent_id` = de create-rij), beide met `vault_id`, `kind`, een nieuw `key_id` (UUID v4) en een nieuwe `prf_salt` (32 willekeurige bytes).

Response 200:
```json
{
  "purpose": "register",
  "key_id": "<uuid>",
  "prf_salt": "<b64u 32>",
  "rp": { "id": "icthorsecloud.nl", "name": "HorseSafe" },
  "user": { "id": "<b64u van UTF-8(user_id)>", "name": "<email>", "display_name": "<email>" },
  "create": { "challenge_id": "<uuid>", "challenge": "<b64u 32>" },
  "assert": { "challenge_id": "<uuid>", "challenge": "<b64u 32>" },
  "pub_key_cred_params": [ -8, -7 ],
  "exclude_credentials": [ "<b64u credential_id>", "…" ],   // alle credentials van deze gebruiker
  "authenticator_selection": { "authenticator_attachment": "cross-platform", "resident_key": "discouraged", "user_verification": "required" },
  "attestation": "direct",
  "hints": [ "security-key" ],
  "timeout_ms": 120000,
  "expires_at": 1760000000
}
```

**purpose = `unlock`** — vault van gebruiker (404). `allow_credentials` = sleutels van die vault met `kind='bio' AND status='active'`, plus `kind='recovery' AND status='active'` met recovery-state `released`. Lege lijst → 409 `no_usable_keys` (geen challenge aangemaakt).

Response 200:
```json
{
  "purpose": "unlock",
  "challenge_id": "<uuid>", "challenge": "<b64u 32>",
  "rp_id": "icthorsecloud.nl", "user_verification": "required", "hints": [ "security-key" ],
  "timeout_ms": 120000, "expires_at": 1760000000,
  "allow_credentials": [ { "key_id": "<uuid>", "kind": "bio", "credential_id": "<b64u>", "prf_salt": "<b64u 32>" } ]
}
```

**purpose = `stepup`** — `allow_credentials` = alle sleutels van de gebruiker (alle vaults) met `kind='bio' AND status='active'`. Lege lijst → 409 `no_bio_keys` (de client valt dan terug op TOTP, 12.8). Response als bij unlock, zonder `prf_salt` in de items (`{key_id, kind, credential_id}`).

#### 12.6.1 Registratie — `POST /vault/{vid}/keys` — S of SU

**Step-up-eis:** heeft de gebruiker al minstens één sleutel met `status != 'revoked'` (in welke vault dan ook)? Dan **SU** (bio of totp, 12.8). Anders S.

Client-flow (normatief):
1. `POST /webauthn/options {purpose:"register", vault_id, kind}`.
2. `navigator.credentials.create({publicKey:{ rp, user:{id, name, displayName}, challenge: create.challenge, pubKeyCredParams: [{type:"public-key",alg:-8},{type:"public-key",alg:-7}], authenticatorSelection:{authenticatorAttachment:"cross-platform", residentKey:"discouraged", requireResidentKey:false, userVerification:"required"}, attestation:"direct", hints:["security-key"], timeout, excludeCredentials, extensions:{prf:{}} }})`. Fail-closed: geen `response.getAuthenticatorData` → `browser_unsupported`; `prf.enabled !== true` → `no_prf`. Eventuele PRF-resultaten uit `create` worden genegeerd (één codepad).
3. `navigator.credentials.get({publicKey:{ challenge: assert.challenge, rpId: rp.id, allowCredentials:[{type:"public-key", id: <nieuwe credential>}], userVerification:"required", hints:["security-key"], timeout, extensions:{prf:{evalByCredential:{<credential_id b64u>:{first: prf_salt}}}} }})`. Geen `prf.results.first` → `no_prf`.
4. sk/pk afleiden (12.5); `sealed = Seal_v2(pk, CK, "store", vault_id, key_id)`; ter controle zelf openen; daarna PRF-, seed- en CK-tussenbuffers wissen.
5. POST:

Request:
```json
{
  "key_id": "<uuid uit options>",
  "kind": "bio" | "recovery",
  "label": "1..64 tekens",
  "create": {
    "challenge_id": "<uuid>",
    "credential_id": "<b64u rawId>",
    "client_data_json": "<b64u>",
    "attestation_object": "<b64u>",
    "transports": [ "usb" ]                // optioneel, alleen opgeslagen ter info; mag ontbreken
  },
  "assert": {
    "challenge_id": "<uuid>",
    "credential_id": "<b64u, gelijk aan create.credential_id>",
    "client_data_json": "<b64u>",
    "authenticator_data": "<b64u>",
    "signature": "<b64u>",
    "user_handle": "<b64u>" | null
  },
  "public_key": "<b64u 32 = pk_c>",
  "sealed": "<Seal_v2-JSON-string, kid = key_id>"
}
```
Pydantic-grenzen: `credential_id` 16-1366 tekens b64u; `client_data_json` ≤ 4096; `attestation_object` ≤ 16384; `authenticator_data` ≤ 1024; `signature` ≤ 1024; `public_key` exact 43 tekens b64u; `sealed` ≤ 1024; `label` 1-64, getrimd; `key_id` UUID-vorm.

Servercontroles, in deze volgorde (eerste fout wint; geen enkele schrijfactie of audit-`vault_key_add` vóór stap 7):
1. Vault van gebruiker → 404 `not_found`. Step-up-eis → 403 `stepup_required`.
2. Beide challenges atomair verbruiken; ze moeten bestaan, van deze gebruiker zijn, purpose `register` resp. `register_assert`, `assert.parent_id == create.challenge_id`, en `vault_id`, `kind` en `key_id` gelijk aan het request → anders 400 `invalid_challenge`.
3. Create-controles 12.4 (stappen 1-9).
4. `assert.credential_id == create.credential_id` → anders 400 `credential_mismatch`. Assertion-controles 12.4 met de net geverifieerde publieke sleutel en de `register_assert`-challenge.
5. `validate_sealed(sealed, key_id)` → 400 `invalid_sealed`.
6. Aantal sleutels opnieuw tellen → 409 `too_many_keys`.
7. INSERT in één transactie: `id=key_id`, `kind`, `label`, `status='active'`, `credential_id`, `cose_public_key` (b64u), `aaguid`, `att_fmt`, `sign_count` (uit de assertion), `prf_salt` (uit de challenge-rij — de client stuurt hem niet), `public_key`, `sealed`, tijden. Unieke-sleutelfout → 409 `credential_exists`.
8. Daarna: audit `vault_key_add` `{vault_id, key_id, kind, aaguid}`; mail "nieuwe sleutel gekoppeld" (12.11, niet-blokkerend).

Mislukt stap 2-6: audit `vault_key_add_rejected` `{vault_id, kind, reason: <foutcode>}`.

Response **201**: het sleutelobject (12.6.3).

#### 12.6.2 Ontgrendelen — `POST /vault/{vid}/keys/{kid}/unlock` — S + assertion

Vervangt `GET /vault/{vid}/keys/{kid}/sealed` (dat endpoint verdwijnt; geeft daarna 404/405).

Client-flow: `POST /webauthn/options {purpose:"unlock", vault_id}` → één `navigator.credentials.get` met `allowCredentials` uit de opties, `userVerification:"required"`, `hints:["security-key"]`, `extensions:{prf:{evalByCredential:{<credential_id>:{first:<prf_salt>}}}}` → `rawId` koppelen aan `key_id` via `allow_credentials` → POST.

Request:
```json
{
  "challenge_id": "<uuid>",
  "credential_id": "<b64u rawId>",
  "client_data_json": "<b64u>",
  "authenticator_data": "<b64u>",
  "signature": "<b64u>",
  "user_handle": "<b64u>" | null
}
```

Servercontroles, in volgorde:
1. Sleutel van gebruiker en vault → 404. `kind == 'phone'` → 404 (Koblitz).
2. Challenge verbruiken: purpose `unlock`, zelfde gebruiker en `vault_id` → anders 400 `invalid_challenge`.
3. `credential_id == key.credential_id` → anders 400 `credential_mismatch`.
4. Assertion-controles 12.4 (incl. 409 `sign_count_regression`).
5. Bij `kind == 'recovery'`: recovery-state (12.7) moet `released` zijn; anders **423** met `{"error": "recovery_<state>", "state": "<state>", "release_at": <int|null>, "release_until": <int|null>}`, waarbij `<state>` ∈ `idle | waiting | consumed | expired | blocked`. (De assertion wordt eerst geverifieerd, zodat iemand zonder de sleutel geen status kan aftasten.)
6. Bij `kind == 'bio'`: `status` moet `active` zijn (anders 423 `key_blocked`; komt in Koblitz niet voor).
7. Schrijven: `last_used_at = nu`, `sign_count`; bij recovery ook `release_consumed_at = nu`.
8. Audit: `vault_key_unlock` `{vault_id, key_id}` of `recovery_key_used` `{vault_id, key_id}`. Bij recovery: mail "noodsleutel gebruikt".

Response **200**:
```json
{ "id": "<key_id>", "sealed": "<Seal_v2-JSON-string>" }
```

Client: AAD met eigen `vault_id` en `key_id`; `pk` uit PRF moet gelijk zijn aan `public_key` van de sleutel (anders `unseal_failed`); `credentialsFromHashes` → `Kdbx.load`. `InvalidKey` hier betekent "kopie verouderd" (zie §2).

#### 12.6.3 Lijst — `GET /vault/{vid}/keys` — S

Response **200** (let op: **object**, niet langer een kale lijst):
```json
{
  "keys": [ {
    "id": "<uuid>",
    "kind": "bio" | "recovery",
    "label": "…",
    "status": "active" | "blocked",
    "credential_id": "<b64u>",
    "prf_salt": "<b64u 32>",
    "public_key": "<b64u 32>",
    "aaguid": "<uuid>",
    "authenticator": "YubiKey Bio Series - FIDO Edition" | null,
    "created_at": 0, "updated_at": 0, "last_used_at": null,
    "recovery": null | {
      "state": "idle" | "waiting" | "released" | "consumed" | "expired" | "blocked",
      "release_requested_at": null, "release_at": null, "release_until": null,
      "release_consumed_at": null, "blocked_at": null, "blocked_by": null
    }
  } ],
  "notify_available": true,
  "stepup_until": null
}
```
- `recovery` is `null` voor `bio`. `authenticator` komt uit de allowlist (`description`), `null` als onbekend.
- Nooit `sealed`, `cose_public_key` of `sign_count` in deze response.
- `notify_available` = mailer geconfigureerd (12.11). `stepup_until` = de step-up-claim uit het huidige JWT als die nog geldig is, anders `null`.
- Sortering: `created_at` oplopend. Sleutels met `status='revoked'` worden niet getoond.

Hetzelfde sleutelobject (één item uit `keys`) is de response van registratie, release, cancel, block en unblock.

#### 12.6.4 Opnieuw verzegelen — `PUT /vault/{vid}/keys/sealed` — SU

Voor na een wijziging buiten HorseSafe (KeePassXC). Request:
```json
{ "items": [ { "id": "<key_id>", "sealed": "<Seal_v2, kid = id>" } ] }
```
Client: vóór het verzegelen toont de client elke sleutel die een kopie krijgt (label, type, model, koppeldatum; gekoppeld in de laatste 7 dagen gemarkeerd) en vraagt bevestiging; onbekende sleutels eerst verwijderen.
1 t/m 20 items, unieke ids. Controles: vault (404); SU (403 `stepup_required`); elke `id` is een sleutel van deze vault met `status != 'revoked'` (anders 400 `unknown_key`); `validate_sealed(item.sealed, item.id)` (anders 400 `invalid_sealed`). Alles of niets in één transactie. Response **200** `{"updated": <n>}`. Audit `vault_key_reseal` `{vault_id, count}`.

#### 12.6.5 Wachtwoord/keyfile wijzigen — `PUT /vault/{vid}/rekey` — SU + If-Match

`multipart/form-data`:
- header `If-Match: <huidige etag>` — ontbreekt → **428** `if_match_required` (header optioneel declareren, zelf de 428 geven);
- veld `blob`: de nieuwe KDBX4 (nieuwe pw en/of keyfile). Client (`credentialsForRekey`, 12.13): een leeg veld behoudt het huidige onderdeel (pw+keyfile blijft pw+keyfile); verwijderen alleen via een expliciet vinkje met bevestiging; kdbxweb krijgt altijd een eigen kopie van de keyfile-bytes (een keyfile van 32 bytes wordt anders in place gebruikt en zou bij wissen de kluis onopenbaar maken). Vóór de upload toont de client de ontvangende sleutels zoals bij 12.6.4; wijkt de lijst bij het verzegelen af → `keys_changed`;
- veld `sealed`: JSON-string `{"items":[{"id","sealed"}]}` met **exact** één item per sleutel van de vault met `status != 'revoked'` (ook geblokkeerde noodsleutels). Nul sleutels → `{"items":[]}` is toegestaan.

Controles en volgorde:
1. vault (404); SU (403 `stepup_required`); If-Match (428); blobgrootte (413 `blob_too_large`).
2. `sealed` parsen (422 bij kapotte JSON); verzameling ids ≠ verzameling actuele sleutels → 409 `keys_mismatch`; `validate_sealed` per item → 400 `invalid_sealed`.
3. etag ≠ If-Match → 412 `etag_mismatch` met `current_etag` (zoals `PUT /vault/{vid}`).
4. Atomair: `BEGIN IMMEDIATE` → UPDATE alle `sealed` + `updated_at` → UPDATE `vaults` (size, etag, updated_at) → blob atomair wegschrijven (`_atomic_write`) → `COMMIT`. Mislukt het wegschrijven: `ROLLBACK`, 500. (Restrisico: COMMIT faalt na het wegschrijven; dan zijn de kopieën verouderd en meldt de UI "kopie verouderd".) `PUT /vault/{vid}` (gewone save, ook het vastleggen van pins) gebruikt dezelfde `BEGIN IMMEDIATE`-volgorde met etag-controle binnen de transactie (reviewronde 3): een save die tegelijk met een rekey loopt, wacht en krijgt 412, en kan de gerekeyde blob dus niet overschrijven met een KDBX onder de oude credentials.
5. Audit `vault_rekey` `{vault_id, size, keys}`; mail "wachtwoord/keyfile van je kluis gewijzigd" **ná het antwoord** (`BackgroundTask`): een trage SMTP-server mag een gecommitte rekey niet laten verlopen (nginx-504).

**Onbekende uitkomst (client, reviewronde 2):** een expliciete weigering (servercode zoals `stepup_required`, `etag_mismatch`, `keys_mismatch`, `invalid_sealed`, `write_failed`, of een 4xx) betekent "niets doorgevoerd": de tab houdt de oude credentials. Geen of een onduidelijk antwoord (netwerkfout, 5xx/504 zonder code) → `HwKeyError('rekey_unknown')`; de client haalt dan `GET /vault` op en vergelijkt de etag met SHA-256 van de verstuurde blob (`rekeyLanded`). Gelijk → de rekey is gelukt en de tab neemt de nieuwe credentials en etag over; ongelijk → `rekey_not_applied`, oude credentials blijven; niet vast te stellen → de kluis wordt vergrendeld met de melding beide wachtwoorden/keyfiles te bewaren en eerst het nieuwe te proberen. Na een geslaagde rekey gaat de tab nooit meer terug naar de oude credentials.

Response **200** met header `ETag`:
```json
{ "vault": { …VaultPublic… }, "resealed": <n> }
```

#### 12.6.6 Noodsleutel: vrijgave — `POST|DELETE /vault/{vid}/keys/{kid}/release` — S

**POST (aanvragen):**
1. sleutel (404); `kind != 'recovery'` → 400 `not_recovery_key`.
2. state `blocked` → 409 `recovery_blocked`.
3. state `waiting` of `released` → **200** met het ongewijzigde sleutelobject (niet verlengen of herstarten; geen nieuwe mail).
4. Mailer niet geconfigureerd → **503** `notify_unavailable`.
5. Vrijgave vastleggen en committen: `release_requested_at = nu`, `release_at = nu + recovery_delay_hours*3600`, `release_consumed_at = NULL`. Verbinding sluiten.
6. Mail "vrijgave noodsleutel aangevraagd" versturen (`asyncio.to_thread`, buiten de DB-verbinding) en het resultaat **afwachten**. Mislukt: vrijgave terugdraaien (`release_requested_at = release_at = NULL`), audit `notify_failed` `{event:"recovery_release_request"}`, **503** `notify_failed`.
7. Gelukt: audit `recovery_release_request` `{vault_id, key_id, release_at}` (met IP en user-agent). **200** met het sleutelobject.

**DELETE (annuleren):** sleutel (404); niet recovery → 400 `not_recovery_key`; state niet `waiting` of `released` → **409** `nothing_to_cancel`; anders `release_requested_at = release_at = NULL`, audit `recovery_release_cancel`, mail "vrijgave geannuleerd", **200** met het sleutelobject.

#### 12.6.7 Noodsleutel: blokkeren — `POST|DELETE /vault/{vid}/keys/{kid}/block`

**POST (blokkeren) — S** (defensief, dus géén step-up):
sleutel (404); niet recovery → 400 `not_recovery_key`; al `blocked` → **200**, ongewijzigd, geen mail. Anders: `status='blocked'`, `blocked_at=nu`, `blocked_by='web'`, lopende vrijgave gewist (`release_requested_at = release_at = NULL`). Audit `recovery_block` `{vault_id, key_id, by:"web"}`, mail "noodsleutel geblokkeerd". **200** met het sleutelobject.

**DELETE (opheffen) — SU met `stepup_method == "bio"`** (besluit 3):
sleutel (404); niet recovery → 400 `not_recovery_key`; geen geldige step-up → 403 `stepup_required`; step-up met andere methode dan `bio` → **403 `stepup_bio_required`**; niet `blocked` → 409 `not_blocked`; de Bio uit de step-up (JWT-claim `stepup_key`) is geen actieve Bio van de gebruiker of is gekoppeld ná `blocked_at` → **403 `stepup_key_too_new`** + audit `recovery_unblock_rejected` `{vault_id, key_id, reason}` (R6: een na de blokkade gekoppelde Bio kan niet opheffen; dan noodsleutel verwijderen en opnieuw koppelen). Anders `status='active'`, `blocked_at = blocked_by = NULL` (state wordt `idle`). Audit `recovery_unblock` `{vault_id, key_id, stepup_method}`, mail "blokkade noodsleutel opgeheven". **200** met het sleutelobject.
(Miller voegt `stepup_method == "phone"` toe als tweede toegestane methode.)

#### 12.6.8 Verwijderen — `DELETE /vault/{vid}/keys/{kid}` — S

Defensief, geen step-up. sleutel (404) → DELETE. Audit `vault_key_delete` `{vault_id, key_id, kind}`; mail "sleutel verwijderd". **204**, lege body.

**Via de kluis (`DELETE /vault/{vid}`, reviewronde 3):** de sleutels verdwijnen mee door `ON DELETE CASCADE`. Ze tellen als verwijderd: per sleutel audit `vault_key_delete` `{vault_id, key_id, kind, via:"vault_delete"}` en één mail "sleutel verwijderd". Zo start ook dan de TOTP-afkoelperiode van §12.8 (anders kon wie wachtwoord + TOTP heeft een bijkluis met de enige Bio weggooien en direct een TOTP-step-up krijgen, R6).

### 12.7 Recovery-state (afleiding, één functie in de service)

```
recovery_state(key, now):
  if key.status == 'blocked':                         return 'blocked'
  if key.release_at is NULL:                          return 'idle'
  if key.release_consumed_at is not NULL:             return 'consumed'
  if now <  key.release_at:                           return 'waiting'
  if now <  key.release_at + recovery_window_hours*3600: return 'released'
  return 'expired'
release_until = release_at + recovery_window_hours*3600   (NULL als release_at NULL)
```
Een nieuwe aanvraag mag vanuit `idle`, `consumed` en `expired` en wist `release_consumed_at`. Tijd komt uit `vault_key_service.now()` (tests verzetten de klok).

### 12.8 Step-up — `POST /auth/stepup` — S

Request, één van:
```json
{ "method": "bio", "challenge_id": "<uuid>", "credential_id": "<b64u>", "client_data_json": "<b64u>", "authenticator_data": "<b64u>", "signature": "<b64u>", "user_handle": "<b64u>" | null }
```
```json
{ "method": "totp", "code": "123456" }
```

**bio:** challenge (purpose `stepup`, zelfde gebruiker) → 400 `invalid_challenge`; `credential_id` hoort bij een sleutel van de gebruiker met `kind='bio' AND status='active'` → anders 400 `credential_mismatch`; assertion-controles 12.4. Geen PRF nodig.
**totp:** alleen toegestaan als de gebruiker **geen** actieve bio-sleutel heeft → anders 403 `stepup_method_not_allowed`; gebruiker zonder TOTP → 409 `stepup_unavailable`; binnen `recovery_delay_hours` na een audit `vault_key_delete` met `kind:"bio"` (ook via `DELETE /vault/{vid}`, §12.6.8) of een `mfa_setup_totp` met `had_keys:true` → **403 `stepup_cooldown`** met `retry_at` (R6); code fout → 401 `invalid_code` (audit `stepup_fail`); meer dan 5 fouten per 15 minuten per gebruiker (geteld via audit `stepup_fail`) → 429 `too_many_attempts`.

Succes: nieuw JWT-cookie met de bestaande claims plus
```
"stepup_until": now + stepup_ttl_seconds,
"stepup_method": "bio" | "totp",
"stepup_key": "<key_id>"            // alleen bij bio: welke sleutel bevestigde (unblock, 12.6.7)
```

**TOTP wijzigen (`POST /auth/totp/verify` met `secret`):** bestaat er al een TOTP-secret → **409 `totp_already_configured`** (eerst `/auth/totp/disable` met de huidige code); met hardware-sleutels alleen vanuit een sessie met `mfa=true` (anders 403 `mfa_required`). Audit `mfa_setup_totp` `{action, had_keys}`; mail "authenticator-app ingesteld/verwijderd" bij instellen en uitschakelen.
`jwt_service.issue` krijgt daarvoor optionele parameters; `reissue_with_mfa` en een gewone login laten deze claims weg (step-up vervalt dan). Audit `stepup` `{method}`. Response **200**:
```json
{ "ok": true, "method": "bio", "stepup_until": 1760000300 }
```

**SU-controle** (helper `require_stepup(request, methods=("bio","totp"))`): `mfa == true` en `stepup_until >= now`, anders 403 `stepup_required`; `stepup_method` niet in `methods` → 403 `stepup_bio_required` (alleen bij unblock relevant: `methods=("bio",)`).

**Waar SU nodig is in Koblitz:** registratie (als er al sleutels zijn), `PUT …/keys/sealed`, `PUT …/rekey`, `DELETE …/block` (alleen bio). Niet bij: lijst, unlock, release, cancel, block, delete.

Client (`stepup.js`): bij 403 `stepup_required` de dialoog tonen. Eerst `checkSupport()`: zonder hardware-sleutelsteun (`browser_unsupported`, `safari`, `wrong_host`; tijdens de poging ook `no_prf`) meteen het TOTP-veld met de reden (bij bio-only alleen de reden). Opties `purpose:"stepup"`; 409 `no_bio_keys` → TOTP-veld; anders "Raak je YubiKey Bio aan" (met de link "Gebruik authenticator-code" verborgen). Na succes de oorspronkelijke actie één keer herhalen. Bij `stepup_bio_required`: alleen de Bio-route tonen.

### 12.9 Database: migratie 005 herschrijven (geen 006)

**Keuze:** `005_vault_keys.sql` wordt herschreven in plaats van een nieuwe 006 toe te voegen.
**Waarom:** productie draait op schema 4 (`version.json`, `schema.sql`); 005 bestaat alleen in de WIP-commit `9000044` en is nooit gedeployed. Een 006 bovenop een nooit-uitgerolde 005 zou alleen een ALTER/rebuild-keten opleveren voor tabellen zonder data, en SQLite kan een `CHECK` (zoals `kind IN (…, 'phone')`) niet met ALTER wijzigen. Ontwikkel- en test-DB's die de WIP-005 al hebben toegepast, moeten opnieuw worden aangemaakt (pytest maakt per test een verse DB). Miller krijgt 006, Montgomery 007.

**Migratiepatroon:** `INSERT OR REPLACE INTO schema_version (version) VALUES (5);` — **niet** `DELETE FROM schema_version` (bug in de WIP).

**`schema.sql`:** volgt het bestaande patroon (fresh-install-blob = alle migraties): dezelfde DDL als 005 toevoegen, kop "Schema-versie 5", `INSERT OR IGNORE INTO schema_version (version) VALUES (5);`. Een pytest controleert dat een DB via `schema.sql` en een DB via schema-4 + 005 voor deze drie tabellen dezelfde `sqlite_master.sql` hebben.

**DDL (normatief):**
```sql
-- Migration 005 — v0.2.0-Koblitz: hardware-sleutels per vault (P-CRYPT-09)
CREATE TABLE IF NOT EXISTS devices (               -- Miller vult deze tabel; nu leeg, staat er voor de FK
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label           TEXT NOT NULL,
    model           TEXT,
    k_dev_pub       TEXT NOT NULL,
    k_biosig_pub    TEXT NOT NULL,
    att_chains      TEXT NOT NULL,
    security_level  TEXT NOT NULL,
    strongbox       INTEGER NOT NULL DEFAULT 0,
    app_version     TEXT,
    created_at      INTEGER NOT NULL,
    last_seen_at    INTEGER,
    revoked_at      INTEGER
);
CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);

CREATE TABLE IF NOT EXISTS vault_keys (
    id                    TEXT PRIMARY KEY,                 -- UUID v4 (= key_id uit register-opties)
    user_id               TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    vault_id              TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    kind                  TEXT NOT NULL CHECK (kind IN ('bio', 'recovery', 'phone')),
    label                 TEXT NOT NULL,
    status                TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'blocked', 'revoked')),
    device_id             TEXT REFERENCES devices(id) ON DELETE CASCADE,   -- alleen kind='phone'
    credential_id         TEXT,                             -- WebAuthn, b64u
    cose_public_key       TEXT,                             -- WebAuthn, b64u (COSE_Key)
    aaguid                TEXT,                             -- UUID-string
    att_fmt               TEXT,                             -- 'packed' (of 'none' in tests)
    sign_count            INTEGER NOT NULL DEFAULT 0,
    prf_salt              TEXT,                             -- 32 B b64u, niet geheim
    public_key            TEXT NOT NULL,                    -- X25519 pk_c, 32 B b64u
    sealed                TEXT NOT NULL,                    -- Seal_v2-JSON
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL,
    last_used_at          INTEGER,
    release_requested_at  INTEGER,                          -- alleen recovery
    release_at            INTEGER,                          -- alleen recovery
    release_consumed_at   INTEGER,                          -- alleen recovery
    blocked_at            INTEGER,                          -- alleen recovery
    blocked_by            TEXT,                             -- 'web' | 'device:<id>'
    CHECK ((kind = 'phone') = (device_id IS NOT NULL)),
    CHECK (kind = 'phone' OR (credential_id IS NOT NULL AND cose_public_key IS NOT NULL AND prf_salt IS NOT NULL)),
    CHECK (status <> 'blocked' OR kind = 'recovery'),
    UNIQUE (user_id, credential_id)
);
CREATE INDEX IF NOT EXISTS idx_vault_keys_vault ON vault_keys(vault_id);
CREATE INDEX IF NOT EXISTS idx_vault_keys_user ON vault_keys(user_id);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id              TEXT PRIMARY KEY,                   -- UUID v4 = challenge_id
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose         TEXT NOT NULL CHECK (purpose IN ('register', 'register_assert', 'unlock', 'stepup')),
    parent_id       TEXT REFERENCES webauthn_challenges(id) ON DELETE CASCADE,  -- register_assert -> register
    vault_id        TEXT REFERENCES vaults(id) ON DELETE CASCADE,
    kind            TEXT CHECK (kind IS NULL OR kind IN ('bio', 'recovery', 'phone')),
    key_id          TEXT,                               -- register: het toekomstige vault_keys.id
    prf_salt        TEXT,                               -- register: b64u 32 B
    challenge_hash  TEXT NOT NULL,                      -- hex SHA-256 van de 32 challenge-bytes; nooit de challenge zelf
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    used_at         INTEGER
);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_user ON webauthn_challenges(user_id, expires_at);

INSERT OR REPLACE INTO schema_version (version) VALUES (5);
```

### 12.10 Audit-events (Koblitz)

`vault_key_add`, `vault_key_add_rejected`, `vault_key_delete`, `vault_key_unlock`, `vault_key_reseal`, `vault_key_clone_suspect`, `vault_rekey`, `recovery_release_request`, `recovery_release_cancel`, `recovery_key_used`, `recovery_block`, `recovery_unblock`, `recovery_unblock_rejected`, `stepup`, `stepup_fail`, `notify_failed`.

- Altijd met `user_id`, IP en (waar beschikbaar) user-agent; `detail` alleen met ids, `kind`, `aaguid`, tijden, foutcodes en tellingen.
- Nooit: `sealed`, `ph`, `kh`, PRF-uitvoer, challenges, client-data, signatures, TOTP-codes, SMTP-gegevens.
- De WIP-namen `recovery_release_requested` / `recovery_release_cancelled` vervallen (nog nooit gelogd in productie).

### 12.11 Mailer (besluit 4)

Nieuwe module `backend/services/mail_service.py`; zowel `magic_link_service` als `vault_key_service.notify_user` gebruiken hem.

| Setting | Env | Default |
|---|---|---|
| `smtp_host` | `HORSESAFE_SMTP_HOST` | `""` |
| `smtp_port` | `HORSESAFE_SMTP_PORT` | `587` |
| `smtp_user` | `HORSESAFE_SMTP_USER` | `""` |
| `smtp_password` | `HORSESAFE_SMTP_PASSWORD` | `""` |
| `smtp_from` | `HORSESAFE_SMTP_FROM` | `""` (= `smtp_user`) |
| `smtp_starttls` | `HORSESAFE_SMTP_STARTTLS` | `true` |
| `smtp_timeout_seconds` | `HORSESAFE_SMTP_TIMEOUT_SECONDS` | `15` |
| `gmail_user`, `gmail_app_password` | bestaand | fallback |

Gedrag:
- **Keuze zender:** `smtp_host` en `smtp_user` en `smtp_password` gezet → `SMTPSender`: `smtplib.SMTP(host, port, timeout)` → `ehlo` → `starttls(context=ssl.create_default_context())` (als `smtp_starttls`) → `ehlo` → `login` → `send_message`. Anders, als `gmail_user` en `gmail_app_password` gezet zijn → bestaande `GmailSMTPSender` (465, SMTP_SSL; werkt niet op HC55, alleen fallback). Anders: niet geconfigureerd.
- **From = SMTP-gebruiker:** `From` is `smtp_from or smtp_user`. Als `smtp_from` gezet is en afwijkt van `smtp_user`, logt de app bij start een waarschuwing en gebruikt toch `smtp_user` (Hostinger-regel MAIL_FROM = SMTP_USER). Productiewaarde: `info@icthorse.nl`.
- **API van de module:** `is_configured() -> bool`; `send(to, subject, body) -> None` (synchroon, gooit bij fout); `async send_async(to, subject, body) -> bool` (via `asyncio.to_thread`, vangt fouten af, logt zonder credentials, `False` bij fout); `set_sender(sender)` voor tests. `magic_link_service.set_sender` blijft bestaan en delegeert, zodat `test_mfa_magic_link.py` blijft werken.
- **Aanroepen:** nooit binnen een open DB-verbinding of transactie; eerst de DB-actie afronden, dan `send_async`. Uitzondering die op het resultaat wacht: de noodsleutel-vrijgave (12.6.6). Overige meldingen: fout → audit `notify_failed` `{event}`, de actie zelf slaagt.
- **`notify_available`** (in de lijst-response, 12.6.3) = `is_configured()`.
- **Secrets:** de waarden staan alleen in `/opt/horsesafe/.env` (gevuld uit ClaudeSecrets door Christian). Nooit in code, docs, tests of logs; in docs en `.env.example` alleen de variabelenamen.

**Meldingen (onderwerp; body in het Nederlands, met label, tijd (UTC, `dd-mm-jjjj uu:mm`), IP en "Was jij dit niet?"-advies; nooit geheimen):**

| Event | Onderwerp |
|---|---|
| sleutel gekoppeld | HorseSafe: nieuwe sleutel gekoppeld |
| sleutel verwijderd | HorseSafe: sleutel verwijderd |
| vrijgave aangevraagd | HorseSafe: vrijgave noodsleutel aangevraagd |
| vrijgave geannuleerd | HorseSafe: vrijgave noodsleutel geannuleerd |
| noodsleutel gebruikt | HorseSafe: noodsleutel gebruikt |
| geblokkeerd | HorseSafe: noodsleutel geblokkeerd |
| blokkade opgeheven | HorseSafe: blokkade noodsleutel opgeheven |
| rekey | HorseSafe: wachtwoord of keyfile van je kluis gewijzigd |
| clone-vermoeden | HorseSafe: verdachte sleutel-teller |

### 12.12 `/health`

Bestaande response plus `"test_attestation": <bool>`. `version` wordt `0.2.0-Koblitz`. Geen mail- of sleutelinformatie.

### 12.13 Frontend-contract (`frontend/js/hwkeys.js`)

Publieke API op `window.HorseSafeHwKeys` (ook laadbaar onder Node ≥ 20 voor de cryptotests):

| Functie | Gedrag |
|---|---|
| `checkSupport()` → `{ok, reason}` | fail-closed: `PublicKeyCredential` aanwezig; WebCrypto X25519 werkt; geen Safari (UA bevat `Safari` en niet `Chrome`/`Chromium`/`Edg`/`Firefox`, en elke iOS/iPadOS) → `reason:"safari"`; andere host dan de rpId (behalve `localhost` in dev) → `reason:"wrong_host"` met link naar `https://icthorsecloud.nl/HorseSafe/`. |
| `listKeys(vaultId)` → `{keys, notify_available, stepup_until}` | 12.6.3 |
| `enroll({vaultId, kind, label, secret, pin})` → sleutelobject | 12.6.1 volledig, inclusief zelf-openen vóór POST; daarna `await pin(key_id, public_key)` (vastleggen in de KDBX en opslaan) vóór de POST — zonder `pin` of als die faalt: `pin_save_failed`, geen POST (R15) |
| `unlock({vaultId})` → `{secret:{ph,kh}, key}` | 12.6.2 |
| `resealAll({vaultId, keys, secret, pins})` → `n` | 12.6.4 (SU); eerst `pins[k.id] === k.public_key` voor elke sleutel, anders `key_pin_mismatch`/`key_not_pinned` en niets verzegeld (R15) |
| `rekey({vaultId, etag, blob, keys, secret, pins})` → `{vault, resealed, etag}` | 12.6.5 (SU); pins als bij `resealAll`; netwerkfout/5xx zonder code → `rekey_unknown` |
| `rekeyLanded({vaultId, blob})` → `{state:'landed'\|'not_landed'\|'unknown', etag?}` | 12.6.5 onbekende uitkomst: server-etag == SHA-256(blob)? (`blobEtag(blob)`) |
| `readPins(db, vaultId)`, `pinKey(db, vaultId, keyId, publicKey)`, `pinStatus(key, pins)` | Vastgelegde ontvangers in de KDBX (`db.meta.customData`, veld `HorseSafe.KeyPins.v1` = `{"v":1,"vault_id":…,"keys":{key_id: public_key}}`); `pinStatus` → `ok`/`missing`/`mismatch` voor het sleutelpaneel |
| `requestRelease`, `cancelRelease`, `block`, `unblock`, `deleteKey` `(vaultId, keyId)` | 12.6.6-12.6.8 |
| `stepUp({method, code?})` | 12.8 (`stepup.js` bouwt de dialoog hierop) |
| `secretFromCredentials(cred)`, `credentialsFromHashes(secret)` | 12.5 |
| `credentialsForRekey({current, password?, keyFile?, removePassword?, removeKeyFile?})` → `{credentials, secret}` | 12.6.5: onveranderd onderdeel blijft; fouten `rekey_nothing`, `rekey_conflict`, `rekey_no_factor`; deelt geen geheugen met `keyFile` |
| `_crypto` | `keypairFromPrf`, `seal`, `unseal`, `sealWith`, `buildAad`, `b64uEncode`, `b64uDecode` (tests) |

Fouten zijn `HwKeyError` met `code` = de servercode uit `detail.error`, of een clientcode: `browser_unsupported`, `no_prf`, `no_uv`, `synced`, `unseal_failed`, `cancelled` (gebruiker annuleert / `NotAllowedError`), `wrong_host`, `safari`, `invalid_request` (422), `api_<status>`. Extra velden uit `detail` (zoals `release_at`, `state`) worden op het foutobject gezet.

Clientcontroles (defense in depth naast de server): UV-vlag aan, BE-vlag uit, `getAuthenticatorData` aanwezig, `prf.results.first` aanwezig, `pk` uit PRF == `key.public_key` (ontgrendelen), `public_key` == vastgelegde pin in de KDBX (reseal/rekey, R15). Ontbreekt iets → fout, nooit stil doorgaan.

**Nederlandse meldingen (minimaal):**

| Code | Melding |
|---|---|
| `browser_unsupported`, `safari` | Deze browser kan niet met een YubiKey ontgrendelen. Gebruik Chrome of Edge op de laptop. |
| `wrong_host` | Hardware-sleutels werken alleen op icthorsecloud.nl. Open HorseSafe daar. |
| `no_prf` | Deze sleutel of browser ondersteunt de benodigde functie (PRF) niet. Gebruik een YubiKey 5 of Bio in Chrome of Edge. |
| `uv_missing`, `no_uv` | De sleutel heeft geen vingerafdruk of PIN gevraagd. |
| `not_device_bound`, `synced` | Dit is een gesynchroniseerde passkey. Alleen een fysieke YubiKey is toegestaan. |
| `attestation_invalid`, `authenticator_not_allowed` | Deze sleutel wordt niet geaccepteerd. Gebruik een YubiKey Bio (of YubiKey 5 als noodsleutel). |
| `not_bio_authenticator` | Voor dagelijks gebruik is een YubiKey Bio nodig. Een gewone YubiKey kan alleen als noodsleutel. |
| `credential_exists` | Deze sleutel is al gekoppeld. |
| `too_many_keys` | Het maximum aantal sleutels voor deze kluis is bereikt. |
| `invalid_challenge` | De aanvraag is verlopen. Probeer het opnieuw. |
| `sign_count_regression` | Deze sleutel gedraagt zich verdacht (teller ging terug). Ontgrendel met je keyfile en controleer je sleutels. |
| `unseal_failed` | Deze sleutel past niet bij de verzegelde kopie. |
| `recovery_idle` | Vraag eerst vrijgave van de noodsleutel aan. |
| `recovery_waiting` | De noodsleutel is nog niet vrijgegeven (wacht nog …). |
| `recovery_expired` | Het venster van de noodsleutel is verlopen. Vraag opnieuw vrijgave aan. |
| `recovery_consumed` | Deze vrijgave is al gebruikt. Vraag opnieuw vrijgave aan. |
| `recovery_blocked` | De noodsleutel is geblokkeerd. Hef de blokkade op met je YubiKey Bio. |
| `notify_unavailable` | Meldingen werken niet. Vrijgave van de noodsleutel is tijdelijk uitgeschakeld. |
| `notify_failed` | De melding kon niet verstuurd worden; de vrijgave is niet gestart. Probeer het later opnieuw. |
| `nothing_to_cancel` | Er loopt geen vrijgave om te annuleren. |
| `not_blocked` | Deze noodsleutel is niet geblokkeerd. |
| `stepup_required` | Bevestig eerst met je YubiKey Bio (of authenticator-code). |
| `stepup_bio_required` | Opheffen kan alleen met je YubiKey Bio. |
| `stepup_unavailable` | Stel eerst een authenticator-app (TOTP) in of koppel een YubiKey Bio. |
| `stepup_cooldown` | Bevestigen met een authenticator-code kan tijdelijk niet: kort geleden is een YubiKey Bio verwijderd of de authenticator-app ingesteld. (+ resterende tijd) |
| `stepup_key_too_new` | Opheffen kan alleen met een YubiKey Bio die al gekoppeld was vóór de blokkade. Verwijder anders de noodsleutel en koppel hem opnieuw. |
| `totp_already_configured` | Er is al een authenticator-app ingesteld. Schakel die eerst uit met een geldige code. |
| `rekey_nothing`, `rekey_conflict`, `rekey_no_factor` | Kies een nieuw wachtwoord, een nieuwe keyfile, of verwijder er één. / Kies per onderdeel óf een nieuwe waarde óf verwijderen. / De kluis moet een wachtwoord of een keyfile houden. |
| `keys_changed` | De sleutellijst is intussen gewijzigd. Controleer de sleutels en probeer opnieuw. |
| `key_pin_mismatch` | De publieke sleutel van "<label>" wijkt af van wat je kluis bij het koppelen vastlegde. Er is mogelijk met de server geknoeid; er is niets verzegeld. Verwijder die sleutel en koppel hem opnieuw. |
| `key_not_pinned` | "<label>" staat niet in je kluis vastgelegd (koppelen niet afgerond, of de kluis is buiten HorseSafe bewerkt); er is niets verzegeld. Verwijder die sleutel en koppel hem opnieuw. |
| `pin_save_failed` | De sleutel kon niet in je kluis worden vastgelegd; hij is niet gekoppeld. Probeer het opnieuw. |
| `rekey_unknown`, `rekey_not_applied` | Er kwam geen duidelijk antwoord van de server; onbekend of het wijzigen is doorgevoerd. / Het wijzigen is niet doorgevoerd …; je huidige wachtwoord/keyfile blijft gelden. |
| `keys_mismatch` | De sleutellijst is intussen gewijzigd. Herlaad en probeer opnieuw. |
| `etag_mismatch` | De kluis is elders gewijzigd. Herlaad en probeer opnieuw. |
| kopie verouderd (`InvalidKey` na unlock) | Kopie verouderd. Ontgrendel één keer met wachtwoord/keyfile en klik Bijwerken. |

`vault-ui.js`: `state.secret` = `secretFromCredentials(...)` na een geslaagde `openDatabase`; bij vergrendelen worden de ProtectedValues gewist en `state.secret = null`. `crypto.js::openDatabase` krijgt een variant die een kant-en-klaar `Credentials`-object accepteert (voor de hardware-route).

### 12.14 Minimale tests (Koblitz)

pytest (`backend/tests/test_vault_keys.py`, `test_webauthn.py`, `test_stepup.py`, `test_mail_service.py`; assertions/attestation gemaakt met een in-test softwareauthenticator, `test_attestation` alleen waar nodig):
- registratie: BE=1 → 400 `not_device_bound`; UV=0 → 400 `uv_missing`; niet-Bio-AAGUID als `bio` → 400 `not_bio_authenticator`; `fmt=none` zonder testvlag → 400 `attestation_invalid`; verkeerde origin → 400 `origin_mismatch`; hergebruikte of verlopen challenge → 400 `invalid_challenge`; `sealed.kid` ≠ `key_id` → 400 `invalid_sealed`; tweede sleutel zonder step-up → 403 `stepup_required`; geen `vault_key_add`-audit bij een afgewezen registratie.
- unlock: signCount-daling → 409; recovery na 23 u → 423 `recovery_waiting`; na 25 u met assertion → 200; daarna nogmaals → 423 `recovery_consumed`; na 49 u → `expired`; geblokkeerd → 423 `recovery_blocked`.
- release zonder mailer → 503 `notify_unavailable`; mailer gooit → 503 `notify_failed` en state blijft `idle`; blokkeren → release 409; deblokkeren zonder step-up → 403 `stepup_required`; met TOTP-step-up → 403 `stepup_bio_required`; met bio-step-up → 200.
- cancel zonder lopend verzoek → 409 `nothing_to_cancel`.
- rekey zonder If-Match → 428; ontbrekende sleutel in `sealed` → 409 `keys_mismatch`; succes vervangt blob en alle kopieën.
- step-up: TOTP terwijl er een actieve bio is → 403 `stepup_method_not_allowed`; JWT na `stepup_ttl_seconds` → 403; TOTP-secret vervangen (met of zonder MFA) → 409 `totp_already_configured`; TOTP-step-up na Bio verwijderen of TOTP instellen met sleutels → 403 `stepup_cooldown`, na 24 u → 200; deblokkeren met een Bio die ná de blokkade is gekoppeld → 403 `stepup_key_too_new`.
- frontend (`node --test`): `credentialsForRekey` behoudt het onveranderde onderdeel en blijft juist na het wissen van een keyfile van 32 bytes; `stepup.js` valt zonder hardware-sleutelsteun terug op TOTP (niet bij bio-only).
- Seal_v2: Python-referentie reproduceert `specs/testvectors/seal_v2.json` en het bestand is gelijk aan de uitvoer van `gen_seal_v2.py`; `node --test` controleert dezelfde vectoren (nooit overslaan; ontbreekt het bestand, dan faalt de test); `validate_sealed` weigert v1, extra sleutels en verkeerde lengtes.
- Reviewronde 2: wachtwoordlogin + `backup-codes/generate` → 403 `mfa_required`; magic-link zonder (of met andermans) wachtwoordsessie → geweigerd en niet verbruikt; reseal/rekey met verwisselde of niet-vastgelegde `public_key` → geen PUT; rekey met 5xx/netwerkfout → `rekey_unknown`, `rekeyLanded` herkent een gecommitte rekey; Playwright: pins overleven opslaan + openen, verwisselde `public_key` blokkeert reseal, rekey met verloren antwoord (504) wordt herkend en de tab werkt door met de nieuwe etag.
- schema: `schema.sql` en schema-4 + 005 leveren dezelfde DDL; `schema_version` = 5 zonder `DELETE`.
- mailer: STARTTLS-pad met nep-SMTP; From = `smtp_user`; magic-link gaat via de mailer; `notify_user` blokkeert de event-loop niet (`to_thread`).
- app-start weigert `test_attestation` met rpId `icthorsecloud.nl`.

`node --test` en Playwright: zie §10, acceptatie 2 en 3.

### 12.15 Bewust niet in Koblitz

`kind='phone'`, `devices`-endpoints, pairing, `/device/v1/*`, `/app/*`, approvals, de JWT-claim `sid`, `relay`-purpose, FCM, native kluis. De tabellen `devices` en de `phone`-waarden in de CHECKs staan er alleen zodat Miller zonder table-rebuild kan bouwen; de Koblitz-API weigert `kind:"phone"` (422 via het `Literal`-type).

## 13. Miller deel 2 API-contract (v0.3.4) — telefoon koppelen

Bindend voor backend, web en app (akkoord bouwplan fase A, 14-10-2026, §11.2). Afwijkingen = bug of contractwijziging.

### 13.0 Wijziging t.o.v. §4.5 (aanscherping)

In §4.5 maakte de **server** het QR-geheim. Een kwaadwillende server kan dan de telefoonsleutels verwisselen en
met rekenkracht een SAS van 6 cijfers laten kloppen (zelfde gat als §11.2.3). Daarom maakt nu de **browser** het
geheim `s` (16 B). De server krijgt alleen `k_srv`; de browser houdt `k_web`. De telefoon MAC't het transcript met
beide. De browser controleert `mac_web` zelf: de server kan geen andere `pk_c` laten verzegelen zonder dat de
browser het merkt. De SAS blijft als zichtbare controle voor de gebruiker (verkeerd toestel gescand).

### 13.1 Afleidingen (testvectoren `specs/testvectors/pair_v1.json`, generator `gen_pair_v1.py`)

```
s            = 16 willekeurige bytes (browser, crypto.getRandomValues; nooit naar de server)
k_srv        = HKDF-SHA256(ikm=s, salt=32 nulbytes, info=UTF-8("HSv2 pair srv"), L=32)
k_web        = HKDF-SHA256(ikm=s, salt=32 nulbytes, info=UTF-8("HSv2 pair web"), L=32)
QR           = "hs1p:" + pairing_id + "." + b64u(s)                       (b64u = base64url zonder '=')
att_challenge= SHA-256( UTF-8("HSv2 pair att") || 0x00 || UTF-8(pairing_id) || 0x00 || k_srv )
transcript   = UTF-8( "HSv2 pair" ‖ "\0" ‖ pairing_id ‖ "\0" ‖ pk_c ‖ "\0" ‖ k_dev_pub ‖ "\0" ‖ k_biosig_pub
                      ‖ "\0" ‖ label ‖ "\0" ‖ model ‖ "\0" ‖ app_version )
               (alle velden als de strings die in het claim-request staan; geen enkel veld bevat "\0")
mac_srv      = HMAC-SHA256(k_srv, transcript)      mac_web = HMAC-SHA256(k_web, transcript)
sas          = ( uint32_be( SHA-256( UTF-8("HSv2 pair sas") || 0x00 || transcript )[0..4] ) mod 10^6 ),
               6 cijfers met voorloopnullen
sig_biosig   = ECDSA-P256-SHA256 (DER) met K_biosig over transcript
```
Coderingen: `pk_c` = b64u van 32 B X25519; `k_dev_pub`/`k_biosig_pub` = b64u van X.509 SubjectPublicKeyInfo (DER,
EC P-256); certificaatketens = lijst b64u-DER, leaf eerst; MAC's en handtekening b64u.

### 13.2 Telefoonsleutels (app)

| Sleutel | Type | Eigenschappen |
|---|---|---|
| K_dev | EC P-256 sign | geen UV, `setUnlockedDeviceRequired(true)`, attestation met `att_challenge`, StrongBox eerst |
| K_biosig | EC P-256 sign | `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`, `setInvalidatedByBiometricEnrollment(true)`, attestation met `att_challenge`, StrongBox eerst |
| K_wrap | AES-256-GCM | zelfde UV-eisen als K_biosig, `setUnlockedDeviceRequired(true)`; wikkelt `sk_c` (32 B random X25519) |

Alleen `BiometricPrompt` met `CryptoObject` en `BIOMETRIC_STRONG`; nooit `DEVICE_CREDENTIAL`. Koppelen kost twee
aanrakingen (wikkelen `sk_c`, ondertekenen transcript). `KeyPermanentlyInvalidatedException` → alles lokaal wissen,
scherm "Opnieuw koppelen".

### 13.3 Flow

1. **Web** (vault open, CK in RAM): `POST /devices/pairings` (SU) `{vault_id, k_srv}` → `{pairing_id, expires_at}`;
   toont QR. Eén open koppeling per gebruiker (nieuwe = oude `cancelled`), max 10 per uur → 429.
2. **App**: QR scannen → `canAuthenticate(BIOMETRIC_STRONG) == SUCCESS` (anders blokkerend scherm) → sleutels
   maken → `sk_c` wikkelen (vinger 1) → transcript ondertekenen (vinger 2) → `POST /devices/pairings/{id}/claim`.
   Antwoord `{device_id, sas}`; app toont de SAS en "Vergelijk met je laptop".
3. **Web** pollt `GET /devices/pairings/{id}` (S, 1 s) tot `claimed`; controleert `mac_web` (fout → afbreken,
   `DELETE`, melding "Koppeling vertrouwd niet — mogelijk gemanipuleerd"); rekent de SAS; toont hem met
   "Klopt" / "Klopt niet".
4. **Klopt** → web `Seal_v2(pk_c, CK, "store", vault_id, key_id)` (terug-openen kan niet zonder `sk_c`; alleen vormcontrole) → `POST /devices/pairings/{id}/confirm {sealed}`. **Klopt niet** → `DELETE`.
5. **App** pollt `GET /device/v1/status` (D, 2 s, max 10 min) tot `active` → "Gekoppeld".
6. **App** (optioneel, veldtest fase A): "Proef: kopie openen" → `GET /device/v1/keys/{kid}/sealed` → vinger →
   `sk_c` → Seal_v2 openen (AAD met eigen vault_id/key_id) → alleen vormcontrole `{ph,kh}`, buffers wissen,
   "Kopie klopt". Niets van de inhoud wordt getoond of bewaard.

### 13.4 Endpoints (onder `/HorseSafe/api`)

| Methode en pad | Auth | Kern |
|---|---|---|
| `POST /devices/pairings` | SU | body `{vault_id, k_srv:b64u 43}`; vault van gebruiker anders 404; 201 `{pairing_id, expires_at}` (TTL 300 s) |
| `GET /devices/pairings/{id}` | S | eigenaar anders 404; `{status, expires_at, claim?:{device_id, key_id, pk_c, k_dev_pub, k_biosig_pub, label, model, app_version, mac_web, security_level, strongbox}}` |
| `DELETE /devices/pairings/{id}` | S | `pending|claimed` → `cancelled`; claimed-device wordt verwijderd; 204 |
| `POST /devices/pairings/{id}/claim` | publiek (mac) | rate-limit per IP 10/10 min; zie 13.5; 201 `{device_id, sas}` |
| `POST /devices/pairings/{id}/confirm` | S | eigenaar, status `claimed`, binnen 600 s na start; `{sealed}` → `validate_sealed(sealed, key_id)`; één transactie: device `confirmed_at`, `vault_keys` (kind `phone`, `device_id`, `public_key = pk_c`, label = toestellabel) → 201 sleutelobject (12.6.3, met `device`) |
| `GET /devices` | S | eigen toestellen, zonder ketens |
| `DELETE /devices/{id}` | S | `revoked_at = nu`, bijbehorende `vault_keys`-rijen verwijderd (geen verzegelde kopie laten liggen); 204; audit + mail |
| `GET /device/v1/status` | D | `{device_id, state: "pending"|"active"|"revoked", keys:[{key_id, vault_id, label}]}` (`revoked` → 200 met lege keys, zodat de app lokaal kan wissen) |
| `GET /device/v1/keys/{kid}/sealed` | D | sleutel hoort bij dit toestel en is `active` → `{key_id, vault_id, sealed}`; anders 404 |

`GET /vault/{vid}/keys` toont phone-sleutels met `device: {id, label, model}`.
`POST /vault/{vid}/keys/{kid}/unlock` met een phone-sleutel blijft 404 (ontgrendelen = Montgomery).

### 13.5 Claim-controles (volgorde; eerste fout wint; niets geschreven vóór stap 8)

1. Pydantic: `pk_c` 43 b64u; `k_*_pub` ≤ 200 b64u; ketens 2-6 certificaten van ≤ 4096 b64u; `label` 1-64,
   `model` ≤ 64, `app_version` ≤ 32, zonder `\0`/stuurtekens; MAC's 43 b64u; `sig_biosig` ≤ 120 b64u.
2. Koppeling bestaat, `pending`, niet verlopen → anders 404 `pairing_not_found` (geen onderscheid).
3. `mac_srv` timing-safe gelijk → anders 400 `pairing_mac_invalid` (koppeling blijft `pending`; na 3 fouten `cancelled`).
4. Ketens beide: geldige handtekeningen, root in de gevendorde Google-roots (`backend/data/android_attestation_roots.pem`),
   geen certificaat in de revocatielijst (`https://android.googleapis.com/attestation/status`, 24 u cache op schijf;
   niet ophaalbaar en geen cache → 503 `attestation_status_unavailable`); leaf-publieke sleutel == `k_*_pub`.
5. Key-description-extensie (OID 1.3.6.1.4.1.11129.2.1.17) van beide leafs: `attestationChallenge == att_challenge`;
   `attestationSecurityLevel` en `keyMintSecurityLevel` ∈ {TrustedEnvironment, StrongBox}; RootOfTrust
   `verifiedBootState == Verified` en `deviceLocked == true`; `attestationApplicationId`: package
   `nl.icthorse.horsesafe` en signature-digest in `android_allowed_signers` (standaard alleen `fbd6b151…062e`).
   K_biosig: `userAuthType` bevat biometrie (2), geen `noAuthRequired`, geen `authTimeout` (per-use).
   K_dev: `unlockedDeviceRequired` aanwezig. → anders 400 `attestation_invalid` met `reason` (vaste codes).
6. `sig_biosig` geldig met `k_biosig_pub` over het transcript → anders 400 `signature_invalid`.
7. Aantal actieve toestellen per gebruiker ≤ 5 → 409 `too_many_devices`.
8. Eén transactie: koppeling → `claimed`, `devices`-rij (zonder `confirmed_at`), claim-JSON + nieuw `key_id`
   opgeslagen; audit `device_pairing_claim`.

Mislukt 3-7: audit `device_pairing_rejected {pairing_id, reason}`. Testvlag `test_device_attestation` (alleen tests)
staat software-attestation, package `nl.icthorse.horsesafe.debug` en willekeurige signer toe; `create_app()` weigert
die vlag met de productie-rpId (zelfde patroon als `test_attestation`). `/health` toont `test_device_attestation`.

### 13.6 Device-handtekening (D)

Headers: `X-HS-Device: <device_id>`, `X-HS-Ts: <unix s>`, `X-HS-Nonce: <b64u 16 B>`, `X-HS-Sig: <b64u DER>`.
Getekend met K_dev: `UTF-8("HSv2 dev" ‖ "\0" ‖ METHOD ‖ "\0" ‖ PATH ‖ "\0" ‖ ts ‖ "\0" ‖ nonce ‖ "\0" ‖ b64u(SHA-256(body)))`,
PATH = pad vanaf `/api` inclusief querystring (bv. `/api/device/v1/status`). Controles: toestel bestaat en is niet
`revoked` (uitzondering: `/device/v1/status`), `|nu − ts| ≤ 60`, nonce nog niet gezien (tabel `device_nonces`,
opruimen na 120 s), handtekening geldig → anders 401 `device_auth_failed` (geen detail). Succes: `last_seen_at = nu`.

### 13.7 Migratie 006

```sql
ALTER TABLE devices ADD COLUMN confirmed_at INTEGER;
CREATE TABLE pairings (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE, k_srv TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','claimed','confirmed','cancelled')),
  mac_failures INTEGER NOT NULL DEFAULT 0, device_id TEXT REFERENCES devices(id) ON DELETE CASCADE,
  key_id TEXT, claim_json TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  claimed_at INTEGER, confirmed_at INTEGER);
CREATE INDEX idx_pairings_user ON pairings(user_id, created_at);
CREATE TABLE device_nonces (device_id TEXT NOT NULL, nonce TEXT NOT NULL, created_at INTEGER NOT NULL,
  PRIMARY KEY (device_id, nonce));
INSERT OR REPLACE INTO schema_version (version) VALUES (6);
```
`k_srv` wordt bij `confirmed`/`cancelled` gewist (`''`).

### 13.8 Audit en mail

Audit: `device_pairing_start`, `device_pairing_claim`, `device_pairing_confirm`, `device_pairing_cancel`,
`device_pairing_rejected {reason}`, `device_revoke`. Nooit `s`, `k_srv`, MAC's, sealed of ketens in audit.
Mail (niet-blokkerend): "Nieuw toestel gekoppeld" bij confirm, "Toestel verwijderd" bij revoke.

### 13.9 App-netwerk

`INTERNET`; network-security-config: alleen `icthorsecloud.nl`, `cleartextTrafficPermitted=false`, pin-set op
ISRG Root X1 + X2 (SPKI-SHA-256), vervaldatum pins 2028-12-31. Geen FCM. Basis-URL vast in BuildConfig.
De PIN-schermen van deel 1 blijven zonder netwerkcode (bronbeleidstest: `yubikey/`, `pin/`, `flow/` importeren niets uit `net/`).

### 13.10 Minimale tests

- pytest: vectoren pair_v1; flow happy path met test-attestation; elke claim-fout uit 13.5 (incl. echte
  attestation-fixtures: een vastgelegde echte keten mag, anders zelfgemaakte keten met eigen root in de test);
  mac-fouten → cancelled na 3; verlopen; dubbele claim; confirm door andere gebruiker 404; device-handtekening
  (verkeerde sig, oude ts, hergebruikte nonce, revoked); revoke verwijdert vault_keys; prod-guard testvlag.
- `node --test`: pair_v1-vectoren (k_srv, k_web, mac_web, sas).
- JVM: pair_v1- en seal_v2-vectoren (incl. openen), transcript-codering, bronbeleid (geen `DEVICE_CREDENTIAL`, geen `net/`-import in PIN-code).
- Playwright: koppelflow met neptoestel (Python-helper die als app claimt met testvlag).
