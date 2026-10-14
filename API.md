# API.md — HorseSafe REST-API

> Versie: v0.2.0-Koblitz (in bouw). Basis-endpoints sinds v0.0.x; hardware-sleutels, step-up en noodsleutel nieuw in v0.2.0.
> Conform `ARCHITECTURE.md §2.3`, `PRINCIPLES.md` en — voor alles rond hardware-sleutels — het bindende contract `docs/HARDWARE_KEYS.md` §12. Bij verschil wint §12.

## Basis-URL

- **Productie:** `https://icthorsecloud.nl/HorseSafe/api/` (nginx strip het voorvoegsel; FastAPI ziet de paden hieronder)
- **Publiek:** `https://icthorse.nl/HorseSafe/` is een 302 naar icthorsecloud.nl. Hardware-sleutels werken **alleen** op icthorsecloud.nl (WebAuthn-rpId).
- **Dev:** `http://localhost:3997`

## Authenticatie

- **JWT cookie** (HttpOnly, Secure, SameSite=Strict)
- Cookie-naam: `horsesafe_session`
- TTL: 12u sliding window
- Header voor write-acties: `If-Match: <etag>` (optimistic lock)
- **Afkortingen** in de Koblitz-endpoints: **S** = JWT met `mfa=true`; **SU** = S plus geldige step-up (`stepup_until >= nu`, zie `POST /auth/stepup`).
- Zonder cookie 401 `not_authenticated`; ongeldig 401 `invalid_token`; `mfa=false` 403 `mfa_required`.

## Foutmodel

Zoals de code het doet (`HTTPException(detail={...})`):

```json
{ "detail": { "error": "<machine-code>", "...": "extra velden zoals current_etag, state, release_at" } }
```

De frontend leest altijd `body.detail.error`. Pydantic-validatiefouten blijven FastAPI-standaard: **422** met `{"detail": [ ... ]}` (lijst); de frontend behandelt die als `invalid_request`. Binaire velden zijn base64url zonder padding ("b64u"); tijden Unix-seconden.

| HTTP | Betekenis |
|---|---|
| 200 | OK |
| 201 | Created |
| 204 | No content (delete) |
| 400 | Inhoudelijke fout (bv. `invalid_challenge`, `invalid_sealed`, `uv_missing`) |
| 401 | Niet geauthenticeerd |
| 403 | Wel geauthenticeerd maar geen rechten |
| 409 | Conflict (bv. e-mail al in gebruik) |
| 412 | Precondition Failed (etag-mismatch) |
| 413 | Blob te groot |
| 422 | Validatiefout (Pydantic) |
| 423 | Locked (failed-login throttle; noodsleutel niet in venster: `recovery_<state>`) |
| 428 | `If-Match` ontbreekt (`/rekey`) |
| 429 | Rate-limit / te veel challenges / te veel step-up-pogingen |
| 503 | Meldkanaal ontbreekt of melding mislukt (noodsleutel-vrijgave) |

## Endpoints

### Auth

#### `POST /auth/register`
**Body:**
```json
{
  "email": "user@example.com",
  "password": "<account-pw, niet vault-pw>",
  "ack_data_loss": true
}
```
**Response 201:**
```json
{ "user_id": "<uuid>", "email": "user@example.com" }
```
**Errors:** 400 (zwak pw / ontbrekende ack), 409 (e-mail bestaat).

#### `POST /auth/login`
**Body:**
```json
{ "email": "user@example.com", "password": "..." }
```
**Response 200:** zet `horsesafe_session` cookie. Body:
```json
{ "mfa_required": true, "mfa_methods": ["totp", "magic_link"] }
```
**Errors:** 401, 423.

#### `POST /auth/magic-link`
**Body:** `{ "email": "user@example.com" }`
**Response 202:** "Als deze e-mail bestaat, is een link verzonden." (info-leak-resistant)

#### `GET /auth/magic-link/redeem?t=<token>` (compat)
Alleen voor links uit oudere mails: **302** naar `mfa.html#ml=<token>`, zonder bijwerkingen (kijkt niet naar het cookie, verbruikt niets, zet geen cookie). Nieuwe mails linken direct naar `<public_url>/mfa.html#ml=<token>`.

#### `POST /auth/magic-link/redeem`
**Body:** `{ "t": "<token>" }`. Wordt verstuurd door `mfa.html` (same-site `fetch`, `credentials:'include'`).
**Tweede stap, geen login (v0.2.0-Koblitz, reviewronde 2):** vereist een geldig sessie-cookie van **dezelfde** gebruiker (na `POST /auth/login` in deze browser). Dan wordt de link verbruikt en het JWT opgewaardeerd naar `mfa=true` → **200** `{ "ok": true }` + nieuw cookie; de pagina gaat door naar `vault.html`.
Zonder (of met andermans) sessie → **403 `magic_link_login_first`**; de link wordt **niet** verbruikt en er wordt geen cookie gezet (audit `mfa_fail` `{flow:"magic_link"}`); de pagina stuurt door naar `login.html?error=magic_link_login_first`. Ongeldig/verlopen/gebruikt → **400 `invalid_link`**.
**Waarom een POST vanaf de pagina (reviewronde 3):** het sessie-cookie is `SameSite=Strict`. Een klik in webmail is een cross-site navigatie, waarbij de browser dat cookie niet meestuurt; een redeem via de GET uit de mail eindigde daardoor altijd in `magic_link_login_first`. De `fetch` vanaf `mfa.html` is same-site, dus daar gaat het cookie wel mee. Het token staat in het fragment (`#`) en komt zo niet in server-logs of `Referer`; de pagina haalt het meteen uit de adresbalk.

#### `POST /auth/backup-codes/generate` — S
Genereert 10 nieuwe codes (vervangt de oude; plaintext eenmalig in de response). Vereist een sessie **met MFA**: wachtwoord alleen → **403 `mfa_required`** en bestaande codes blijven geldig (v0.2.0-Koblitz, reviewronde 2).

#### `POST /auth/backup-codes/verify`
**Body:** `{ "code": "XXXXX-XXXXX" }`. Eenmalig; upgrade het JWT naar `mfa=true`. Fout → 400 `invalid_code`; throttle → 423.

#### `POST /auth/totp/setup`
**Auth:** JWT (geen MFA vereist nog).
**Response 200:**
```json
{ "secret_base32": "...", "qr_code_url": "otpauth://totp/HorseSafe:user@example.com?secret=...&issuer=HorseSafe" }
```

#### `POST /auth/totp/verify`
**Body:** `{ "code": "123456" }` (challenge) of `{ "secret": "...", "code": "123456" }` (instellen)
**Response 200:** `{ "ok": true, "mfa_passed": true }`; bij instellen wordt TOTP geactiveerd.
Instellen (v0.2.0-Koblitz): bestaat er al TOTP → **409 `totp_already_configured`** (eerst `/auth/totp/disable` met de huidige code); gebruiker met hardware-sleutels en sessie zonder MFA → 403 `mfa_required`. Instellen en uitschakelen: audit `mfa_setup_totp` + mail.

#### `POST /auth/logout`
Wist cookie. 204.

#### `POST /auth/stepup` — S (v0.2.0-Koblitz)
Verse bevestiging voor uitbreidende sleutelacties. Body, één van:
```json
{ "method": "bio", "challenge_id": "<uuid>", "credential_id": "<b64u>", "client_data_json": "<b64u>", "authenticator_data": "<b64u>", "signature": "<b64u>", "user_handle": "<b64u>|null" }
```
```json
{ "method": "totp", "code": "123456" }
```
- `bio`: challenge uit `POST /webauthn/options {purpose:"stepup"}`; credential van een actieve Bio-sleutel van de gebruiker; volledige assertion-controles.
- `totp`: alleen als de gebruiker **geen** actieve Bio-sleutel heeft (anders 403 `stepup_method_not_allowed`); geen TOTP ingesteld → 409 `stepup_unavailable`; binnen 24 u na het verwijderen van een Bio of het instellen van TOTP terwijl er al sleutels waren → 403 `stepup_cooldown` `{retry_at}`; fout → 401 `invalid_code`; > 5 fouten per 15 min → 429 `too_many_attempts`.
**Response 200:** nieuw JWT-cookie met extra claims `stepup_until` (nu + `HORSESAFE_STEPUP_TTL_SECONDS`, standaard 300) en `stepup_method` (bij `bio` ook `stepup_key` = id van de bevestigende sleutel); body `{ "ok": true, "method": "bio", "stepup_until": 1760000300 }`. Een gewone login of `reissue_with_mfa` laat de claims weg.

### Vault

Alle endpoints: vereisen JWT + voltooide MFA in deze sessie.

#### `GET /vault`
**Response 200:**
```json
[ { "id": "<vault-uuid>", "name": "default", "size_bytes": 4096, "etag": "<sha-256>", "updated_at": 1734820000 } ]
```

#### `POST /vault`
**Body:** multipart upload van lege of bestaande KDBX4-blob + `name` field.
**Response 201:** zoals GET-row.

#### `GET /vault/{id}`
**Response 200:** body = pure KDBX4-bytes. Header `ETag: <sha-256>`. Content-Type: `application/octet-stream`.

#### `PUT /vault/{id}`
**Header:** `If-Match: <oude-etag>` verplicht.
**Body:** nieuwe KDBX4-blob.
**Response 200:** zoals GET-row; nieuwe etag in de body én in header `ETag` (de header ontbrak tot v0.2.0-Koblitz, waardoor de tweede save op rij zonder `If-Match` ging → 422).
**Error 412:** `{"error":"etag_mismatch","current_etag":"<server-etag>"}`.
Atomair (reviewronde 3): etag-controle, meta-update (`WHERE etag = ?`) en blob schrijven gebeuren onder één `BEGIN IMMEDIATE`, net als `/rekey`. Een save die tegelijk met een rekey loopt, wacht dus en krijgt dan 412 in plaats van de gerekeyde blob te overschrijven.

#### `DELETE /vault/{id}`
**Response 204.** Blob wordt veilig overgeschreven (3-pass random) vóór unlink.
De hardware-sleutels van de kluis verdwijnen mee (FK `ON DELETE CASCADE`). Ze tellen als verwijderd (v0.2.0-Koblitz, reviewronde 3): audit `vault_delete` `{vault_id, keys}` plus per sleutel `vault_key_delete` `{vault_id, key_id, kind, via:"vault_delete"}`, en één mail "sleutel verwijderd". Zat er een Bio bij, dan start daarmee de TOTP-step-up-afkoelperiode (403 `stepup_cooldown`, R6).

#### `POST /vault/{id}/audit-export`
**Body:** `{ "format": "csv|json|xlsx|kdbx", "reason": "<verplicht voor plaintext>" }`
**Response 200:** `{ "audit_id": "<uuid>", "allowed": true }`. Frontend voert daarna de export client-side uit.

### Admin

Alle endpoints: vereisen JWT met claim `is_admin: true` + voltooide MFA.

#### `GET /admin/users`
Lijst van alle users met counts.

#### `POST /admin/users`
Body: `{ email, is_admin, magic_link_only }`. Server stuurt invite-magic-link.

#### `DELETE /admin/users/{id}`
Cascading delete: vaults + audit-log-anonimisatie. Hard-delete na 30 dagen.

#### `GET /admin/stats`
```json
{
  "users_total": 12,
  "vaults_total": 12,
  "storage_bytes": 524288,
  "logins_24h": 45,
  "failed_logins_24h": 3
}
```

#### `GET /admin/audit?user=&event=&from=&to=`
Audit-log met filters.

### WebAuthn en hardware-sleutels (v0.2.0-Koblitz)

Volledige request/response-schema's, controlevolgorde en foutcodes: `docs/HARDWARE_KEYS.md` §12.4-§12.8. Hieronder het overzicht.

| Methode | Pad | Auth | Doel | Succes |
|---|---|---|---|---|
| POST | `/webauthn/options` | S | Opties + challenge voor `register`, `unlock` of `stepup` | 200 |
| GET | `/vault/{vid}/keys` | S | Sleutellijst van de vault | 200 |
| POST | `/vault/{vid}/keys` | S, of SU als de gebruiker al een sleutel heeft | YubiKey koppelen (attestation + assertion + `public_key` + `sealed`) | 201 |
| POST | `/vault/{vid}/keys/{kid}/unlock` | S + assertion | Verzegelde kopie ophalen na server-geverifieerde assertion | 200 |
| PUT | `/vault/{vid}/keys/sealed` | SU | Alle kopieën opnieuw verzegelen (na wijziging in KeePassXC) | 200 |
| PUT | `/vault/{vid}/rekey` | SU + `If-Match` | Nieuwe blob + nieuwe kopie per sleutel, atomair (multipart) | 200 + `ETag` |
| POST | `/vault/{vid}/keys/{kid}/release` | S | Vrijgave noodsleutel aanvragen (24 uur wachttijd) | 200 |
| DELETE | `/vault/{vid}/keys/{kid}/release` | S | Vrijgave annuleren | 200 |
| POST | `/vault/{vid}/keys/{kid}/block` | S | Noodsleutel blokkeren (defensief, geen step-up) | 200 |
| DELETE | `/vault/{vid}/keys/{kid}/block` | SU met `stepup_method="bio"` | Blokkade opheffen | 200 |
| DELETE | `/vault/{vid}/keys/{kid}` | S | Sleutel verwijderen | 204 |

`GET /vault/{vid}/keys/{kid}/sealed` uit de WIP bestaat niet meer (404/405); een kopie komt alleen nog vrij via `…/unlock` met een geldige assertion.

#### `POST /webauthn/options`
```json
{ "purpose": "register" | "unlock" | "stepup", "vault_id": "<uuid>", "kind": "bio" | "recovery" }
```
`vault_id` verplicht bij `register`/`unlock`, verboden bij `stepup`; `kind` alleen en verplicht bij `register`. Max. 10 open challenges per gebruiker (429 `too_many_challenges`).
- `register` → `{key_id, prf_salt, rp, user, create:{challenge_id, challenge}, assert:{challenge_id, challenge}, pub_key_cred_params:[-8,-7], exclude_credentials, authenticator_selection:{cross-platform, resident_key:"discouraged", user_verification:"required"}, attestation:"direct", hints:["security-key"], timeout_ms, expires_at}`. Fouten: 409 `too_many_keys`, 403 `stepup_required`.
- `unlock` → `{challenge_id, challenge, rp_id, user_verification, hints, timeout_ms, expires_at, allow_credentials:[{key_id, kind, credential_id, prf_salt}]}`: actieve Bio-sleutels plus noodsleutels in status `released`. Leeg → 409 `no_usable_keys`.
- `stepup` → idem zonder `prf_salt`, over alle actieve Bio-sleutels van de gebruiker. Leeg → 409 `no_bio_keys` (client valt terug op TOTP).

#### Sleutelobject (response van lijst-items, koppelen, release, cancel, block, unblock)
```json
{
  "id": "<uuid>", "kind": "bio" | "recovery" | "phone", "label": "…", "status": "active" | "blocked",
  "credential_id": "<b64u>", "prf_salt": "<b64u 32>", "public_key": "<b64u 32>",
  "aaguid": "<uuid>", "authenticator": "YubiKey Bio Series - FIDO Edition" | null,
  "created_at": 0, "updated_at": 0, "last_used_at": null,
  "recovery": null | { "state": "idle|waiting|released|consumed|expired|blocked",
                       "release_requested_at": null, "release_at": null, "release_until": null,
                       "release_consumed_at": null, "blocked_at": null, "blocked_by": null },
  "device": null | { "id": "<uuid>", "label": "…", "model": "…" }        // alleen kind "phone"
}
```
Nooit `sealed`, `cose_public_key` of `sign_count`. `GET /vault/{vid}/keys` geeft `{ "keys": [ … ], "notify_available": true, "stepup_until": null }`.

#### `POST /vault/{vid}/keys` (koppelen)
Body: `key_id`, `kind`, `label` (1-64), `create` {`challenge_id`, `credential_id`, `client_data_json`, `attestation_object`, `transports`?}, `assert` {`challenge_id`, `credential_id`, `client_data_json`, `authenticator_data`, `signature`, `user_handle`}, `public_key` (X25519, 43 tekens b64u), `sealed` (Seal_v2-JSON, `kid` = `key_id`, ≤ 1024 tekens).
Belangrijkste fouten: 400 `invalid_challenge`, `bad_client_data`, `origin_mismatch`, `rp_id_mismatch`, `up_missing`, `uv_missing`, `not_device_bound`, `alg_not_allowed`, `attestation_invalid`, `authenticator_not_allowed`, `not_bio_authenticator`, `credential_mismatch`, `invalid_sealed`; 403 `stepup_required`; 409 `credential_exists`, `too_many_keys`.

#### `POST /vault/{vid}/keys/{kid}/unlock`
Body: `challenge_id`, `credential_id`, `client_data_json`, `authenticator_data`, `signature`, `user_handle`. Response `{ "id": "<key_id>", "sealed": "<Seal_v2>" }`.
Fouten: 400 `invalid_challenge`/`credential_mismatch`/assertion-codes; 409 `sign_count_regression`; 423 `recovery_idle|waiting|consumed|expired|blocked` met `state`, `release_at`, `release_until` (assertion wordt eerst geverifieerd, zodat zonder sleutel geen status af te tasten is).

#### `PUT /vault/{vid}/keys/sealed`
Body `{ "items": [ { "id": "<key_id>", "sealed": "<Seal_v2>" } ] }`, 1-20 unieke items, alles of niets. Response `{ "updated": n }`. Fouten: 403 `stepup_required`; 400 `unknown_key`, `invalid_sealed`.

#### `PUT /vault/{vid}/rekey`
`multipart/form-data` met `blob` (nieuwe KDBX4) en `sealed` (`{"items":[…]}`, exact één item per niet-ingetrokken sleutel, ook geblokkeerde). Header `If-Match` verplicht. Response `{ "vault": { … }, "resealed": n }` + header `ETag`.
Fouten: 403 `stepup_required`; 428 `if_match_required`; 413 `blob_too_large`; 409 `keys_mismatch`; 400 `invalid_sealed`; 412 `etag_mismatch` (+ `current_etag`); 500 `write_failed` (teruggedraaid).
De meldmail gaat ná het antwoord (achtergrondtaak). Krijgt de client geen of een onduidelijk antwoord (netwerk, 5xx/504 zonder code), dan vergelijkt hij `GET /vault` → `etag` met SHA-256 van de verstuurde blob om te bepalen of de rekey is doorgevoerd (`docs/HARDWARE_KEYS.md` §12.6.5).
Client (reviewronde 2): `/keys/sealed` en `/rekey` verzegelen alleen naar publieke sleutels die bij het koppelen in de versleutelde KDBX zijn vastgelegd (pins); de server ziet daar niets van.

#### Noodsleutel: `…/{kid}/release` en `…/{kid}/block`
- `POST …/release`: 400 `not_recovery_key`; 409 `recovery_blocked`; loopt al → 200 ongewijzigd; geen mailer → **503 `notify_unavailable`**; melding mislukt → **503 `notify_failed`** (vrijgave teruggedraaid); anders `release_at = nu + 24 u`.
- `DELETE …/release`: niets lopend → 409 `nothing_to_cancel`.
- `POST …/block`: altijd toegestaan met S; al geblokkeerd → 200 ongewijzigd. Wist een lopende vrijgave.
- `DELETE …/block`: zonder step-up 403 `stepup_required`; step-up met TOTP → 403 `stepup_bio_required`; niet geblokkeerd → 409 `not_blocked`; Bio uit de step-up gekoppeld ná de blokkade → 403 `stepup_key_too_new` (audit `recovery_unblock_rejected`). Vanaf Miller ook toegestaan met telefoonvinger.
- Elke actie: audit + mail (behalve de ongewijzigde 200-gevallen).

### Telefoon koppelen (v0.3.4-Miller deel 2)

Bindend contract: `docs/HARDWARE_KEYS.md` §13. De browser maakt het QR-geheim `s` (16 B) en stuurt alleen `k_srv = HKDF(s, "HSv2 pair srv")`; `k_web` blijft in de browser en controleert `mac_web` zelf. Alle binaire velden b64u.

| Methode | Pad | Auth | Doel | Succes |
|---|---|---|---|---|
| POST | `/devices/pairings` | SU | Koppeling starten `{vault_id, k_srv}` → `{pairing_id, expires_at}` (TTL 300 s) | 201 |
| GET | `/devices/pairings/{id}` | S | `{status, expires_at, claim}`; `claim` bij `claimed`/`confirmed` | 200 |
| DELETE | `/devices/pairings/{id}` | S | Annuleren (`pending`/`claimed`); niet-bevestigd toestel wordt verwijderd | 204 |
| POST | `/devices/pairings/{id}/claim` | publiek (mac) | Claim door de app | 201 `{device_id, sas}` |
| POST | `/devices/pairings/{id}/confirm` | S | `{sealed}` (Seal_v2 naar `pk_c`, `kid` = `key_id`) → phone-sleutel | 201 sleutelobject |
| GET | `/devices` | S | Eigen, niet-ingetrokken toestellen (zonder ketens/sleutels) | 200 `{devices:[…]}` |
| DELETE | `/devices/{id}` | S | Toestel intrekken; zijn phone-sleutels worden verwijderd | 204 |
| GET | `/device/v1/status` | D | `{device_id, state: pending\|active\|revoked, keys:[{key_id, vault_id, label}]}` | 200 |
| GET | `/device/v1/keys/{kid}/sealed` | D | `{key_id, vault_id, sealed}` voor een actieve sleutel van dit toestel, anders 404 | 200 |

**`POST /devices/pairings`** — fouten: 404 `not_found` (vault), 403 `stepup_required`, 429 `too_many_pairings` (> 10 per uur), 409 `too_many_keys` (vroege melding; phone-sleutels tellen mee). Een nieuwe koppeling zet een open koppeling van dezelfde gebruiker op `cancelled`.

**`GET /devices/pairings/{id}`** — `cancelled` of verlopen `pending` → 404 `not_found` (zoals onbekend). Een `claimed` koppeling die 600 s na de start niet bevestigd is, wordt lui opgeruimd (`cancelled`, toestel-rij weg, `k_srv` gewist). `claim` = `{device_id, key_id, pk_c, k_dev_pub, k_biosig_pub, label, model, app_version, mac_web, security_level: "TrustedEnvironment"|"StrongBox", strongbox}`. Nooit `k_srv` of `mac_srv`.

**`DELETE /devices/pairings/{id}`** — al `cancelled` → 204 (geen wijziging); `confirmed` → 409 `pairing_confirmed` (gebruik `DELETE /devices/{id}`).

**`POST /devices/pairings/{id}/claim`** — body:
```json
{ "pk_c": "<b64u 32>", "k_dev_pub": "<b64u SPKI ≤200>", "k_biosig_pub": "<b64u SPKI ≤200>",
  "k_dev_chain": ["<b64u DER, leaf eerst>", "…"], "k_biosig_chain": ["…"],
  "label": "1-64", "model": "0-64", "app_version": "0-32",
  "mac_srv": "<b64u 32>", "mac_web": "<b64u 32>", "sig_biosig": "<b64u DER ≤120>" }
```
Ketens 2-6 certificaten van ≤ 4096 tekens; tekstvelden zonder stuurtekens, Unicode-opmaaktekens (Cf), U+2028/U+2029 en losse surrogaten (anders 422) en niet getrimd (ze gaan letterlijk het transcript in). Controles in volgorde (eerste fout wint): 422 vorm; 404 `pairing_not_found` (onbekend, niet `pending` of verlopen); 400 `pairing_mac_invalid` (na 3 fouten `cancelled`); 400 `attestation_invalid` met `reason`; 503 `attestation_status_unavailable` (revocatielijst niet ophaalbaar en geen cache van hooguit 7 dagen); 400 `signature_invalid`; 409 `too_many_devices` (max. 5 actieve toestellen). Rate-limit 10 per 10 min per IP.

`reason` bij `attestation_invalid`: `chain_invalid`, `root_untrusted`, `revoked`, `key_mismatch`, `key_type`, `extension_missing`, `extension_invalid`, `challenge_mismatch`, `security_level`, `root_of_trust_missing`, `boot_unverified`, `device_unlocked`, `app_id_missing`, `package_mismatch`, `signer_mismatch`, `no_biometric`, `no_auth_required`, `auth_timeout`, `unlocked_device_required_missing`.

**`POST /devices/pairings/{id}/confirm`** — fouten: 404 `not_found`; 409 `pairing_not_claimed`; 409 `pairing_expired` (> 600 s na start); 400 `invalid_sealed`; 409 `too_many_keys`.

**Device-handtekening (D, §13.6)** — headers `X-HS-Device: <device_id>`, `X-HS-Ts: <unix s>`, `X-HS-Nonce: <b64u 16 B>`, `X-HS-Sig: <b64u DER>`; ECDSA-P256-SHA256 met K_dev over `UTF-8("HSv2 dev" ‖ 0 ‖ METHOD ‖ 0 ‖ PATH ‖ 0 ‖ ts ‖ 0 ‖ nonce ‖ 0 ‖ b64u(SHA-256(body)))`, PATH = pad vanaf `/api` incl. querystring (bv. `/api/device/v1/status`). `|nu − ts| ≤ 60`, nonce eenmalig. Elke fout → 401 `device_auth_failed` zonder detail. Een ingetrokken toestel mag alleen `/device/v1/status` (antwoord `revoked`, lege `keys`).

**Sleutelobject voor phone-sleutels** — `kind: "phone"`, `credential_id`/`prf_salt`/`aaguid`/`authenticator` = `null`, plus `device: {id, label, model}` (`null` bij bio/recovery). `POST /vault/{vid}/keys/{kid}/unlock` en de andere `…/keys/{kid}`-routes geven voor een phone-sleutel 404; verwijderen gaat via `DELETE /devices/{id}`. Phone-sleutels tellen mee voor `too_many_keys` en moeten in `PUT …/rekey` en `PUT …/keys/sealed` worden meegenomen.

## Rate-limits

| Endpoint | Limiet |
|---|---|
| `/auth/login` | 5/15min per IP+email |
| `/auth/magic-link` | 3/uur per email, 10/uur per IP |
| `/auth/totp/verify` | 5/15min per account |
| `/vault/{id}` PUT | 60/min per user |
| `/admin/*` | 100/min per admin |
| `/vault/*` (incl. sleutels) | 60/min per IP (middleware) |
| `/webauthn/options` | default 300/min + max. 10 open challenges per gebruiker |
| `/auth/stepup` (TOTP) | max. 5 fouten per 15 min per gebruiker |
| `POST /devices/pairings` | max. 10 per uur per gebruiker (429 `too_many_pairings`) |
| `POST /devices/pairings/{id}/claim` | 10/10min per IP (middleware) |

## OpenAPI

Sinds v0.1.0 staan `/docs`, `/redoc` en `/openapi.json` in productie uit (`HORSESAFE_DOCS_ENABLED=false`, default). In dev/test aan te zetten met `HORSESAFE_DOCS_ENABLED=true`.

## Health

`GET /health` → o.a. `version`, `"test_attestation": <bool>` en (v0.3.4-Miller) `"test_device_attestation": <bool>`. Geen mail- of sleutelinformatie.
