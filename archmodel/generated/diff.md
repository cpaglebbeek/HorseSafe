# HorseSafe — verschil as-is (code) ↔ to-be (ontwerp)

Gegenereerd door ModelArchDSL; niet met de hand bewerken.

| Status | Aantal |
|---|---:|
| Gebouwd | 38 |
| Deels gebouwd | 0 |
| Gepland (to-be) | 7 |
| Alleen in code | 0 |
| Niet traceerbaar | 0 |
| Extern (andere repo) | 9 |
| Ontwerp | 54 |

Feiten uit de code: 94, waarvan 0 niet in het ontwerp.

## Gepland — in het ontwerp, nog niet in de code

- `ac_android` HorseSafe Android-app (v0.3.0-Miller, gepland) — zoekt: module:android*
- `ac_approve` Goedkeuring laptop via telefoon-QR + vinger (v0.4.0-Montgomery, gepland) — zoekt: route:* *approvals*
- `ac_native` Native read-only kluis in de app (v0.5.0-Lange, gepland, niet bouwen vóór veldtest v0.4)
- `ai_deviceapi` Device-API: koppelen, status, sealed, recovery-block, app-update (v0.3.0-Miller, gepland) — zoekt: route:* *pairings*, route:* *device/v1/*, route:* *app/latest
- `do_approvals` Goedkeuringen + ingetrokken sessies (migratie 007, gepland) — zoekt: table:approvals, table:revoked_sessions
- `do_pairings` Koppelingen + device-nonces (migratie 006, gepland) — zoekt: table:pairings, table:device_nonces
- `dv_phone` Telefoon Z Fold6 (Keystore BIOMETRIC_STRONG, v0.3.0-Miller)
