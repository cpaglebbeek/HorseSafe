# S17 — Telefoon koppelen

**Route:** `/HorseSafe/vault.html` → "🔑 Sleutels" (S14) → "📱 Telefoon koppelen" (paneel `#pair-section`)
**Auth-eis:** JWT+MFA en een geopende kluis (ontgrendelmateriaal in tab-RAM); starten vraagt S15 (step-up, `POST /devices/pairings` is SU)
**Doel:** de HorseSafe-app op de telefoon veilig koppelen; de telefoon krijgt een verzegelde kopie die alleen hij met de vingerafdruk kan openen
**Doelgroep:** eigenaar van de kluis, laptop en telefoon naast elkaar
**Sinds:** v0.3.4-Miller (deel 2)

## Key-messages
- "Open de HorseSafe-app op je telefoon, kies **Koppelen** en scan deze QR-code. De app vraagt twee keer om je vingerafdruk."
- "Nog 4:59 geldig. Laat niemand anders deze code scannen."
- "Staat op je telefoon **precies dezelfde code**?"
- Bij een verkeerde `mac_web`: **"Koppeling niet vertrouwd — mogelijk gemanipuleerd."** (er is niets verzegeld)

## CTA's
- Start: "📱 Telefoon koppelen" (`#phone-pair`)
- SAS-stap: primair "✓ Klopt" (`#pair-sas-ok`, krijgt focus), "✗ Klopt niet" (`#pair-sas-bad`, rood)
- Altijd: "Annuleren" (`#pair-cancel`); na afloop heet die knop "Sluiten"
- In de sleutellijst (S14), per telefoon: "Toestel verwijderen" (`data-device`) met bevestiging

## Componenten
- `#pair-step-qr` — `#pair-qr` (SVG uit `vendor/qrcode`, `role="img"`, max. 280 px, witte stille zone) + `#pair-countdown` (m:ss)
- `#pair-step-sas` — `#pair-sas` (6 cijfers als "267 364", monospace, 2,25–3,5 rem; `aria-label` met losse cijfers), toestel/model/app-versie (`#pair-device-label`, `#pair-device-model`, `#pair-device-app`)
- `#pair-status` — `role="status"`, `aria-live="polite"`; de aftelling meldt zich alleen per minuut
- `#pair-error` — `role="alert"`

## Toestanden
| Toestand | Wat de gebruiker ziet | API |
|---|---|---|
| Voorbereiden | "Koppeling voorbereiden…"; bij 403 eerst S15 | `POST /devices/pairings {vault_id, k_srv}` |
| Wachten | QR + aftelling 5:00 → 0:00, "Wachten op je telefoon…" | `GET /devices/pairings/{id}` elke seconde |
| Niet vertrouwd | QR weg, rode melding "Koppeling niet vertrouwd — mogelijk gemanipuleerd" | `DELETE /devices/pairings/{id}` |
| Vergelijken | SAS groot + toestel, "Klopt" / "Klopt niet" | — |
| Klopt | "Bezig met koppelen…" → "✓ Telefoon "…" gekoppeld", lijst ververst | Seal_v2 + `POST /devices/pairings/{id}/confirm {sealed}` |
| Klopt niet | "Je gaf aan dat de code niet klopt. De koppeling is geannuleerd en er is niets verzegeld." | `DELETE /devices/pairings/{id}` |
| Verlopen | "De QR-code is verlopen. Begin opnieuw." | `DELETE /devices/pairings/{id}` |
| Annuleren / kluis vergrendeld / tab dicht | "Koppeling geannuleerd." / paneel dicht | `DELETE /devices/pairings/{id}` (tab dicht: best effort, keepalive) |
| Elders nieuwe koppeling gestart, verlopen of opgeruimd (GET → 404) | "Deze koppeling bestaat niet meer (verlopen of geannuleerd). Begin opnieuw." | — |
| `key_id` van de server staat al in de sleutellijst of is al vastgelegd | "Koppeling niet vertrouwd — de server gaf een sleutelnummer op dat al bij je kluis hoort …" (vóór verzegelen/vastleggen) | `DELETE /devices/pairings/{id}` |

## Regels
- Het geheim `s` (16 B) maakt de browser; de server krijgt alleen `k_srv`. `k_web` blijft in de tab en controleert `mac_web` (timing-safe via WebCrypto HMAC-verify). `s` en `k_web` worden na afloop gewist; de QR staat niet meer in beeld zodra er een claim is.
- Het `pairing_id` in het transcript is altijd het eigen id van deze sessie, nooit een waarde uit de claim.
- Vóór de confirm wordt de telefoonsleutel (`pk_c`) in de versleutelde kluis vastgelegd (R15), zodat "Bijwerken" en wachtwoord wijzigen (S16) ook de telefoon bijwerken.
- Smalle schermen (≥ 320 px): QR schaalt mee, SAS breekt niet af, knoppen minimaal 44 px hoog en onder 480 px elk over de volle breedte.

## Flows (in → uit)
- Vorige scherm: S14 (via S15)
- Volgende scherm: S14 met de nieuwe telefoonrij (succes) / S17 met melding (fout, opnieuw starten)
- Op de telefoon: app-scherm "Vergelijk met je laptop" → "Gekoppeld" (`docs/HARDWARE_KEYS.md` §13.3 stap 2 en 5)

## Bron
- `UI_DESIGN.md` § S17 · `docs/HARDWARE_KEYS.md` §13 (§13.1 afleidingen, §13.3 flow, §13.4 endpoints) en §12.5 (Seal_v2)
- `frontend/vault.html` · `frontend/js/pairing.js` · `frontend/js/pairing-ui.js` · `frontend/js/hwkeys-ui.js`
- Tests: `frontend/tests/unit/pairing.test.mjs` (vectoren `specs/testvectors/pair_v1.json`) · `frontend/tests/pairing.spec.ts`
