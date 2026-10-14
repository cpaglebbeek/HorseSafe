# M19 — Opnieuw koppelen

**App:** HorseSafe Android (`android/`), sinds v0.3.4-Miller deel 2
**Bevat geheim:** —
**Doel:** Melden dat de koppelsleutels ongeldig zijn geworden en alles lokaal gewist is (§13.2:
`KeyPermanentlyInvalidatedException` → alles lokaal wissen, scherm "Opnieuw koppelen").

## Key-messages
- Rood blok: de vingerafdrukken op dit toestel zijn gewijzigd (of de sleutels zijn verdwenen); de
  koppelsleutels zijn ongeldig en alles van de koppeling is van deze telefoon gewist.
- "Verwijder het oude toestel in HorseSafe op de laptop en koppel deze telefoon opnieuw."
  (De app kan het toestel zelf niet intrekken: §13 heeft geen device-eigen revoke-endpoint.)

## CTA's
- Primair: "Opnieuw koppelen" → M14.
- Secundair: "Terug naar start" → M0.

## Flows
- M0/M17 (sleutelcontrole bij openen), M14 (claim), M17 (proef) → M19 → M14

## Bron
- `keystore/AndroidPhoneKeys.kt` (`guard`), `pairing/PairingFlow.kt` (`keysValid`, `wipeLocal`), `ui/screens/PairingScreens.kt`
