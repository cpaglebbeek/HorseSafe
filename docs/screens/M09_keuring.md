# M9 — Keuring

**App:** HorseSafe Android (`android/`), sinds v0.3.0-Miller deel 1
**Bevat geheim:** —
**Doel:** Uitkomst van een keuring met vergelijking met de vorige basis.

## Key-messages
- Eisen groen/oranje/rood; attestation (bij keuren met PIN).
- Vergelijking met het vorige rapport uit het verleden (eigen app-sleutel eerst): elk verschil rood, andere sleutel (serial-HMAC) = STOP `KEY_SWAPPED`, geen basis = oranje.

## CTA's
- Exporteren; Afsluiten.

## Flows
- M2 / M8 → M10

## Bron
- `UI_DESIGN.md` §Android-app; `docs/HARDWARE_KEYS.md` §4.1
- `android/app/src/main/java/nl/icthorse/horsesafe/ui/` (`Navigation.kt`, `screens/`, `Texts.kt`)
