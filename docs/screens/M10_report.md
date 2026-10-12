# M10 — Rapport

**App:** HorseSafe Android (`android/`), sinds v0.3.0-Miller deel 1
**Bevat geheim:** —
**Doel:** Rapport zonder geheimen tonen, bewaren, exporteren en importeren.

## Key-messages
- Whitelist-velden (geen PIN, tokens, credentialId, ruw serienummer).
- Zelfgekozen codes (zak, papierlocatie) met het PIN-alfabet, max. 12 tekens.
- Inrichtingsrapport = nieuwe vergelijkingsbasis.
- "Koppel de sleutel daarna op de laptop in Chrome, op scherm S14 van HorseSafe."

## CTA's
- Primair: "Afsluiten" (wist de PIN, beëindigt de app). Secundair: "Exporteren…", "Importeren…" (opslagkiezer).

## Flows
- inrichting / keuring → einde

## Bron
- `UI_DESIGN.md` §Android-app; `docs/HARDWARE_KEYS.md` §4.1
- `android/app/src/main/java/nl/icthorse/horsesafe/ui/` (`Navigation.kt`, `screens/`, `Texts.kt`)
