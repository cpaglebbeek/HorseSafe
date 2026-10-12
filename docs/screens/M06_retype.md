# M6 — Overtypen

**App:** HorseSafe Android (`android/`), sinds v0.3.0-Miller deel 1
**Bevat geheim:** ja
**Doel:** Bewijzen dat het papier leesbaar is: alle 9 groepen van papier overtypen.

## Key-messages
- Eigen toetsenblok (29 tekens + Wis), geen systeemtoetsenbord, geen klembord.
- Na elke groep alleen "klopt" of "groep N wijkt af", nooit welk teken.
- Knop pas actief bij 9 kloppende groepen.

## CTA's
- Primair: "PIN bevestigen".

## Flows
- M5 → bezig (attestation / setPin / tellen) → M6b

## Bron
- `UI_DESIGN.md` §Android-app; `docs/HARDWARE_KEYS.md` §4.1
- `android/app/src/main/java/nl/icthorse/horsesafe/ui/` (`Navigation.kt`, `screens/`, `Texts.kt`)
