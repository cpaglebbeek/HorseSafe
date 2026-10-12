# M6b — Onomkeerbaar

**App:** HorseSafe Android (`android/`), sinds v0.3.0-Miller deel 1
**Bevat geheim:** —
**Doel:** Expliciete toestemming vóór `setMinPinLength(63)`.

## Key-messages
- Rood kader: "De minimale PIN-lengte 63 kan alleen nog omhoog en is alleen terug te draaien met een reset die alles op de sleutel wist."
- Vinkje: "Ik begrijp dat dit niet terug kan."

## CTA's
- Primair: "Ik begrijp het, vastzetten". Annuleren (PIN staat dan al op de sleutel → later hervatten).

## Flows
- bezig → minimum + alwaysUv → M7 (hoofdsleutel) / M10

## Bron
- `UI_DESIGN.md` §Android-app; `docs/HARDWARE_KEYS.md` §4.1
- `android/app/src/main/java/nl/icthorse/horsesafe/ui/` (`Navigation.kt`, `screens/`, `Texts.kt`)
