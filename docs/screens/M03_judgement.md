# M3 — Oordeel

**App:** HorseSafe Android (`android/`), sinds v0.3.0-Miller deel 1
**Bevat geheim:** —
**Doel:** Laten zien wat de sleutel is en of hij aan de eisen voldoet.

## Key-messages
- Sleuteltype (AAGUID-beschrijving), firmware (Management), vormfactor.
- Per eis groen/oranje/rood: FIDO_2_1, setMinPINLength, authnrCfg, alwaysUv, maxPINLength (afwezig = STOP), firmware-grens per klasse, clientPin, bioEnroll, PIN- en vingerpogingen.
- Hervatten: lijst "nog te doen".
- Noodsleutel: oranje melding dat de PIN anders moet zijn dan die van de hoofdsleutel (restrisico R20).

## CTA's
- Primair: "Verder: PIN maken" (nieuw) of "Verder: PIN van papier invoeren" (hervatten); uit bij een geblokkeerde omgeving.

## Flows
- M2 → M4 (nieuw) / M8 (hervatten) / M11 (STOP)

## Bron
- `UI_DESIGN.md` §Android-app; `docs/HARDWARE_KEYS.md` §4.1
- `android/app/src/main/java/nl/icthorse/horsesafe/ui/` (`Navigation.kt`, `screens/`, `Texts.kt`)
