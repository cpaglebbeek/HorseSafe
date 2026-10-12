# M7 — Vingers

**App:** HorseSafe Android (`android/`), sinds v0.3.0-Miller deel 1
**Bevat geheim:** —
**Doel:** Vingers inschrijven (inrichting hoofdsleutel) of beheren.

## Key-messages
- Vinger kiezen; naam automatisch (`R-wijs` …), lengte volgens de sensor.
- Voortgang uit `remaining`, feedback in het Nederlands, testaanraking per vinger.
- Inrichting: 2 of 3 vingers. Beheren: toevoegen, hernoemen (met testaanraking), verwijderen.
- Alleen de hoofdsleutel; op een noodsleutel weigert de app vóór er een PIN-poging gebruikt is.

## CTA's
- Primair: vinger toevoegen / klaar.

## Flows
- bezig → M10 (inrichting) ; M8 → M7 (beheren)

## Bron
- `UI_DESIGN.md` §Android-app; `docs/HARDWARE_KEYS.md` §4.1
- `android/app/src/main/java/nl/icthorse/horsesafe/ui/` (`Navigation.kt`, `screens/`, `Texts.kt`)
