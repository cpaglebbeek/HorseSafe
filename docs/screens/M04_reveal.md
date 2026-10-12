# M4 — PIN tonen

**App:** HorseSafe Android (`android/`), sinds v0.3.0-Miller deel 1
**Bevat geheim:** ja
**Doel:** De nieuwe PIN van 63 tekens één keer tonen om over te schrijven.

## Key-messages
- 9 genummerde kaarten: 4 + 3 tekens en een omkaderd controleteken.
- Een kaart toont zijn inhoud alleen zolang je hem ingedrukt houdt; getekend op een Canvas uit de CharArray (geen String, niet in de a11y-boom).
- Geblokkeerd bij venster niet zichtbaar, opname of onveilige omgeving; melding bij een schermafbeelding.

## CTA's
- Primair: verder naar overschrijven-controle. Annuleren (vóór setPin staat er niets op de sleutel; formulier vernietigen).

## Flows
- M3 → M5

## Bron
- `UI_DESIGN.md` §Android-app; `docs/HARDWARE_KEYS.md` §4.1
- `android/app/src/main/java/nl/icthorse/horsesafe/ui/` (`Navigation.kt`, `screens/`, `Texts.kt`)
