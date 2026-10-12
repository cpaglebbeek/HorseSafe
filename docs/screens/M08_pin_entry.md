# M8 — PIN invoeren

**App:** HorseSafe Android (`android/`), sinds v0.3.0-Miller deel 1
**Bevat geheim:** ja
**Doel:** PIN van papier invoeren voor hervatten, keuren met PIN, PIN wijzigen, vingers beheren en oefenen.

## Key-messages
- Per groep 7 tekens + het controleteken; een fout controleteken geeft "groep N klopt niet, controleer het papier" en kost geen poging.
- Banner "PIN-pogingen x/8"; bij ≤ 3 is "PIN gebruiken" geblokkeerd.
- PIN wijzigen: eerst de HUIDIGE PIN van het oude papier.
- Oefenen: niets opgeslagen; optioneel één echte controle (CM-token), daarna alleen Afsluiten.

## CTA's
- Primair: "PIN gebruiken" / "PIN bevestigen" / "Opnieuw oefenen"; na de echte controle alleen "Afsluiten".

## Flows
- M3 / M0 → vervolgstap / M9 / M11

## Bron
- `UI_DESIGN.md` §Android-app; `docs/HARDWARE_KEYS.md` §4.1
- `android/app/src/main/java/nl/icthorse/horsesafe/ui/` (`Navigation.kt`, `screens/`, `Texts.kt`)
