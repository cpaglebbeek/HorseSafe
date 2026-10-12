# M2 — Sleutel aansluiten

**App:** HorseSafe Android (`android/`), sinds v0.3.0-Miller deel 1
**Bevat geheim:** —
**Doel:** Precies één YubiKey verbinden en herkennen.

## Key-messages
- "Steek één YubiKey direct in de USB-C-poort, zonder hub of dock."
- YubiKey 5 NFC: één OTG-adapter USB-A → USB-C.
- Android-dialoog: Toestaan, maar "altijd openen" NIET aanvinken.
- Alleen bij keuren zonder PIN: noodsleutel mag via NFC.
- Status: wacht / gevonden, bezig met herkennen / meer dan één sleutel (rood).

## CTA's
- Annuleren.

## Flows
- M1 → M3 (herkend) / M11 (STOP)

## Bron
- `UI_DESIGN.md` §Android-app; `docs/HARDWARE_KEYS.md` §4.1
- `android/app/src/main/java/nl/icthorse/horsesafe/ui/` (`Navigation.kt`, `screens/`, `Texts.kt`)
