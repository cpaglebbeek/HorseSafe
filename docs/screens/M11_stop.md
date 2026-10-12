# M11 — Stop

**App:** HorseSafe Android (`android/`), sinds v0.3.0-Miller deel 1
**Bevat geheim:** —
**Doel:** Uitleggen waarom de app stopt en wat er al op de sleutel staat.

## Key-messages
- Waarom (Stop-tekst), wat je nu doet (advies), wat al op de sleutel staat (PIN, minimum, alwaysUv, vingers), beoordeling.
- Reset alleen buiten de app (Yubico Authenticator / `ykman`), alleen bij de testsleutel.

## CTA's
- Afsluiten / terug naar start.

## Flows
- elke stap → M11

## Bron
- `UI_DESIGN.md` §Android-app; `docs/HARDWARE_KEYS.md` §4.1
- `android/app/src/main/java/nl/icthorse/horsesafe/ui/` (`Navigation.kt`, `screens/`, `Texts.kt`)
