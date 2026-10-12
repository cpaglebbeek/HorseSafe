# M0 — Start

**App:** HorseSafe Android (`android/`), sinds v0.3.0-Miller deel 1
**Bevat geheim:** —
**Doel:** Omgevingsoordeel tonen en de taak kiezen.

## Key-messages
- "HorseSafe — YubiKey inrichten en keuren"; versie zichtbaar.
- Omgeving: groen, of per overtreding reden + advies (a11y-dienst, ontwikkelaarsopties/ADB, multi-window, ander display/DeX, schermopname).
- Geen reset in de app.

## CTA's
- Menukaarten: Nieuwe hoofdsleutel (Bio) · Nieuwe noodsleutel (kies YK5 of Bio zonder vinger) · Inrichting hervatten · Keuren zonder PIN · Keuren met PIN · PIN wijzigen · Vingers beheren · Oefenen · Rapporten · Over HorseSafe

## Flows
- — → M1 (inrichten, hervatten, keuren met PIN, PIN wijzigen, vingers) / M2 (keuren zonder PIN) / M8 (oefenen) / M10 (rapporten) / M12

## Bron
- `UI_DESIGN.md` §Android-app; `docs/HARDWARE_KEYS.md` §4.1
- `android/app/src/main/java/nl/icthorse/horsesafe/ui/` (`Navigation.kt`, `screens/`, `Texts.kt`)
