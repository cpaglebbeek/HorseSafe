# M12 — Over

**App:** HorseSafe Android (`android/`), sinds v0.3.0-Miller deel 1
**Bevat geheim:** —
**Doel:** Herkomst en vertrouwen controleerbaar maken.

## Key-messages
- Versie (en "debug-build" bij debug).
- SHA-256 van `yubico_fido_roots.pem` en `aaguids.json`.
- Signer-digest van het APK (verwacht `32491e0f…3f17`).
- Licenties: yubikit-android 3.0.1 (Apache-2.0, NOTICE), overige AndroidX/Kotlin.

## CTA's
- Terug.

## Flows
- M0 → M12 → M0

## Bron
- `UI_DESIGN.md` §Android-app; `docs/HARDWARE_KEYS.md` §4.1
- `android/app/src/main/java/nl/icthorse/horsesafe/ui/` (`Navigation.kt`, `screens/`, `Texts.kt`)
