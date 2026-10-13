# M13 — Sleutel wissen

**App:** HorseSafe Android (`android/`), sinds v0.3.1-Miller
**Bevat geheim:** — (geen PIN; wel geblokkeerd door de omgevingsbewaking, net als de PIN-schermen)
**Doel:** Een al ingerichte, geblokkeerde of afgewezen sleutel volledig wissen (CTAP `authenticatorReset`),
zodat hij opnieuw ingericht kan worden.

## Key-messages
- Rood blok: wissen is onomkeerbaar; daarna werkt de sleutel nergens meer, ook niet in HorseSafe;
  enige gekoppelde sleutel = jezelf buitensluiten.
- Wat er nu op staat (PIN ja/nee, vingers ja/nee, minimum, alwaysUv) en wat verloren gaat
  (alle FIDO-credentials, PIN, vingers, minimum 63, alwaysUv). PIV, OATH en OpenPGP blijven.
- Bevestigen: laatste 4 cijfers van het serienummer overtypen (cijfertoetsen in de app, geen systeemtoetsenbord),
  daarna 3 seconden ingedrukt houden.
- Opnieuw aansluiten: de YubiKey accepteert wissen alleen in de eerste seconden na insteken (USB) of tegen
  de telefoon houden (NFC, alleen YubiKey 5). Bij USB meteen OK tikken op de toestemmingsvraag.
- De app controleert vóór het wissen dat dezelfde sleutel terugkwam (serienummer); anders `RESET_OTHER_KEY`.
- Aanraken: gouden contact (YubiKey 5) of vingerafdruksensor (Bio).
- Na het wissen: nagelezen (geen PIN, geen vingers) en de herinnering de koppeling in HorseSafe (S14) zelf te verwijderen.

## CTA's
- Cijfers 0-9 + Wis; "Houd 3 seconden ingedrukt om te wissen".
- "Stoppen, niets wissen" (tot het wissen loopt).
- Na wissen: "Inrichten als hoofdsleutel (Bio)", "Inrichten als noodsleutel", "Terug naar start".

## Flows
- M0 "Sleutel wissen" → M13 (aansluiten → bevestigen → opnieuw aansluiten → aanraken → gewist) → M1 (inrichten) of M0
- M11 bij `PIN_ALREADY_SET`, `BIO_ALREADY_ENROLLED`, `FORCE_PIN_CHANGE`, `KEY_ALREADY_USED`, `YK5_ALWAYS_UV_PRESET`,
  `PIN_BLOCKED`, `RECOVERY_BIO_HAS_FINGER`, `RESUME_NOT_ALLOWED` (alleen als er in dit proces nog geen PIN was) → M13
- Te laat / niet aangeraakt / los tijdens wissen → terug naar "opnieuw aansluiten" met melding; de bevestiging blijft geldig.
- Geen serienummer leesbaar → `RESET_NO_SERIAL` (wissen buiten de app); na wissen nog PIN of vinger → `RESET_READBACK_FAILED`.

## Bron
- `android/app/src/main/java/nl/icthorse/horsesafe/flow/ResetFlow.kt`, `yubikey/YubikitResetOps.kt` (enige reset-aanroep)
- `ui/screens/ResetScreens.kt`, `ui/HorseSafeViewModel.kt` (F8), `docs/HARDWARE_KEYS.md` §4.1
