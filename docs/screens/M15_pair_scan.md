# M15 — QR-code scannen

**App:** HorseSafe Android (`android/`), sinds v0.3.4-Miller deel 2
**Bevat geheim:** de QR bevat het koppelgeheim `s` (16 B); het wordt niet getoond, niet bewaard en na het afleiden van k_srv/k_web gewist
**Doel:** De koppel-QR `hs1p:<pairing_id>.<b64u(s)>` van de laptop lezen (§13.1).

## Key-messages
- "Richt de camera op de QR-code op het scherm van de laptop."
- Andere QR-code: "Dit is geen koppelcode van HorseSafe." (strikte parser: voorvoegsel, UUID in kleine
  letters, 22 tekens canonieke base64url).
- De code is 5 minuten geldig en werkt één keer; er wordt geen foto bewaard.

## Componenten
- Camerabeeld via zxing-android-embedded `BarcodeView` (alleen QR, zonder GMS) als view in MainActivity,
  met TextureView: blijft onder FLAG_SECURE. De zxing-`CaptureActivity` is uit het manifest verwijderd.
- Camera loopt alleen zolang M15 in beeld is; bij onStop van de activity terug naar M14.

## CTA's
- "Afbreken" (en Terug) → M14.

## Flows
- M14 → (CAMERA-toestemming) → M15 → geldige QR → M14 bezig → M16
- Geen toestemming → M14 met melding.

## Bron
- `pairing/QrScanner.kt`, `pairing/PairingQr.kt`, `ui/screens/PairingScreens.kt`
