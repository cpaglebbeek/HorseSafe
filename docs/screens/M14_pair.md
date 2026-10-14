# M14 — Telefoon koppelen

**App:** HorseSafe Android (`android/`), sinds v0.3.4-Miller deel 2
**Bevat geheim:** — (FLAG_SECURE wel; geen PIN, dus niet geblokkeerd door de omgevingsbewaking van M4-M8)
**Doel:** Uitleg en start van het koppelen van deze telefoon aan het HorseSafe-account (HARDWARE_KEYS §13.3 stap 2).

## Key-messages
- Na koppelen opent de telefoon een verzegelde kopie van het ontgrendelmateriaal, alleen met de vingerafdruk;
  een toestel-PIN of patroon telt nooit (E2).
- Vier stappen: op de laptop "Telefoon koppelen" (QR), scannen, twee keer de vinger, 6 cijfers vergelijken.
- Koppelen gebruikt internet, alleen naar de HorseSafe-server; YubiKey-functies blijven zonder netwerk.
- Tijdens het werk ("Sleutels maken…"): je legt zo twee keer je vinger op de sensor; annuleren laat niets achter.
- Al gekoppeld: rood blok "Deze telefoon is al gekoppeld" — vervangen wist de koppeling en de sleutels op de
  telefoon; het oude toestel verwijder je in HorseSafe op de laptop.
- Foutmeldingen (rood blok): geen camera-toestemming, QR verlopen/gebruikt (`pairing_not_found`), MAC fout,
  attestation afgekeurd (met reden), intrekkingslijst niet bereikbaar, te veel toestellen, server-SAS wijkt af,
  vinger geannuleerd of te veel pogingen, geen verbinding.

## CTA's
- Primair: "QR-code scannen" (vraagt pas dan CAMERA), of "Ja, koppeling vervangen".
- Secundair: "Terug" / "Nee, terug"; tijdens het werk "Afbreken".

## Flows
- M0 "Telefoon koppelen" → M14 (geen koppeling, sterke vinger aanwezig) → M15
- M0 → M18 (geen BIOMETRIC_STRONG), → M16 (koppeling `pending`), → M17 (koppeling `active`)
- M15 geldige QR → M14 (bezig: sleutels, vinger 1 wikkelen, vinger 2 ondertekenen, claim) → M16
- Fout → M14 met rood blok; vingerafdruk gewijzigd → M19

## Bron
- `android/app/src/main/java/nl/icthorse/horsesafe/ui/screens/PairingScreens.kt`, `ui/PairingViewModel.kt`, `ui/Texts.kt`
- `pairing/PairingFlow.kt`; `docs/HARDWARE_KEYS.md` §13.2, §13.3
