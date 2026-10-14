# M18 — Vingerafdruk nodig

**App:** HorseSafe Android (`android/`), sinds v0.3.4-Miller deel 2
**Bevat geheim:** —
**Doel:** Blokkerend scherm als `canAuthenticate(BIOMETRIC_STRONG) != BIOMETRIC_SUCCESS` (§13.3 stap 2, E1/E2).

## Key-messages (rood blok, per oorzaak)
- Geen vinger ingesteld: "Stel eerst een vingerafdruk in (Instellingen > Biometrie en beveiliging > Vingerafdrukken)".
- Geen sterke sensor / niet ondersteund: koppelen kan op dit toestel niet.
- Sensor tijdelijk niet beschikbaar; beveiligingsupdate vereist.
- Altijd: "HorseSafe accepteert alleen een sterke vingerafdruk (Android-klasse 3). Gezichtsherkenning, PIN,
  patroon of wachtwoord van het toestel tellen niet."

## CTA's
- Primair: "Opnieuw controleren" (→ M14 als het nu wel kan).
- Secundair: "Terug" → M0.

## Flows
- M0 / M14 / M15 (na een geldige QR, tweede controle) → M18 → M14

## Bron
- `biometric/StrongGate.kt` (`availability`), `ui/Texts.kt` (`bioBlocked`), `ui/screens/PairingScreens.kt`
