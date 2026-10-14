# M17 — Gekoppeld

**App:** HorseSafe Android (`android/`), sinds v0.3.4-Miller deel 2
**Bevat geheim:** — (de proef opent de kopie kort in het geheugen; niets ervan komt in beeld)
**Doel:** Bevestigen dat de telefoon gekoppeld is, de verzegelde kopieën tonen (label en kluis) en de proef
"Kopie openen" (§13.3 stap 6, veldtest fase A) aanbieden.

## Key-messages
- Groen blok met het toestellabel: "Deze telefoon is gekoppeld." Ontgrendelen op de laptop met de telefoon
  komt in Montgomery (v0.4.0).
- Per sleutel: label, eerste 8 tekens van de kluis-id, knop "Proef: kopie openen".
- Proef: `GET /device/v1/keys/{kid}/sealed` → vinger → sk_c uitpakken (K_wrap) → Seal_v2 openen met de EIGEN
  vault_id/key_id → alleen vormcontrole {ph,kh} → buffers wissen → "Kopie klopt … Er is niets getoond of
  bewaard." Fout: "De kopie ging niet open (unseal_failed)."
- Bij openen van het scherm: sleutels gecontroleerd (gewijzigde vingerafdruk → M19) en status ververst
  (`revoked` → alles lokaal gewist, melding; 401/404 → alleen melding, niets gewist, evt. klokwaarschuwing).
- "Opnieuw koppelen" maakt nieuwe sleutels in de vrije sleutelset; deze koppeling blijft staan tot de nieuwe
  claim geslaagd is.

## CTA's
- "Proef: kopie openen" (per sleutel), "Status verversen", "Opnieuw koppelen (vervangt deze koppeling)" → M14.
- "Terug naar start" → M0.

## Flows
- M16 → M17; M0 → M17 (koppeling `active`); M17 → M19 (vingerafdruk gewijzigd)

## Bron
- `ui/screens/PairingScreens.kt`, `pairing/PairingFlow.kt` (`refresh`, `trialOpen`, `keysValid`), `crypto/Seal.kt`
