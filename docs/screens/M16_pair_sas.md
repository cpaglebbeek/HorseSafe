# M16 — Vergelijk de code

**App:** HorseSafe Android (`android/`), sinds v0.3.4-Miller deel 2
**Bevat geheim:** — (de SAS is een controlecode, geen geheim)
**Doel:** De gebruiker vergelijkt de 6 cijfers op telefoon en laptop (§13.1 `sas`, §13.3 stap 2-5) en wacht tot de
laptop "Klopt" heeft gekozen.

## Key-messages
- Grote code in twee groepen van 3 cijfers (bv. `267 364`). De telefoon rekent de SAS zelf uit het transcript;
  wijkt de SAS van de server af, dan breekt de app de koppeling af (M14 met melding) en toont hij niets.
- "Staan op de laptop dezelfde 6 cijfers? Klik daar op Klopt. Zijn ze anders, klik dan op Klopt niet."
- "Wachten op de laptop… (tot 10 minuten)": `GET /device/v1/status` (device-handtekening) elke 2 s.
- 401/404 (bv. afgewezen, verlopen of net opgeruimd) → melding op M16, er wordt NIETS gewist (§13.3 stap 5); de
  gebruiker kiest "Opnieuw wachten" of "Koppeling op deze telefoon afbreken". Bij 401 met een serverklok die
  > 60 s afwijkt: "De klok van deze telefoon loopt … voor/achter". Na 10 minuten: "Opnieuw wachten".

## CTA's
- "Opnieuw wachten" (alleen na een fout/time-out).
- "Koppeling op deze telefoon afbreken" (wist koppelbestand en sleutels lokaal).
- "Sluiten (koppeling blijft open)" → M0; bij terugkomst gaat het wachten verder.

## Flows
- M14 → M16 → (`active`) → M17; (`revoked`) → M14; (401/404) → M16 met melding

## Bron
- `ui/screens/PairingScreens.kt`, `pairing/PairingFlow.kt` (`claim`, `awaitActive`), `crypto/PairV1.kt`
