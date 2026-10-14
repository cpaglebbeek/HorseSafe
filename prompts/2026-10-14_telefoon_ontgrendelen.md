---
date: 2026-10-14
repo: HorseSafe
session: telefoon_ontgrendelen
status: pending
resume: "verder met HorseSafe: veldtest koppelen telefoon (0.3.4 live), daarna fase B Montgomery"
project: HorseSafe
ecosystem: iCt Horse Diensten
linked_actions: [telefoon-ontgrendelen]
---

# Sessie 2026-10-14 — telefoon-ontgrendelen naar voren

## Verzoeken en besluiten van Christian (chronologisch)
1. "verder me horsesafe" → stand gemeld (live 0.2.0-Koblitz, app 0.3.3-Miller, hardwaretest bij Christian).
2. "ik wil nu eerst testen zonder yubikey met alleen vingerafdruk als ik horsesafe op web open" → uitgelegd dat dit
   nu niet kan (alleen YubiKeys; telefoon = Miller deel 2 + Montgomery). Keuze "2": telefoon bouwen.
3. WhatIf fase A/B; vraag aparte app (advies b) of dezelfde app (a). "akkoord" → niet afgeleid, nagevraagd.
4. "a. vingerafdruk en code invoeren (zoals claudeweb)" → één app; ontgrendelen met code + vinger zoals BB-001.
5. WhatIf: BB-001 is niet zero-knowledge (server controleert de code) → voorstel 6 cijfers, telefoon controleert,
   commitment-SAS. "akkoord".

Vastgelegd in `docs/HARDWARE_KEYS.md` §11.2 (+ notities bij E9 en §5) en `ACTIONS.md`.

6. R4: "a" → eigen release-keystore (HARDWARE_KEYS §11.2 punt 5).

7. Bouwplan fase A (A1–A12) → "akkoord" (deploy/publicatie A12 apart).

## Voortgang fase A
- A1 klaar: eigen release-keystore op HC55 (`~/.keystores/horsesafe-release.jks`, signer `fbd6b151…062e`),
  back-up + env in ClaudeSecrets (commit 14565c8), Gradle tekent ermee, zonder env ongetekend (geen debug-terugval).
- Contract `HARDWARE_KEYS.md` §13 + `specs/testvectors/pair_v1.json`. Aanscherping t.o.v. §4.5: koppelgeheim in de
  browser (k_srv naar server, k_web blijft in browser) — anders kan de server de telefoonsleutels verwisselen.
- Backend, app en web worden parallel gebouwd tegen §13 (niet gecommit tot integratie en review).

- Agents backend/app/web klaar; integratie: userAuthType strikt == 2 (advies backend-agent, E2), Gen-Y-pins YE/YR toegevoegd
  (icthorsecloud.nl draait op YE1 → Root YE; pins zelf nagerekend), smoke.sh gerepareerd (vals ROOD: FLAG_SECURE-grep
  en `monkey` rc 251 op Android 14).
- Adversariële review: 0 kritiek/hoog; middel = app wiste geldige koppeling bij 401 → gefixt, plus 9 laag.
- Eindmeting: pytest 269, node 87, Playwright 12, JVM 337, lint 0 errors; release vc 304 sha 3e0419c2…c20c,
  verify_apk GROEN; smoke Android 16+14 groen; emulator zonder vinger-HAL → M18 correct.

8. A12 WhatIf → "akkoord". Deploy HC55: backup, migratie 006, health 0.3.4-Miller, smoke GROEN. Valkuil: migrate
   zonder `.env` raakte een losse repo-DB — opnieuw met env gedraaid, runbook + deploy-script gerepareerd; oude
   `devserver.py`/`README.md` uit webroot verwijderd (`--delete-excluded`). HorseAPK: vc 304 gepubliceerd.

## Open
- Christian: app op Fold/Fairphone opnieuw installeren (nieuwe keystore), daarna veldtest op echte telefoon.
- Bouwplan fase A (Miller deel 2, 0.3.4) als WhatIf + akkoord.
