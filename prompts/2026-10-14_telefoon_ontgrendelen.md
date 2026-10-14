---
date: 2026-10-14
repo: HorseSafe
session: telefoon_ontgrendelen
status: pending
resume: "verder met HorseSafe: besluit R4 release-keystore, daarna bouwplan fase A (Miller deel 2, 0.3.4)"
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

## Open
- Besluit R4 release-keystore (volgende vraag).
- Bouwplan fase A (Miller deel 2, 0.3.4) als WhatIf + akkoord.
