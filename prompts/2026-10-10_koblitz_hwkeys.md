# Sessie 2026-10-10/11 — v0.2.0-Koblitz: hardware-sleutels in het web (sessie 80ac11c8)

## Prompts (chronologisch, HorseSafe-deel)
1. "1 uur. bouw intussen ook simpele apk waarme ik ubikey , gewoon en bio kan instellen / koppelen voor horsssafe. ultracode en /APKDeploy"
2. "1 ja 2 ja 3 ook uitbreiding webversie 4 horsesaf en ubikey apk app horen in de horsesafe repo. bouuw daar"
3. "akkoord" — overzicht 7 punten
4. "akkoord" — P-CRYPT-09 + nieuwe tekst CLAUDE.md:53
5. "akkoord" — codenamen Koblitz/Miller/Montgomery/Lange, ROADMAP doorgeschoven
6. "a" — blokkade noodsleutel blijft tot Bio-step-up
7. "a" — generieke SMTP 587 met icthorse-account (ClaudeSecrets → /opt/horsesafe/.env)
8. "b" — eigen emulator hb-horsesafe (voor Miller)
9. "a" — polling, geen FCM
10. "a" — v0.5 (Lange) niet nu
11. "akkoord" — stap 0 + v0.2.0-Koblitz (Miller/Montgomery NIET; per fase akkoord)

## Acties
- Stap 0: onafgemaakt werk van sessie 42d3ff7c ongewijzigd veiliggesteld → commit `9000044`.
- Ontwerp `docs/HARDWARE_KEYS.md` (jury + Koblitz API-contract §12).
- Bouwworkflow (ultracode): spec → backend/frontend/docs parallel → 3 adversariële reviewrondes
  (zk-security, spec-eisen, correctheid). 16 bevindingen, alle gefixt, o.a.:
  TOTP-secret overschrijven met alleen wachtwoord, backup-codes zonder MFA, magic-link als volledige login,
  32-byte keyfile in-place gewist door kdbxweb (dataverlies), Bio-step-up met nieuw gekoppelde Bio,
  public_key-verwisseling (key-pinning in KDBX), vault-delete-cascade omzeilde TOTP-afkoelperiode,
  etag-race save↔rekey, magic-link onbruikbaar door SameSite=Strict.
- Tests: backend 196/196, frontend unit 59/59, Playwright 10/10 (CDP virtual authenticator).
- Commit `68e4695` (84 bestanden, per bestand toegevoegd, `git ls-tree` geverifieerd), push.
- Incident gecontroleerd: legacy e2e-specs wezen naar :3997 (LIVE). Journal: alleen OPTIONS (405/429),
  geen POST/PUT/DELETE sinds 10-10 18:00 → productie niet geraakt. Actie in ACTIONS.md.
- Deploy HC55 (11-10 00:31–00:33 UTC): backup DB/vaults/.env naar `/opt/horsesafe/backups-predeploy/` (700),
  SMTP-gegevens uit ClaudeSecrets (`icthorse-mail/info_password`) zonder printen in `.env`,
  checkout bijgewerkt naar origin/main, pip (webauthn 2.7.1), migratie 005 (schema 5),
  rsync frontend met excludes, restart. `/api/health` = 0.2.0-Koblitz, test_attestation:false;
  post_deploy_smoke groen (smoke-account opgeruimd); nginx -t ok, ClaudeWeb ok.
- Testmail via nieuwe mailer: 250, afgeleverd in info@icthorse.nl-inbox.
- Commit `9cf5294` (version.json + ACTIONS.md).
- /ModelArchDSL init+update (er was nog geen archmodel).

## Open
- Veldtest met echte YubiKey Bio (Christian).
- Akkoord voor v0.3.0-Miller (Android-app) — per fase.

## Vervolg 2026-10-11 — v0.2.1-Koblitz (open Koblitz-punten, sessie 42d3ff7c)

Prompt: "akkoord" op het voorstel om de open Koblitz-punten als v0.2.1 op te pakken (geen deploy).

- e2e-specs admin/mfa/smoke via `frontend/tests/isolated.ts` op een eigen tijdelijke backend; vangnet breekt
  verzoeken naar :3997 (LIVE) af — negatief geverifieerd met een tijdelijke probe-spec (faalde zoals bedoeld).
- Deploy-excludes in `scripts/deploy_hc55.sh` + runbook; vastgesteld dat live `devserver.py` en `README.md`
  publiek serveert (200, geen geheimen) — verdwijnt bij de volgende deploy.
- Privacy/GDPR (Hostinger-subverwerker, sleutelmetadata) en UI-docs (S6, S14-S16) bijgewerkt.
- Tests lokaal: pytest 196/196, node --test 59/59, Playwright 10/10; CI GitHub groen (run 38128879042).
- **Open:** `ci.yml`-wijziging kon niet gepusht worden (gh-token mist scope `workflow`) — Christian:
  `gh auth refresh -s workflow`, daarna commit + push. Deploy v0.2.1 alleen na akkoord.
