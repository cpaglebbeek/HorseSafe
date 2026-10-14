# docs/screens/ — HorseSafe schermen-referentie

> Per scherm uit `UI_DESIGN.md` (S1-S16; S14-S16 sinds v0.2.0-Koblitz; Android-app M0-M12 sinds v0.3.0-Miller, M13 sinds v0.3.1, M14-M19 sinds v0.3.4): doel + key-messages + CTA + screenshot (vanaf Fase 2 frontend POC).

## Conventie

Per scherm één markdown-bestand: `S<NN>_<slug>.md` met onderstaande structuur. Screenshot als PNG in dezelfde dir: `S<NN>_<slug>.png`.

```markdown
# S<NN> — <schermnaam>

**Route:** `/HorseSafe/<pad>`
**Auth-eis:** geen / JWT / JWT+MFA / JWT+MFA+admin
**Doel:** ...
**Doelgroep:** ...

## Key-messages
- ...

## CTA's
- Primair: ...
- Secundair: ...

## Componenten
- ...

## Flows (in → uit)
- Vorige scherm: S<NN>
- Volgende scherm: S<NN> (success) / S<NN> (fail)

## Visuele referentie
![](S<NN>_<slug>.png)

## Bron
- UI_DESIGN.md §S<NN>
- ARCHITECTURE.md §2.4 (indien flow)
```

## Stand van zaken (2026-05-21)

| # | Scherm | MD | PNG | Status |
|---|---|---|---|---|
| S1 | Landing | `S01_landing.md` (placeholder) | — | ⏳ Fase 2 |
| S2 | Account-login | `S02_login.md` (placeholder) | — | ⏳ Fase 2 |
| S3 | Account-registratie | `S03_register.md` (placeholder) | — | ⏳ Fase 2 |
| S4 | MFA-challenge | `S04_mfa.md` (placeholder) | — | ⏳ Fase 3 |
| S5 | Vault-lijst | `S05_vault_list.md` (placeholder) | — | ⏳ Fase 2 (v0.1.x) |
| S6 | Vault-unlock | `S06_vault_unlock.md` (placeholder) | — | ⏳ Fase 2 |
| S7 | Vault-content | `S07_vault_content.md` (placeholder) | — | ⏳ Fase 2 |
| S8 | Entry bewerken | `S08_entry_edit.md` (placeholder) | — | ⏳ Fase 2 |
| S9 | Import-flow | `S09_import.md` (placeholder) | — | ⏳ Fase 5 |
| S10 | Export-flow | `S10_export.md` (placeholder) | — | ⏳ Fase 5 |
| S11 | Admin-pagina | `S11_admin.md` (placeholder) | — | ⏳ Fase 4 |
| S12 | Settings | `S12_settings.md` (placeholder) | — | ⏳ Fase 3 |

Placeholders worden bij Fase 2-start ingevuld; screenshots na elk schermbouw-commit.

## Android-app (v0.3.0-Miller deel 1)

| # | Scherm | MD | PNG |
|---|---|---|---|
| M0 | Start | `M00_start.md` | — |
| M1 | Checklist | `M01_checklist.md` | — |
| M2 | Sleutel aansluiten | `M02_connect.md` | — |
| M3 | Oordeel | `M03_judgement.md` | — |
| M4 | PIN tonen | `M04_reveal.md` | — (FLAG_SECURE: geen screenshot mogelijk) |
| M5 | Overschrijven | `M05_copy.md` | — |
| M6 | Overtypen | `M06_retype.md` | — |
| M6b | Onomkeerbaar | `M06b_irreversible.md` | — |
| M7 | Vingers | `M07_fingers.md` | — |
| M8 | PIN invoeren | `M08_pin_entry.md` | — |
| M9 | Keuring | `M09_keuring.md` | — |
| M10 | Rapport | `M10_report.md` | — |
| M11 | Stop | `M11_stop.md` | — |
| M12 | Over | `M12_about.md` | — |
| M13 | Sleutel wissen | `M13_reset.md` | — |
| M14 | Telefoon koppelen | `M14_pair.md` | — |
| M15 | QR-code scannen | `M15_pair_scan.md` | — (camerabeeld onder FLAG_SECURE) |
| M16 | Vergelijk de code | `M16_pair_sas.md` | — |
| M17 | Gekoppeld | `M17_paired.md` | — |
| M18 | Vingerafdruk nodig | `M18_bio_required.md` | — |
| M19 | Opnieuw koppelen | `M19_repair.md` | — |

Alle Android-schermen hebben FLAG_SECURE; screenshots alleen uit een emulator-debugbuild (nog niet gemaakt).
