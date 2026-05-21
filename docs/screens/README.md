# docs/screens/ — HorseSafe schermen-referentie

> Per scherm uit `UI_DESIGN.md` (S1-S12): doel + key-messages + CTA + screenshot (vanaf Fase 2 frontend POC).

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
