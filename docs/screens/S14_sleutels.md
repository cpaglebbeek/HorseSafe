# S14 — Sleutelbeheer

**Route:** `/HorseSafe/vault.html` → "🔑 Sleutels" (paneel `#keys-section`)
**Auth-eis:** JWT+MFA en een geopende kluis (ontgrendelmateriaal in tab-RAM); koppelen vanaf de tweede sleutel, bijwerken en blokkade opheffen vragen S15
**Doel:** YubiKey Bio en noodsleutel koppelen, bekijken, blokkeren en ontkoppelen; sinds v0.3.4-Miller ook telefoons (S17)
**Doelgroep:** eigenaar van de kluis
**Sinds:** v0.2.0-Koblitz

## Key-messages
- "Open deze kluis met je vingerafdruk op een YubiKey Bio."
- "Een noodsleutel bewaar je in een fysieke kluis; hij werkt pas 24 uur na aanvraag."
- "Je wachtwoord/keyfile blijft altijd werken — ook in KeePassXC."

## CTA's
- Primair: "+ YubiKey Bio koppelen" (`#key-add-bio`)
- Secundair: "+ Noodsleutel koppelen" (`#key-add-recovery`), "↻ Bijwerken" (`#keys-reseal`), "Sluiten" (`#keys-close`)
- Per rij: Verwijder; bij een noodsleutel ook Blokkeren / Opheffen / Annuleren; bij een telefoon "Toestel verwijderen"
- "📱 Telefoon koppelen" (`#phone-pair`) → S17

## Componenten
- `#notify-banner` — meldingen niet ingesteld → vrijgave noodsleutel uitgeschakeld
- tabel `#keys-body` (in `.table-scroll`) — naam (telefoon: toestellabel) · soort (+ model) · gekoppeld · laatst gebruikt · status · acties
- `#key-label` — naam van de nieuwe sleutel (max. 64 tekens)
- `#keys-error` / `#keys-status`
- onderaan S16 (`#rekey-form`)

## Statussen (gewone taal)
klaar · in de kluis (klaar) · wacht nog 13 u 20 m (tot …) · vrijgegeven tot … · gebruikt · verlopen · geblokkeerd sinds … · "kopie verouderd" (na een wachtwoordwijziging buiten HorseSafe: gebruik "Bijwerken")

## Flows
| Actie | API | Step-up |
|---|---|---|
| Lijst | `GET /vault/{vid}/keys` | nee |
| Koppelen | `POST /webauthn/options` (register) → `POST /vault/{vid}/keys` | vanaf de tweede sleutel |
| Bijwerken | `PUT /vault/{vid}/keys/sealed` | ja |
| Blokkeren noodsleutel | `POST /vault/{vid}/keys/{kid}/block` | nee (defensief) |
| Blokkade opheffen | `DELETE /vault/{vid}/keys/{kid}/block` | ja, alleen YubiKey Bio |
| Ontkoppelen | `DELETE /vault/{vid}/keys/{kid}` | nee (defensief) |
| Telefoon koppelen (S17) | `POST /devices/pairings` → poll `GET /devices/pairings/{id}` → `POST …/confirm` | ja (start) |
| Toestel verwijderen | `DELETE /devices/{id}` (alle kopieën van dat toestel weg) | nee (defensief) |

## Bron
- `UI_DESIGN.md` § S14 · `docs/HARDWARE_KEYS.md` §12.6 en §12.13
- `frontend/vault.html` · `frontend/js/hwkeys-ui.js` · `frontend/js/hwkeys.js`
