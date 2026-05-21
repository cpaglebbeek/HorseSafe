# BUGLIST.md — HorseSafe

> Conform `feedback_debug_buglist_protocol.md`: alle bugs met kleurcode + RCA op 3 niveaus.

Kleurcodes:
- 🟢 **Groen** = snel herstel (fysiek niveau)
- 🟡 **Geel** = out-of-physical-box (logische architectuur)
- 🔴 **Rood** = out-of-the-box (conceptueel redesign + security-audit)
- 🔁 **Loop** = debug-loop — nieuwe invalshoek nodig

---

## Open bugs

_Geen open bugs — repo is skeleton-only._

## Gepland te traceren (preventief)

| ID | Voorzien type | Beschrijving | Mitigatie-strategie |
|---|---|---|---|
| HS-BUG-PRE-001 | 🟡 Geel | KDBX4-round-trip via kdbxweb produceert bestand dat KeePassXC weigert | CI-test: schrijf met kdbxweb → open met KeePassXC-CLI (`keepassxc-cli ls`) |
| HS-BUG-PRE-002 | 🟡 Geel | Argon2id-perf in browser onacceptabel op zwakke devices (mobiel) | Benchmark t=12/m=128MiB op iPhone X-equivalent; fallback t=8/m=64MiB met UI-warning |
| HS-BUG-PRE-003 | 🔴 Rood | Clipboard-wipe faalt → pw blijft na 10s | Documenteer in UI ("best-effort"); v0.2 = extensie |
| HS-BUG-PRE-004 | 🟡 Geel | Optimistic-lock-conflict bij snelle multi-tab edit | Tonen "vault is elders gewijzigd, kies versie" dialog |
| HS-BUG-PRE-005 | 🟢 Groen | Magic-link e-mail wordt als spam gemarkeerd | SPF+DKIM check op iCt_Horse magic-link bridge |
| HS-BUG-PRE-006 | 🟡 Geel | TOTP-drift > 30s door device-clock-skew | RFC 6238 ±1 window-tolerance (= ±30s) instellen in pyotp |
| HS-BUG-PRE-007 | 🔴 Rood | Backend logt per ongeluk KDBX-blob in stderr | strict-mode logging: alleen request-pad + status, nooit body |
| HS-BUG-PRE-008 | 🟡 Geel | Import-CSV met UTF-8-BOM crasht parser | Fixture-tests met BOM, UTF-16, Windows-1252 |
| HS-BUG-PRE-009 | 🟢 Groen | XLSX-export wordt > 50 MB bij grote vaults | Streaming-write met openpyxl write-only mode |
| HS-BUG-PRE-010 | 🟡 Geel | Browser-extensie native-message verliest sync met tab | Heartbeat-protocol elke 5s |

## Resolved bugs

_Nog niets — repo is skeleton-only._

---

## RCA-template (verplicht bij elke bug-resolutie)

```markdown
### HS-BUG-NNN — <korte titel>

**Kleur:** 🟢/🟡/🔴/🔁
**Status:** open / in-progress / resolved
**Versie ontdekt:** v0.x.y-Codename
**Versie opgelost:** v0.x.y-Codename

**Symptoom:** ...

**RCA — drie niveaus:**
- **Functioneel:** wat zag de gebruiker / wat brak in de feature
- **Technisch:** welke code / config / library / data was de directe oorzaak
- **Architectonisch:** welke ontwerpkeuze maakte deze bug mogelijk

**Fix:**
- Diff: <link naar commit>
- Test: <link naar test-bestand>

**Preventie:**
- Welke check zou dit in de toekomst vangen?
```
