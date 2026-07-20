# LAUNCH_PREP.md — HorseSafe v0.1.0-Massey publieke launch

> Voorbereiding voor de publieke launch. **Repo-public + AGPL is GEBLOKKEERD** tot de
> git-history-scrub hieronder is uitgevoerd (zie §1). Alle overige launch-content staat
> klaar zodat public-go daarna één schone stap is.

## 1. BLOKKEREND — git-history bevat plaintext-wachtwoorden

Secret-scan 2026-07-20 (`git grep` over volledige history) vond echte wachtwoord-strings
in de commit-history:

| String | Waar | Status |
|---|---|---|
| `[REDACTED-ACCOUNT-PW]` (account-pw) | `ACTIONS.md`, `CHANGELOG.md`, `prompts/2026-06-05_*.md` | account-pw gereset 2026-07-20, maar onthult patroon |
| `[REDACTED-VAULT-PW]` (oude vault-master) | `CHANGELOG.md`, `prompts/2026-06-05_*.md` | vault her-sleuteld (v5), string stale maar onthult patroon |

**Waarom blokkerend:** beide volgen het patroon `[REDACTED-PREFIX]<Woord>!` dat elders **live** in gebruik
is (o.a. de icthorse-mail-login `[REDACTED-LIVE-PW]`). Publiceren = het patroon publiek maken →
raadbaarheid van nog-actieve credentials. De live vault-master zelf staat NIET in de history
(geverifieerd tegen ClaudeSecrets), dus de vault-inhoud is niet direct blootgesteld.

### Scrub-procedure (uit te voeren ná akkoord — herschrijft history + force-push)

```bash
# 1. Verse mirror-clone als werkkopie
cd /tmp && git clone --mirror git@github.com:cpaglebbeek/HorseSafe.git horsesafe-scrub.git
cd horsesafe-scrub.git

# 2. git-filter-repo met replace-rules (installeer: brew install git-filter-repo)
cat > /tmp/hs-replacements.txt <<'RULES'
[REDACTED-ACCOUNT-PW]==>[REDACTED-ACCOUNT-PW]
[REDACTED-VAULT-PW]==>[REDACTED-VAULT-PW]
RULES
git filter-repo --replace-text /tmp/hs-replacements.txt

# 3. Verifieer schoon
git grep -i "[REDACTED-PREFIX]" $(git rev-list --all) || echo "SCHOON"

# 4. Force-push (LET OP: coördineer — geen andere sessie mag tegelijk pushen)
git push --force --mirror
rm -f /tmp/hs-replacements.txt
```

Daarna lokale clone re-syncen (`git fetch --all && git reset --hard origin/main`) en pas
dan §2 (public + AGPL) uitvoeren.

## 2. Public + AGPL (ná scrub)

```bash
# LICENSE-bestand toevoegen (AGPL-3.0)
curl -s https://www.gnu.org/licenses/agpl-3.0.txt -o LICENSE   # of uit template
git add LICENSE && git commit -m "AGPL-3.0 license voor publieke launch"
git push
gh repo edit cpaglebbeek/HorseSafe --visibility public --accept-visibility-change-consequences
```

## 3. Sitemap-entry (icthorse.nl, Hostinger)

Toevoegen aan `domains/icthorse.nl/public_html/sitemap.xml`:

```xml
<url>
  <loc>https://icthorse.nl/HorseSafe/</loc>
  <changefreq>monthly</changefreq>
  <priority>0.7</priority>
</url>
```

## 4. LinkedIn-post (DRAFT — niet verzenden zonder akkoord)

> 🔐 **HorseSafe is live** — een zero-knowledge wachtwoordkluis waarbij de server je
> master-wachtwoord, keyfile en kluis-inhoud **nooit** ziet.
>
> Waarom nog een wachtwoordmanager? Omdat "zero-knowledge" vaak een marketingterm is.
> HorseSafe maakt het controleerbaar:
> • Kluis wordt in je browser versleuteld (KeePass KDBX4) — de server slaat alleen ciphertext op.
> • Volledig compatibel met KeePassXC-desktop: je export opent gewoon lokaal.
> • Per-entry TOTP-codes, keyfile-ondersteuning, MFA.
> • Open source onder AGPL-3.0 — controleer de crypto zelf.
>
> Probeer het: https://icthorse.nl/HorseSafe/
> Code: https://github.com/cpaglebbeek/HorseSafe
>
> #zerotrust #passwordmanager #opensource #cybersecurity #privacy

## 5. Openstaand op user-credentials (los van public-go)

- **Backup naar Storagebox** — `HORSESAFE_BACKUP_TARGET` in `/opt/horsesafe/.env`; vereist
  Storagebox SSH-key in `~horsesafe/.ssh/`. Nu leeg → `backup.sh` skipt netjes.
- **Magic-link mail** — `HORSESAFE_GMAIL_USER` + `HORSESAFE_GMAIL_APP_PASSWORD`; vereist
  Google App Password (2FA-account). Nu leeg → magic-link disabled (MFA blijft optioneel via TOTP).

## 6. Dashboard-tile (nice-to-have)

Het Dashboard-project (`cpaglebbeek/Dashboard`) doet repo-sync-status, geen live
service-health-probing. Een health-tile met `/HorseSafe/api/health`-poll is een nieuwe
feature in dat repo, buiten HorseSafe-scope. Uitgesteld.
