# DEPENDENCIES.md — HorseSafe

> Alle externe bibliotheken, services en integraties die HorseSafe gebruikt of nodig heeft. Bron-of-truth voor risico-analyse + license-audit.

## Frontend (browser)

| Lib | Versie | Licentie | Functie | Risico |
|---|---|---|---|---|
| **kdbxweb** | ^2.1 | MIT | KDBX3/4 read/write in browser | Active maintenance (keeweb-org). Geen alternatief van vergelijkbare kwaliteit. |
| **libargon2-wasm** | bundled met kdbxweb | Apache-2.0 | Argon2id KDF (zware key-derivation) | WebCrypto heeft GEEN Argon2; deze wasm-bundle is enige optie. |
| **WebCrypto API** | browser-native | — | AES, SHA, HMAC, random | Standaard, geen lib nodig. |

**Geen build-step:** vanilla ES2022 modules, ESM-imports via `<script type="module">`. Geen npm/webpack/vite in productie.
**Dev-only:** Playwright (e2e), eslint, prettier — niet uitgeleverd naar client.

## Backend (Python 3.12)

| Lib | Versie | Licentie | Functie |
|---|---|---|---|
| **FastAPI** | ^0.115 | MIT | HTTP-framework, async |
| **Pydantic** | ^2.9 | MIT | Request/response-validatie |
| **uvicorn** | ^0.30 | BSD-3 | ASGI-server |
| **passlib[argon2]** | ^1.7 | BSD | Argon2id password-hashing |
| **pyotp** | ^2.9 | MIT | TOTP RFC 6238 |
| **pyjwt** | ^2.9 | MIT | JWT cookies |
| **httpx** | ^0.27 | BSD-3 | Outbound calls (e-mail SMTP via iCt_Horse magic-link bridge) |
| **python-multipart** | ^0.0.12 | Apache-2.0 | File-uploads (vault-blobs) |
| **aiosqlite** | ^0.20 | MIT | Async SQLite |
| **pyargon2** | ^1.0 | BSD | Argon2id via libargon2 (server-side hash) |

**Dev-only:**
- pytest, pytest-asyncio, pytest-cov, httpx-mock
- ruff, black, mypy

## Infrastructuur (HC55)

| Component | Versie | Bron |
|---|---|---|
| **nginx** | 1.24.0 | Ubuntu 24.04 packages — al aanwezig (gedeeld) |
| **systemd** | — | Ubuntu 24.04 — al aanwezig |
| **Python** | 3.12 | apt — al aanwezig |
| **SQLite** | 3.45+ | apt — geleverd met Python stdlib |
| **Let's Encrypt** | certbot auto-renew | al aanwezig |
| **rsync** | — | apt — al aanwezig |
| **Hetzner Storagebox** | bestaande account | voor backups |

## Externe services

| Service | Doel | Risico |
|---|---|---|
| **iCt_Horse magic-link bridge** | E-mail verzending magic-links | Single point of failure. Bij outage: TOTP-fallback. |
| **Gmail SMTP** (via iCt_Horse) | Onderliggende e-mail-transport | Standaard cglebbeek@gmail.com app-password. |
| **Let's Encrypt** | TLS-certificaat | Auto-renew via HC55 certbot. |

## Browser-extensie (v0.2.0+, optioneel)

| Item | Keuze |
|---|---|
| Manifest | V3 (MV3) |
| Doel-browsers | Chrome, Edge, Brave, Vivaldi (Chromium-familie). Firefox = aparte build (MV3 support is gedeeltelijk). Safari = niet in scope v0.2.0. |
| Native messaging | Tussen extension-popup en HorseSafe-tab |
| Distribuie | Chrome Web Store (US$5 eenmalig dev-fee) + Edge Add-ons (gratis) |

## Licentie-policy

- HorseSafe-eigen code = **proprietary** zolang repo PRIVATE
- Bij open-source (v0.1.0 overweging): **AGPL-3.0** voorgesteld (consistent met security-georiënteerde open-source projecten + voorkomt closed-fork-SaaS)
- Geen GPL-incompatibele dependencies → kdbxweb (MIT) + FastAPI (MIT) + Pydantic (MIT) zijn allemaal compatibel

## Niet-gebruikte alternatieven (waarom afgewezen)

| Lib | Reden afwijzing |
|---|---|
| **Bitwarden self-hosted (vaultwarden)** | Geen KDBX-compat; Rust-stack vereist DB-schema-fit; Bitwarden-protocol ipv KeePass |
| **Eigen WASM-port KeePassXC C++** | Overkill; kdbxweb dekt 100% van benodigde KDBX4-functionaliteit |
| **CryptoJS** | Verouderd, kdbxweb gebruikt WebCrypto-native waar mogelijk |
| **Node.js backend** | Slechtere fit met bestaande HC55-Python-stack; geen voordeel voor blob-storage |
| **Rust Axum backend** | Goed security-profiel maar crypto-complexiteit zit client-side; Python is sneller voor MVP. Heroverweging bij v0.2.0 als perf-bottleneck blijkt. |
| **Apache Guacamole** | Geen relevantie (geen RDP/SSH) |

## Verwijzingen

- KeePassXC 2.7.12 source: `Meta_iCt_Horse_Diensten/sources/keepassxc-2.7.12-src.tar.xz` (na bugcheck consume)
- kdbxweb: https://github.com/keeweb/kdbxweb
- KDBX4-spec: https://keepass.info/help/kb/kdbx_4.html
- Argon2 RFC: https://www.rfc-editor.org/rfc/rfc9106
- TOTP RFC: https://www.rfc-editor.org/rfc/rfc6238
