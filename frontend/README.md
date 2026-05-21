# frontend/ — HorseSafe browser-client

> Phase 0 — placeholder. Frontend POC volgt in Fase 2.

## Geplande structuur

```
frontend/
├── index.html             # S1 landing
├── login.html             # S2 + S3 + S4
├── vault.html             # S5 + S6 + S7 + S8
├── admin.html             # S11
├── settings.html          # S12
├── assets/
│   ├── horsesafe.css      # dark-theme defaults
│   └── horsesafe.svg      # logo
├── js/
│   ├── api.js             # fetch-wrappers naar /HorseSafe/api/
│   ├── crypto.js          # kdbxweb-wrapper + clipboard-manager
│   ├── auth.js            # login + MFA UI-flow
│   ├── vault-ui.js        # entry-tabel + detail-paneel
│   └── import-export.js
└── vendor/
    └── kdbxweb.esm.js     # MIT, ESM-bundle
```

## Geen build-step

Vanilla ES2022 modules. Direct serveerbaar via nginx static `/HorseSafe/` → `/opt/horsesafe/web/`.
`kdbxweb` wordt als ESM-bundle in `vendor/` gehouden (gepind op versie; geen npm in productie).

## Dev

```bash
cd frontend
python3 -m http.server 8000   # of `npx serve .`
```
Open http://localhost:8000 — gebruikt staging-backend (env-config in `js/api.js`).
