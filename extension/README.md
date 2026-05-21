# extension/ — HorseSafe browser-extensie (v0.2.0)

> Phase 0 — placeholder. Niet in scope tot v0.2.0.

## Doel

- **Autocomplete** wachtwoorden in URL-matchende form-fields
- **Échte clipboard-wipe** (niet best-effort)
- **URL-pinning** als anti-phishing-laag

## Geplande structuur

```
extension/
├── manifest.json          # MV3
├── background.js          # native-messaging-bridge naar HorseSafe-tab
├── content.js             # injection in pagina's voor autocomplete
├── popup.html             # mini-vault-zicht (alleen URL-match-suggesties)
├── popup.js
├── icons/
│   └── horsesafe-128.png
└── README.md              # build + load-unpacked instructies
```

## Targets

- Chrome / Edge / Brave / Vivaldi (Chromium MV3)
- Firefox (aparte build, MV3 partial support)
- Safari = niet in scope v0.2.0

## Distributie

- Chrome Web Store (US$5 dev-fee)
- Edge Add-ons (gratis)
- Firefox Add-ons (gratis)
