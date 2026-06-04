# DESIGN_TOKENS.md — HorseSafe

> Visuele design-tokens (kleuren, typografie, spacing). Cross-ref: `UI_DESIGN.md`.

## Kleuren — dark theme (default)

| Token | Hex | Gebruik |
|---|---|---|
| `--hs-bg-primary` | `#0E1116` | Page-background |
| `--hs-bg-surface` | `#161B22` | Cards, modals, sidebars |
| `--hs-bg-elevated` | `#21262D` | Dropdowns, popovers |
| `--hs-fg-primary` | `#E6EDF3` | Primaire tekst |
| `--hs-fg-secondary` | `#9DA7B0` | Secundaire tekst, labels |
| `--hs-fg-muted` | `#6E7681` | Disabled, hints |
| `--hs-accent` | `#4C9EEB` | Links, focus-rings, primary buttons |
| `--hs-accent-hover` | `#79B8F4` | Hover |
| `--hs-danger` | `#F85149` | Errors, delete, plaintext-export-confirm |
| `--hs-warning` | `#D29922` | Warnings, expiry |
| `--hs-success` | `#3FB950` | Success, lock-engaged-indicator |
| `--hs-border` | `#30363D` | 1px-borders |

## Kleuren — light theme (optie)

| Token | Hex |
|---|---|
| `--hs-bg-primary` | `#FFFFFF` |
| `--hs-bg-surface` | `#F6F8FA` |
| `--hs-fg-primary` | `#1F2328` |
| `--hs-fg-secondary` | `#656D76` |
| `--hs-accent` | `#0969DA` |
| `--hs-danger` | `#CF222E` |
| `--hs-border` | `#D0D7DE` |

(rest analoog)

## Typografie

| Token | Waarde |
|---|---|
| `--hs-font-sans` | `system-ui, -apple-system, "Segoe UI", Roboto, sans-serif` |
| `--hs-font-mono` | `"SF Mono", "JetBrains Mono", Consolas, monospace` |
| `--hs-fs-xs` | `0.75rem` (12px) |
| `--hs-fs-sm` | `0.875rem` (14px) |
| `--hs-fs-base` | `1rem` (16px) |
| `--hs-fs-lg` | `1.125rem` (18px) |
| `--hs-fs-xl` | `1.5rem` (24px) |
| `--hs-fw-normal` | `400` |
| `--hs-fw-medium` | `500` |
| `--hs-fw-bold` | `600` |
| `--hs-lh-tight` | `1.25` |
| `--hs-lh-base` | `1.5` |
| `--hs-totp-code-size` | `1.3em` (TOTP-code-display, v0.0.9-Bellare+) |
| `--hs-totp-letter-spacing` | `0.15em` (TOTP-code-display, v0.0.9-Bellare+) |
| `--hs-totp-numeric-style` | `tabular-nums` (countdown-seconden, voorkomt UI-shimmer) |
| `--hs-totp-code-weight` | `600` (= `--hs-fw-bold`) |

> **Toepassing TOTP-tokens** (vault.html `#d-totp-code` / `#d-totp-countdown`): code in `--hs-font-mono` × `--hs-totp-code-size` × `--hs-totp-letter-spacing` × `--hs-totp-code-weight`. Countdown in standard font × `--hs-fs-sm` × `--hs-totp-numeric-style`.

## Spacing (4-px raster)

| Token | Waarde |
|---|---|
| `--hs-sp-1` | `4px` |
| `--hs-sp-2` | `8px` |
| `--hs-sp-3` | `12px` |
| `--hs-sp-4` | `16px` |
| `--hs-sp-5` | `20px` |
| `--hs-sp-6` | `24px` |
| `--hs-sp-8` | `32px` |
| `--hs-sp-10` | `40px` |
| `--hs-sp-12` | `48px` |

## Border-radius

| Token | Waarde |
|---|---|
| `--hs-br-sm` | `4px` (input, tag) |
| `--hs-br-md` | `6px` (button, card) |
| `--hs-br-lg` | `8px` (modal, sidebar) |
| `--hs-br-full` | `9999px` (avatar, badge) |

## Shadows

| Token | Waarde |
|---|---|
| `--hs-sh-sm` | `0 1px 2px rgba(0,0,0,0.4)` |
| `--hs-sh-md` | `0 4px 8px rgba(0,0,0,0.5)` |
| `--hs-sh-lg` | `0 10px 24px rgba(0,0,0,0.6)` |

## Z-index

| Token | Waarde |
|---|---|
| `--hs-z-base` | `0` |
| `--hs-z-sticky` | `100` |
| `--hs-z-modal` | `1000` |
| `--hs-z-toast` | `2000` |
| `--hs-z-tooltip` | `3000` |

## Animation

| Token | Waarde |
|---|---|
| `--hs-tr-fast` | `100ms cubic-bezier(0.4,0,0.2,1)` |
| `--hs-tr-base` | `200ms cubic-bezier(0.4,0,0.2,1)` |
| `--hs-tr-slow` | `400ms cubic-bezier(0.4,0,0.2,1)` |

## Iconen

Bron: [Lucide](https://lucide.dev) (MIT). Subset:
- `lock` / `unlock` — vault-state
- `eye` / `eye-off` — password-toggle
- `clipboard` / `clipboard-check` — copy-state
- `external-link` — URL-klik
- `key` — keyfile-indicator
- `shield` — MFA
- `download` / `upload` — import/export
- `trash` / `archive` — entry-acties
- `user` / `users` — admin
- `chevron-down` / `chevron-right` — boom-navigatie

## Logo

`frontend/assets/horsesafe.svg` (TBD ontwerp). Concept: paard-silhouet + kluis-vorm; primair `--hs-accent`.

## Responsive breakpoints

| Token | Waarde |
|---|---|
| `--hs-bp-sm` | `640px` (Z-Fold 6 outer screen) |
| `--hs-bp-md` | `768px` (tablet portrait) |
| `--hs-bp-lg` | `1024px` (tablet landscape, kleine laptop) |
| `--hs-bp-xl` | `1280px` (desktop) |

Mobile-first defaults; layout collapse onder `--hs-bp-md`.
