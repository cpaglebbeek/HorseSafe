#!/usr/bin/env bash
# smoke.sh — emulator-smoke ZONDER sleutel (plan Miller deel 1, §Tests 5 + kritiek 11).
#
# Alleen draaien na WhatIf en akkoord van Christian: de emulator (hb-root via /adbdebug) is gedeelde
# infrastructuur. Dit script raakt geen YubiKey en geen server.
#
# Gebruik:  ANDROID_SERIAL=<emulator> android/scripts/smoke.sh [pad/naar/app-release.apk]
#
# Stappen: schone uninstall → install van het distributie-artefact → start → pidof levend →
# `logcat -b crash` leeg voor het pakket → `dumpsys window` toont FLAG_SECURE (FLG_SECURE) →
# afsluiten. "M4 geblokkeerd bij ADB/a11y" kan hier niet (M4 vraagt een sleutel): dat hoort in een
# androidTest met een geïnjecteerde fake-KeyLink (kritiek 11).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
APK="${1:-$HERE/../app/build/outputs/apk/release/app-release.apk}"
PKG="nl.icthorse.horsesafe"
ADB="${ADB:-adb}"
[ -n "${ANDROID_SERIAL:-}" ] || { echo "zet ANDROID_SERIAL (bv. de hb-root-emulator)" >&2; exit 2; }
[ -f "$APK" ] || { echo "APK niet gevonden: $APK" >&2; exit 2; }

fail=0
ok()  { echo "  OK    $*"; }
bad() { echo "  FOUT  $*"; fail=1; }

"$ADB" uninstall "$PKG" >/dev/null 2>&1 || true
"$ADB" logcat -b crash -c || true
"$ADB" install "$APK" >/dev/null && ok "geïnstalleerd" || { bad "install faalt"; exit 1; }
"$ADB" shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
sleep 4
pid="$("$ADB" shell pidof "$PKG" | tr -d '\r' || true)"
[ -n "$pid" ] && ok "proces leeft (pid $pid)" || bad "proces leeft niet"
crash="$("$ADB" logcat -b crash -d | grep -c "$PKG" || true)"
[ "$crash" = 0 ] && ok "logcat -b crash leeg voor $PKG" || bad "$crash crashregels"
if "$ADB" shell dumpsys window windows | tr -d '\r' | grep -A40 "$PKG" | grep -q "FLAG_SECURE\|FLG_SECURE\|SECURE"; then
  ok "FLAG_SECURE op het venster"
else
  bad "FLAG_SECURE niet gevonden"
fi
"$ADB" shell am force-stop "$PKG" || true
echo
if [ "$fail" = 0 ]; then echo "smoke: GROEN"; else echo "smoke: ROOD"; fi
exit "$fail"
