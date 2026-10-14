#!/usr/bin/env bash
# verify_apk.sh — controleert een gebouwd HorseSafe-APK (plan Miller deel 1, §Tests 3; A-13, A-15).
#
# Gebruik:  android/scripts/verify_apk.sh [pad/naar/app-release.apk]
#           (standaard: android/app/build/outputs/apk/release/app-release.apk)
#
# Controles (alleen lezen, geen netwerk, geen toestel):
#   1. apksigner verify --print-certs: geldig, en signer-SHA-256 == de HC55-keystore (E8). Alleen
#      lokaal op HC55 zinvol: in CI en op de build-box tekent een andere (wegwerp)sleutel (kritiek 23).
#      Overslaan met HS_SKIP_SIGNER=1.
#   2. aapt2 dump badging/xmltree: pakket nl.icthorse.horsesafe, versionName/versionCode uit
#      version.json, sinds deel 2 (0.3.4) wel INTERNET / USE_BIOMETRIC / CAMERA maar geen
#      REQUEST_INSTALL_PACKAGES / USE_FINGERPRINT / ACCESS_NETWORK_STATE / POST_NOTIFICATIONS,
#      networkSecurityConfig gezet, niet debuggable, allowBackup=false, geen OtpActivity/
#      YubiKeyPromptActivity/CaptureActivity, geen USB-intent-filter, geen provider/service, precies
#      één exported component (MainActivity).
#   3. sha256 van het APK (voor HorseAPK en het rapport).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ANDROID_DIR="$(cd "$HERE/.." && pwd)"
REPO="$(cd "$ANDROID_DIR/.." && pwd)"
APK="${1:-$ANDROID_DIR/app/build/outputs/apk/release/app-release.apk}"
SDK="${ANDROID_HOME:-$HOME/Android/Sdk}"
BT="$(ls -d "$SDK"/build-tools/* 2>/dev/null | sort -V | tail -1)"
APKSIGNER="$BT/apksigner"
AAPT2="$BT/aapt2"
# Eigen release-keystore sinds 0.3.4-Miller (R4); was debug-keystore 32491e0f…3f17.
EXPECTED_SIGNER="fbd6b151ecfd202279d9ee1999b4bfce7f7eb9095b1a0a5bf5338151a64b062e"

fail=0
ok()   { echo "  OK    $*"; }
bad()  { echo "  FOUT  $*"; fail=1; }

[ -f "$APK" ] || { echo "APK niet gevonden: $APK" >&2; exit 2; }
[ -x "$AAPT2" ] && [ -x "$APKSIGNER" ] || { echo "build-tools niet gevonden in $SDK" >&2; exit 2; }

echo "== $APK"
echo "== sha256: $(sha256sum "$APK" | cut -d' ' -f1)"

echo "-- handtekening"
certs="$("$APKSIGNER" verify --print-certs "$APK" 2>&1)" || { bad "apksigner verify faalt"; echo "$certs"; }
digest="$(printf '%s\n' "$certs" | sed -n 's/.*certificate SHA-256 digest: //p' | head -1)"
if [ "${HS_SKIP_SIGNER:-0}" = 1 ]; then
  ok "signer-controle overgeslagen (HS_SKIP_SIGNER=1); signer: $digest"
elif [ "$digest" = "$EXPECTED_SIGNER" ]; then
  ok "signer $digest"
else
  bad "signer $digest != verwacht $EXPECTED_SIGNER"
fi

echo "-- manifest"
badging="$("$AAPT2" dump badging "$APK")"
xml="$("$AAPT2" dump xmltree --file AndroidManifest.xml "$APK")"

want_version="$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["version"]+"-"+d["codename"])' "$REPO/version.json")"
want_code="$(python3 -c 'import json,sys;a=[int(x) for x in json.load(open(sys.argv[1]))["version"].split(".")];print(a[0]*10000+a[1]*100+a[2])' "$REPO/version.json")"
printf '%s\n' "$badging" | grep -q "package: name='nl.icthorse.horsesafe' " && ok "pakket nl.icthorse.horsesafe" || bad "pakketnaam"
printf '%s\n' "$badging" | grep -q "versionCode='$want_code'" && ok "versionCode $want_code" || bad "versionCode != $want_code"
printf '%s\n' "$badging" | grep -q "versionName='$want_version'" && ok "versionName $want_version" || bad "versionName != $want_version"

for p in REQUEST_INSTALL_PACKAGES USE_FINGERPRINT ACCESS_NETWORK_STATE POST_NOTIFICATIONS; do
  if printf '%s\n' "$badging" | grep -q "uses-permission: name='android.permission.$p'"; then bad "permissie $p aanwezig"; else ok "geen $p"; fi
done
for p in INTERNET USE_BIOMETRIC CAMERA; do
  if printf '%s\n' "$badging" | grep -q "uses-permission: name='android.permission.$p'"; then ok "permissie $p (deel 2)"; else bad "permissie $p ontbreekt"; fi
done
if printf '%s\n' "$xml" | grep -qE 'networkSecurityConfig\(0x01010527\)=@0x'; then ok "networkSecurityConfig gezet"; else bad "networkSecurityConfig ontbreekt"; fi
if printf '%s\n' "$badging" | grep -q "application-debuggable"; then bad "debuggable"; else ok "niet debuggable"; fi
if printf '%s\n' "$xml" | grep -qE 'allowBackup\(0x01010280\)=(false|\(type 0x12\)0x0)$'; then ok "allowBackup=false"; else bad "allowBackup niet false"; fi
for n in OtpActivity YubiKeyPromptActivity CaptureActivity USB_DEVICE_ATTACHED NDEF_DISCOVERED TECH_DISCOVERED InitializationProvider ProfileInstallReceiver; do
  if printf '%s\n' "$xml" | grep -q "$n"; then bad "$n in manifest"; else ok "geen $n"; fi
done
for tag in provider service; do
  if printf '%s\n' "$xml" | grep -qE "^\s*E: $tag "; then bad "<$tag> in manifest"; else ok "geen <$tag>"; fi
done
exported="$(printf '%s\n' "$xml" | grep -cE 'exported\(0x01010010\)=(true|\(type 0x12\)0xffffffff)$' || true)"
[ "$exported" = 1 ] && ok "precies één exported component" || bad "$exported exported componenten"

echo
if [ "$fail" = 0 ]; then echo "verify_apk: GROEN"; else echo "verify_apk: ROOD"; fi
exit "$fail"
