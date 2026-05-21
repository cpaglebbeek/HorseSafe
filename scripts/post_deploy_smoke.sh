#!/usr/bin/env bash
# HorseSafe post-deploy smoke-test v0.0.7-Bellare
# Roundtrip: health → register → login → vault → logout

set -uo pipefail

BASE="${1:-https://horsecloud55.ddns.net/HorseSafe/api}"
TS=$(date +%s)
EMAIL="smoke+${TS}@example.com"
PW="SmokeTestPw1234"

echo "═══ HorseSafe smoke-test tegen $BASE ═══"

ok() { echo "✓ $1"; }
fail() { echo "❌ $1"; exit 1; }

# 1. Health
echo "→ /health"
HEALTH=$(curl -fsS "$BASE/health") || fail "/health niet bereikbaar"
echo "  $HEALTH"
echo "$HEALTH" | grep -q '"status":"ok"' || fail "health-respons niet 'ok'"
ok "health"

# 2. Register
echo "→ POST /auth/register ($EMAIL)"
COOKIES=$(mktemp)
RESP=$(curl -fsS -c "$COOKIES" -X POST "$BASE/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PW\",\"ack_data_loss\":true}" ) \
  || fail "register-fout"
echo "  $RESP" | head -c 100; echo
echo "$RESP" | grep -q '"user_id"' || fail "register: geen user_id in response"
ok "register"

# 3. Login
echo "→ POST /auth/login"
RESP=$(curl -fsS -c "$COOKIES" -b "$COOKIES" -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PW\"}" ) \
  || fail "login-fout"
echo "  $RESP"
echo "$RESP" | grep -q '"ok":true' || fail "login: ok-flag ontbreekt"
ok "login (JWT-cookie gezet)"

# 4. Vault-list (verwacht lege array)
echo "→ GET /vault"
RESP=$(curl -fsS -b "$COOKIES" "$BASE/vault") || fail "vault-list-fout"
echo "  $RESP"
echo "$RESP" | grep -q '^\[\]$' || fail "vault-list: niet leeg"
ok "vault-list"

# 5. /auth/me — has_keypair: false (smoke-user heeft nog geen keypair)
echo "→ GET /auth/me"
RESP=$(curl -fsS -b "$COOKIES" "$BASE/auth/me") || fail "/auth/me-fout"
echo "  $RESP" | head -c 200; echo
echo "$RESP" | grep -q '"has_keypair":false' || fail "me: has_keypair-flag ontbreekt"
ok "/auth/me"

# 6. Logout
echo "→ POST /auth/logout"
curl -fsS -b "$COOKIES" -X POST "$BASE/auth/logout" >/dev/null || fail "logout"
ok "logout"

rm -f "$COOKIES"

echo ""
echo "═══ SMOKE-TEST GROEN — $EMAIL geregistreerd + login-flow werkt ═══"
echo "NB: smoke-test-account blijft in DB. Verwijder via:"
echo "  sudo -u horsesafe sqlite3 /opt/horsesafe/db/horsesafe.db \"DELETE FROM users WHERE email='$EMAIL';\""
