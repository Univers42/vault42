#!/usr/bin/env bash
# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    v12-otp-login.sh                                   :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: dlesieur <dev.pro.photo@gmail.com>         +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2026/06/21 00:00:00 by dlesieur          #+#    #+#              #
#    Updated: 2026/06/21 00:00:00 by dlesieur         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #
#
# V12 — the email-OTP is ENFORCED at the contract authority (gap repair). With
# VAULT42_CONTRACT_REQUIRE_OTP=true the authority's /v1/register requires a valid
# grobase OTP proof (HS256 over the shared GOTRUE_JWT_SECRET, aud=otp-proof, otp==email,
# unexpired) before issuing a contract — so the OTP is a server-side login gate, not a
# client-only step. Flag-off ⇒ register works without a proof (byte-parity).
#
# ISOLATED: runs the vault42-contract authority FROM CURRENT source (cargo, cached) on
# a published loopback port, names suffixed $$, EXIT-trap cleanup. No external services.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WS="$(cd "${SCRIPT_DIR}/../.." && pwd)"
IMG="${V12_IMG:-mini-baas-rust-toolchain:latest}"
VV="-v vault42-cargo-registry:/usr/local/cargo/registry -v vault42-cargo-git:/usr/local/cargo/git"
ON="v12-on-$$"; OFF="v12-off-$$"; PORT_ON=19190; PORT_OFF=19191
SECRET="v12-shared-gotrue-secret-$$"
SEED="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
# An RFC 8032 valid ed25519 public key (parse_fp requires a real key).
PUB="d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
EMAIL="dev@grobase.test"

green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
red() { printf '\033[0;31m%s\033[0m\n' "$*"; }
ok() { green "  ✓ $*"; }
fail() { red "[V12] FAIL — $*"; exit 1; }
cleanup() { docker rm -fv "$ON" "$OFF" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# Mint an HS256 OTP proof. $1=email $2=aud $3=exp-offset-secs $4(optional)=tamper
mint() {
  V12_EMAIL="$1" V12_AUD="$2" V12_OFF="$3" V12_SECRET="$SECRET" V12_TAMPER="${4:-}" python3 - <<'PY'
import os, json, time, hmac, hashlib, base64
b = lambda x: base64.urlsafe_b64encode(x).rstrip(b'=').decode()
h = b(json.dumps({"alg":"HS256","typ":"JWT"},separators=(',',':')).encode())
exp = int(time.time()) + int(os.environ["V12_OFF"])
p = b(json.dumps({"otp":os.environ["V12_EMAIL"],"aud":os.environ["V12_AUD"],"exp":exp},separators=(',',':')).encode())
sig = b(hmac.new(os.environ["V12_SECRET"].encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
if os.environ.get("V12_TAMPER"): sig = sig[:-2] + ("AA" if sig[-2:] != "AA" else "BB")
print(f"{h}.{p}.{sig}")
PY
}

# register against a port; $1=port $2=tenant $3=json-body → echoes HTTP code
reg() { curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$1/v1/register" -H 'Content-Type: application/json' -d "$3"; }

# Wait on the real HTTP /healthz (docker-proxy accepts TCP before the app binds, so a
# bare TCP probe false-positives). $1=container $2=port
wait_http() { local i; for i in $(seq 1 240); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$2/healthz" 2>/dev/null)" = 200 ] && return 0; docker inspect "$1" >/dev/null 2>&1 || { docker logs "$1" 2>&1 | tail -15; return 1; }; sleep 1; done; docker logs "$1" 2>&1 | tail -15; return 1; }

echo "[V12] 1/4 start vault42-contract with REQUIRE_OTP (cargo, cached debug)…"
docker run -d --name "$ON" -v "$WS":/work -w /work $VV \
  -e VAULT42_CONTRACT_REQUIRE_OTP=true -e GOTRUE_JWT_SECRET="$SECRET" \
  -e VAULT42_CONTRACT_SEED="$SEED" -e VAULT42_CONTRACT_DB=/tmp/c-on.db \
  -e VAULT42_CONTRACT_PORT=8443 -e RUST_LOG=warn -p "127.0.0.1:$PORT_ON:8443" \
  "$IMG" sh -c 'cargo run --quiet --bin vault42-contract' >/dev/null
wait_http "$ON" "$PORT_ON" || fail "REQUIRE_OTP authority never listened"
ok "authority up (VAULT42_CONTRACT_REQUIRE_OTP=true)"

echo "[V12] 2/4 valid proof → register 200; missing proof → 401"
GOOD="$(mint "$EMAIL" otp-proof 300)"
C="$(reg "$PORT_ON" t-good "{\"tenant\":\"v12good$$\",\"author_pubkey\":\"$PUB\",\"email\":\"$EMAIL\",\"otp_proof\":\"$GOOD\"}")"
[ "$C" = 200 ] || fail "valid proof expected 200, got $C"
ok "valid OTP proof → register 200 (contract issued)"
C="$(reg "$PORT_ON" t-noproof "{\"tenant\":\"v12noproof$$\",\"author_pubkey\":\"$PUB\"}")"
[ "$C" = 401 ] || fail "missing proof expected 401, got $C"
ok "missing proof → 401 (OTP enforced server-side)"

echo "[V12] 3/4 wrong-email · tampered · expired proofs → 401"
WRONG="$(mint "someone-else@grobase.test" otp-proof 300)"
[ "$(reg "$PORT_ON" t-wrongmail "{\"tenant\":\"v12wm$$\",\"author_pubkey\":\"$PUB\",\"email\":\"$EMAIL\",\"otp_proof\":\"$WRONG\"}")" = 401 ] || fail "wrong-email proof not rejected"
TAMP="$(mint "$EMAIL" otp-proof 300 tamper)"
[ "$(reg "$PORT_ON" t-tamper "{\"tenant\":\"v12tp$$\",\"author_pubkey\":\"$PUB\",\"email\":\"$EMAIL\",\"otp_proof\":\"$TAMP\"}")" = 401 ] || fail "tampered-sig proof not rejected"
EXP="$(mint "$EMAIL" otp-proof -600)"
[ "$(reg "$PORT_ON" t-exp "{\"tenant\":\"v12ex$$\",\"author_pubkey\":\"$PUB\",\"email\":\"$EMAIL\",\"otp_proof\":\"$EXP\"}")" = 401 ] || fail "expired proof not rejected"
ok "wrong-email · tampered-signature · expired → all 401"

echo "[V12] 4/4 flag OFF → register works WITHOUT a proof (byte-parity)"
docker run -d --name "$OFF" -v "$WS":/work -w /work $VV \
  -e VAULT42_CONTRACT_SEED="$SEED" -e VAULT42_CONTRACT_DB=/tmp/c-off.db \
  -e VAULT42_CONTRACT_PORT=8443 -e RUST_LOG=warn -p "127.0.0.1:$PORT_OFF:8443" \
  "$IMG" sh -c 'cargo run --quiet --bin vault42-contract' >/dev/null
wait_http "$OFF" "$PORT_OFF" || fail "flag-off authority never listened"
C="$(reg "$PORT_OFF" t-off "{\"tenant\":\"v12off$$\",\"author_pubkey\":\"$PUB\"}")"
[ "$C" = 200 ] || fail "flag-off register without proof expected 200, got $C"
ok "flag OFF (default) → register without a proof → 200 (byte-parity)"

green "[V12] ALL GATES GREEN — OTP enforced at the contract authority (valid→200, missing/wrong/tampered/expired→401, flag-off→200)"
exit 0
