# **************************************************************************** #
#                                                                              #
#                                                            :::      :::::::: #
#   post-deploy.sh                                         :+:      :+:    :+: #
#                                                          +:+ +:+         +:+ #
#   By: dlesieur <dev.pro.photo@gmail.com>                  +#+  +:+       +#+ #
#                                                            +#+#+#+#+#+   +#+ #
#   Created: 2026/06/19 00:00:00 by dlesieur                        #+#    #+# #
#   Updated: 2026/06/19 00:00:00 by dlesieur                 ###   ########.fr #
#                                                                              #
# **************************************************************************** #

#!/bin/sh
# Post-deploy smoke test against a LIVE fly.io deployment.
#
# DELIBERATELY NOT A GATE under scripts/verify/. Gates are hermetic: they build and drive
# containers on the machine running them, so `run-gate-battery.sh --all --strict` is free,
# offline-reproducible, and safe to run on every push. This probes deployed infrastructure
# instead, and every run WAKES a scale-to-zero machine. Adding it to the battery would bill
# the operator for each `git push` and would make the battery red whenever the network is
# down, which is not a statement about the code.
#
# It asserts what a deploy can plausibly get wrong and a local gate cannot see: the volume
# mounted, the signing key survived, the secrets reached the VM, and the fly proxy speaks
# HTTP/2 to a tonic backend.
set -eu

AUTHORITY="${AUTHORITY_URL:-https://vault42-authority.fly.dev}"
SERVER="${SERVER_URL:-https://vault42-server.fly.dev}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { printf 'FAIL smoke: %s\n' "$1" >&2; exit 1; }

# A scale-to-zero machine cold-starts on the first request, so the first probe is allowed to
# be slow. Retrying here rather than raising every timeout keeps a genuinely dead app fast to
# diagnose instead of hanging for a minute per check.
wake() {
	attempt=1
	while [ "$attempt" -le 6 ]; do
		if curl -fsS --max-time 20 "$AUTHORITY/healthz" >"$WORK/health" 2>/dev/null; then
			return 0
		fi
		printf 'wake attempt %s did not answer; retrying\n' "$attempt"
		sleep 5
		attempt=$((attempt + 1))
	done
	fail "$AUTHORITY/healthz never answered; the app is down or the volume failed to mount"
}

# The authority refuses to start when it finds a database beside a missing signing key, so a
# healthy /healthz already proves the volume mounted and carried the key across the deploy.
assert_authority_is_healthy() {
	wake
	[ "$(cat "$WORK/health")" = "ok" ] ||
		fail "/healthz answered $(cat "$WORK/health"), not ok"
	printf 'ok  authority healthy (volume mounted, signing key intact)\n'
}

# The key must be 64 lowercase hex. An empty or truncated answer is the exact failure the
# runbook's `curl | fly secrets set` recipe used to turn into a server that accepted any
# self-generated keypair, so this checks the shape rather than merely that a request answered.
assert_contract_key_is_usable() {
	curl -fsS --max-time 20 "$AUTHORITY/v1/contract-key" >"$WORK/key.json" ||
		fail "/v1/contract-key did not answer"
	key="$(sed 's/.*"public_key":"//;s/".*//' <"$WORK/key.json")"
	[ "${#key}" -eq 64 ] || fail "contract key is ${#key} chars, not 64: refusing to call this up"
	case "$key" in
		*[!0-9a-f]*) fail "contract key is not lowercase hex" ;;
	esac
	printf 'ok  contract key is 64 hex chars\n'
}

# An unauthenticated protected route must answer 401. A 404 would mean the route vanished, a
# 500 that the store is broken, and a 200 that the Bearer guard is not running in production.
assert_authority_guard_is_live() {
	status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$AUTHORITY/v1/auth/me")"
	[ "$status" = "401" ] ||
		fail "GET /v1/auth/me answered $status, not 401; the Bearer guard is not live"
	printf 'ok  authority rejects an unauthenticated request with 401\n'
}

# gRPC over the fly edge: TLS terminated at the proxy, h2c to tonic. A proxy that fell back to
# HTTP/1.1 returns 502 with an HTML body, so asserting the gRPC content-type proves the
# h2_backend setting survived the deploy.
#
# The frame is a well-formed empty gRPC message: one compression byte plus a four-byte length
# of zero. It comes from a file because a shell cannot pass NUL bytes as an argument, and an
# argument silently truncated at the first NUL would make the server answer "missing request
# message" — a different error that would still look like a live server.
assert_server_speaks_grpc() {
	printf '\000\000\000\000\000' >"$WORK/frame.bin"
	[ "$(wc -c <"$WORK/frame.bin" | tr -d ' ')" = "5" ] ||
		fail "the probe frame is not 5 bytes; this check would prove nothing"
	curl -sS -o /dev/null -D "$WORK/head" --http2 --max-time 30 \
		-X POST "$SERVER/vault.v1.Vault/Whoami" \
		-H 'content-type: application/grpc' -H 'te: trailers' \
		--data-binary "@$WORK/frame.bin" ||
		fail "$SERVER did not answer a gRPC request"
	grep -qi '^content-type: application/grpc' "$WORK/head" ||
		fail "the server answered without a gRPC content-type; the fly proxy is not speaking h2c"
	printf 'ok  server speaks gRPC through the fly edge\n'
}

# UNAUTHENTICATED (16), not UNIMPLEMENTED (12) and not a proxy error. This distinguishes a
# server whose auth interceptor is running from one that would serve the vault to anyone.
assert_server_requires_auth() {
	code="$(sed -n 's/^[Gg]rpc-[Ss]tatus: *//p' "$WORK/head" | tr -d '\r')"
	[ "$code" = "16" ] ||
		fail "unauthenticated Whoami answered grpc-status $code, expected 16 UNAUTHENTICATED"
	printf 'ok  server rejects an unauthenticated call with UNAUTHENTICATED\n'
}

main() {
	printf 'smoke: authority=%s server=%s\n' "$AUTHORITY" "$SERVER"
	assert_authority_is_healthy
	assert_contract_key_is_usable
	assert_authority_guard_is_live
	assert_server_speaks_grpc
	assert_server_requires_auth
	printf 'PASS smoke: both apps are live, hold their state, and refuse unauthenticated callers\n'
}

main "$@"
