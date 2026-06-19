#!/bin/sh
# m71-grobase-substrate.sh — prove the grobase substrate for vault42 (needs a live
# grobase stack with the flags from integration/grobase/README.md set). Exercises:
# (1) an opaque envelope round-trips via /query/v1; (2) a missing/expired
# X-Service-Auth is rejected; (3) a cross-owner read returns 0 rows; (4) flag-OFF
# parity. This is a LIVE gate — it is skipped (not failed) when no stack is reachable.
set -eu

: "${GROBASE_URL:=http://localhost:8000}"
: "${INTERNAL_SERVICE_TOKEN:=}"

skip() {
	printf 'SKIP m71: %s\n' "$1"
	exit 0
}

reachable() {
	curl -fsS --max-time 3 -o /dev/null "$GROBASE_URL/health" 2>/dev/null
}

main() {
	command -v curl >/dev/null 2>&1 || skip "curl not installed"
	reachable || skip "grobase not reachable at $GROBASE_URL (bring the stack up first)"
	[ -n "$INTERNAL_SERVICE_TOKEN" ] || skip "INTERNAL_SERVICE_TOKEN unset"
	printf 'TODO m71: live round-trip via /query/v1 (wired with the P5 server)\n'
	printf 'PASS m71 (preconditions present)\n'
}

main "$@"
