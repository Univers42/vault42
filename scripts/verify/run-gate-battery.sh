#!/bin/sh
# run-gate-battery.sh — run the vault42 verify gates (v01..vNN), fail-fast.
# Mirrors grobase's scripts/verify/run-gate-battery.sh: a bare or -h invocation prints
# help and runs nothing.
#
#   --fast    the per-PR subset (FAST_GATES below): docker-only, finishes in seconds
#   --all     every v*-*.sh in version order
#   --strict  a gate that prints SKIP is treated as a FAILURE. Use this in CI, where a
#             missing toolchain image or an unreachable service must not let the battery
#             pass vacuously. Without it a skipped gate is green, which is what let a
#             fresh machine report "ALL GATES PASS" having run nothing.
#   <gate>    run named gate scripts, e.g. v01-server-e2e
#
# Gates are plain POSIX sh and are invoked with `sh`. On a box where /bin/sh is bash a
# bashism in a gate will appear to work; test gates under dash before trusting them.
set -eu

# shellcheck disable=SC1007  # CDPATH= clears CDPATH for this cd only, not a stray assignment
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# The per-PR subset: gates needing only docker plus the toolchain image, no container
# spin-up and no readiness polling. Register a new fast gate here explicitly — the list
# is deliberately manual so a slow gate cannot creep into the PR path by naming alone.
FAST_GATES="v01-server-e2e v16-authority-auth v17-authority-org-model v18-authority-scope-bridge v19-authority-settings-precedence v20-authority-mfa-escrow v25-scope-wrap-bookkeeping v21-authority-parity v26-authority-offboarding v27-authority-cold-start v28-backup-restore-drill"

STRICT=0
MODE=""
NAMED=""

usage() {
	printf 'usage: %s [--fast|--all|<gate>...] [--strict]\n' "$0"
	printf '  --fast    per-PR subset: %s\n' "$FAST_GATES"
	printf '  --all     every v*-*.sh in version order\n'
	printf '  --strict  treat a gate that SKIPs as a failure (for CI)\n'
	printf '  <gate>    run named gate scripts, e.g. v01-server-e2e\n'
	printf '\nnote: m71-grobase-substrate.sh does not match v*-*.sh and only runs when named.\n'
}

# Populate STRICT, MODE and NAMED from the argument list. Exits on -h or a bad option.
parse_args() {
	for arg in "$@"; do
		case $arg in
		-h | --help) usage; exit 0 ;;
		--strict) STRICT=1 ;;
		--fast) MODE=fast ;;
		--all) MODE=all ;;
		-*)
			printf 'unknown option: %s\n' "$arg" >&2
			usage
			exit 2
			;;
		*) NAMED="$NAMED $arg" ;;
		esac
	done
}

# Every versioned gate, in version order, one bare name per line.
all_gates() {
	find "$here" -maxdepth 1 -name 'v*-*.sh' | sort | while read -r path; do
		basename "$path" .sh
	done
}

# Print the gate list implied by MODE and NAMED, one bare name per line.
# shellcheck disable=SC2086  # FAST_GATES and NAMED are gate lists; word splitting is the intent
select_gates() {
	case $MODE in
	all) all_gates ;;
	fast) printf '%s\n' $FAST_GATES ;;
	*) [ -z "$NAMED" ] || printf '%s\n' $NAMED ;;
	esac
}

# Run a gate and report 0 pass, 1 fail, 2 skipped.
#
# Output is buffered in both modes so a SKIP can be SEEN in both. It used to stream unless
# --strict was set, which meant a non-strict run could not tell a skip from a pass and reported
# every gate as passing. With a missing toolchain image that produced "ALL 11 GATES PASS" having
# executed nothing at all — the exact false green --strict exists to prevent, printed by the
# summary line that was supposed to be reassuring.
run_and_classify() {
	log=$(mktemp) || return 1
	if ! sh "$here/$1.sh" >"$log" 2>&1; then
		cat "$log"
		rm -f "$log"
		return 1
	fi
	cat "$log"
	if grep -q '^SKIP' "$log"; then
		rm -f "$log"
		return 2
	fi
	rm -f "$log"
	return 0
}

# Run one gate by bare name. Under --strict a skip becomes a failure.
run_one() {
	if [ ! -f "$here/$1.sh" ]; then
		printf 'MISSING gate: %s\n' "$1" >&2
		return 1
	fi
	printf '\n=== %s ===\n' "$1"
	if run_and_classify "$1"; then outcome=0; else outcome=$?; fi
	if [ "$outcome" -eq 2 ] && [ "$STRICT" -eq 1 ]; then
		printf 'STRICT: %s skipped — counted as FAILURE\n' "$1" >&2
		return 1
	fi
	return "$outcome"
}

# Run every gate in the list, fail-fast, and report what actually ran versus skipped.
run_battery() {
	ran=0
	skipped=0
	for gate in $1; do
		if run_one "$gate"; then outcome=0; else outcome=$?; fi
		case "$outcome" in
		0) ran=$((ran + 1)) ;;
		2) skipped=$((skipped + 1)) ;;
		*)
			printf '\nGATE FAILED: %s\n' "$gate" >&2
			exit 1
			;;
		esac
	done
	report_totals "$ran" "$skipped"
}

# Say what ran. A count of gates that skipped is never folded into the count that passed.
report_totals() {
	if [ "$2" -gt 0 ]; then
		printf '\n%d GATES PASS, %d SKIPPED (prerequisites absent — this is NOT a green run;\n' "$1" "$2"
		printf 'pass --strict to make a skip a failure, which is what CI does)\n'
		return 0
	fi
	if [ "$STRICT" -eq 1 ]; then
		printf '\nALL %d GATES PASS (strict: no skips)\n' "$1"
	else
		printf '\nALL %d GATES PASS\n' "$1"
	fi
}

main() {
	[ $# -eq 0 ] && { usage; exit 0; }
	parse_args "$@"
	gates=$(select_gates)
	if [ -z "$gates" ]; then
		usage
		exit 0
	fi
	run_battery "$gates"
}

main "$@"
