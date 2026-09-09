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
FAST_GATES="v01-server-e2e v16-authority-auth"

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

# Run a gate, buffering output so a SKIP can be promoted to a failure under --strict.
run_strict() {
	log=$(mktemp) || return 1
	if sh "$here/$1.sh" >"$log" 2>&1; then
		cat "$log"
		if grep -q '^SKIP' "$log"; then
			rm -f "$log"
			printf 'STRICT: %s skipped — counted as FAILURE\n' "$1" >&2
			return 1
		fi
		rm -f "$log"
		return 0
	fi
	cat "$log"
	rm -f "$log"
	return 1
}

# Run one gate by bare name. Streams live unless --strict needs the output buffered.
run_one() {
	if [ ! -f "$here/$1.sh" ]; then
		printf 'MISSING gate: %s\n' "$1" >&2
		return 1
	fi
	printf '\n=== %s ===\n' "$1"
	if [ "$STRICT" -eq 0 ]; then
		if sh "$here/$1.sh"; then return 0; else return 1; fi
	fi
	run_strict "$1"
}

# Run every gate in the list, fail-fast, and report how many actually ran.
run_battery() {
	ran=0
	for gate in $1; do
		run_one "$gate" || {
			printf '\nGATE FAILED: %s\n' "$gate" >&2
			exit 1
		}
		ran=$((ran + 1))
	done
	if [ "$STRICT" -eq 1 ]; then
		printf '\nALL %d GATES PASS (strict: no skips)\n' "$ran"
	else
		printf '\nALL %d GATES PASS\n' "$ran"
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
