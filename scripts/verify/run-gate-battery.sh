#!/bin/sh
# run-gate-battery.sh — run the vault42 verify gates (v01..vNN), fail-fast.
# Mirrors grobase's scripts/verify/run-gate-battery.sh: a bare/-h invocation prints
# help and runs nothing; --fast runs the per-PR subset. Gates are added per phase
# (P2: v01,v02; P3: v07; P4: v03; P7: v04,v05,v06).
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

usage() {
	printf 'usage: %s [--fast|--all|<gate>...]\n' "$0"
	printf '  --fast   per-PR subset (none yet — gates land from P2)\n'
	printf '  --all    every v*-*.sh in version order\n'
	printf '  <gate>   run named gate scripts, e.g. v01-envelope-roundtrip\n'
}

run_one() {
	gate=$1
	script="$here/$gate.sh"
	[ -f "$script" ] || { printf 'MISSING gate: %s\n' "$gate" >&2; return 1; }
	printf '\n=== %s ===\n' "$gate"
	sh "$script"
}

main() {
	[ $# -eq 0 ] && { usage; exit 0; }
	case $1 in
	-h | --help) usage; exit 0 ;;
	--fast | --all)
		set -- $(find "$here" -maxdepth 1 -name 'v*-*.sh' | sort)
		[ $# -eq 0 ] && { printf 'no gates defined yet (land from P2)\n'; exit 0; }
		for g in "$@"; do run_one "$(basename "$g" .sh)"; done
		;;
	*) for g in "$@"; do run_one "$g"; done ;;
	esac
	printf '\nALL GATES PASS\n'
}

main "$@"
