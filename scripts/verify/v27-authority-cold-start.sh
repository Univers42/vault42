# **************************************************************************** #
#                                                                              #
#                                                            :::      :::::::: #
#   v27-authority-cold-start.sh                            :+:      :+:    :+: #
#                                                          +:+ +:+         +:+ #
#   By: dlesieur <dev.pro.photo@gmail.com>                  +#+  +:+       +#+ #
#                                                            +#+#+#+#+#+   +#+ #
#   Created: 2026/06/19 00:00:00 by dlesieur                        #+#    #+# #
#   Updated: 2026/06/19 00:00:00 by dlesieur                 ###   ########.fr #
#                                                                              #
# **************************************************************************** #

#!/bin/sh
# v27-authority-cold-start.sh — prove the authority can start for the first time.
#
# This gate exists because 80e09da made a fresh start impossible and nine green gates said
# nothing. The fail-closed rule it added is right: a database sitting beside a missing signing
# key means contracts were issued by a key that is gone, so minting a replacement would boot
# cleanly and reject every contract ever issued. The defect was ordering. `serve` opened the
# store first, which CREATES the database and runs the migrations, so by the time the key load
# asked "is there a database beside this missing key" the answer was yes — because the process
# had just made one. The check reasoned from evidence it manufactured itself, which makes a
# genuine first start indistinguishable from a lost volume and takes the refusal path always.
#
# Nothing in the battery saw it. Every other authority gate drives the in-process harness, which
# constructs the Authority directly and never runs main; v12 supplies a seed, and a seed takes a
# different branch entirely. So no test ever started the real binary with both files absent —
# the one state every deployment passes through exactly once, and the state a first deploy to
# fly.io is made of.
#
# Three cases, because the fix must not cost the property. A first start with neither file
# present must succeed and mint. A restart with both present must succeed and keep the SAME
# key, since a new one on every boot would be the original catastrophe arriving quietly. A
# start with the database present and the key gone must refuse, and must not leave a key behind
# when it does.
#
# The assertion is the process's own exit status and the key it reports, never a grep for a
# test count.
set -eu

IMAGE="${RUST_TOOLCHAIN_IMG:-mini-baas-rust-toolchain:latest}"
# shellcheck disable=SC1007  # CDPATH= clears CDPATH for this cd only, not a stray assignment
ROOT="$(CDPATH= cd "$(dirname "$0")/../.." && pwd)"

skip() {
	printf 'SKIP v27: %s\n' "$1"
	exit 0
}

# Drive all three cases inside one container: the property is about a real process against a
# real filesystem, so an in-process seam would test a different program.
run_cases() {
	docker run --rm -v "$ROOT":/work -w /work \
		-v vault42-cargo-registry:/usr/local/cargo/registry \
		-v vault42-cargo-git:/usr/local/cargo/git \
		-v vault42-target:/work/target \
		"$IMAGE" sh -c "$(cases_script)"
}

# The body run inside the container. Kept as a here-doc so the quoting stays readable.
cases_script() {
	cat <<'INNER'
set -eu
cargo build -p vault42-authority --locked >/dev/null 2>&1 || exit 70
BIN=./target/debug/vault42-authority
STATE=$(mktemp -d)
DB="$STATE/a.db"; KEY="$STATE/a.key"
export RUST_LOG=info NO_COLOR=1 VAULT42_AUTHORITY_DB="$DB" VAULT42_AUTHORITY_KEY="$KEY"
export VAULT42_AUTHORITY_HOST=127.0.0.1 VAULT42_AUTHORITY_PORT=18444

boot() {
	set +e
	timeout 12 "$BIN" >"$STATE/$1.log" 2>&1
	printf '%s' "$?" >"$STATE/$1.rc"
	set -e
}

key_of() { sed -n '/authority up/p' "$STATE/$1.log" | grep -o '[0-9a-f]\{64\}' | head -1; }

boot first
grep -q 'vault42-authority up' "$STATE/first.log" || { echo "FIRST-START-REFUSED"; cat "$STATE/first.log"; exit 1; }
[ -f "$KEY" ] || { echo "FIRST-START-MINTED-NO-KEY"; exit 1; }
FIRST=$(key_of first)
[ -n "$FIRST" ] || { echo "NO-KEY-REPORTED"; exit 1; }

boot second
grep -q 'vault42-authority up' "$STATE/second.log" || { echo "RESTART-REFUSED"; cat "$STATE/second.log"; exit 1; }
[ "$(key_of second)" = "$FIRST" ] || { echo "RESTART-CHANGED-THE-KEY"; exit 1; }

rm -f "$KEY"
boot lost
[ "$(cat "$STATE/lost.rc")" = "1" ] || { echo "LOST-KEY-DID-NOT-REFUSE rc=$(cat "$STATE/lost.rc")"; exit 1; }
grep -q 'refusing to mint' "$STATE/lost.log" || { echo "REFUSAL-DID-NOT-SAY-WHY"; cat "$STATE/lost.log"; exit 1; }
[ ! -f "$KEY" ] || { echo "REFUSED-BUT-WROTE-A-KEY-ANYWAY"; exit 1; }

rm -rf "$STATE"
INNER
}

main() {
	command -v docker >/dev/null 2>&1 || skip "docker not installed"
	docker image inspect "$IMAGE" >/dev/null 2>&1 || skip "toolchain image $IMAGE absent (run a build first)"
	run_cases || {
		printf 'FAIL v27: the authority cannot cold start, restart cleanly, or refuse a lost key\n'
		exit 1
	}
	printf 'PASS v27: a first start mints, a restart keeps the same key, and a lost key refuses\n'
}

main "$@"
