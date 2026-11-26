#!/bin/sh
# v32 — a server that answers "latest" with an OLD revision must be caught.
#
# Every other anti-rollback check in the tree is stateless and cannot see this: the transport
# label agrees with the revision signed inside the envelope (the server picked both from the
# same old row), the secret id matches (it is the same secret), the signature verifies, and an
# explicit `get --version N` is asking for history anyway. So a client with no memory reads
# revision 1 and believes it is current, while revision 2 sits on the server.
#
# The attack is not simulated here. The gate rewinds the SERVER: it snapshots the database
# after revision 1, writes revision 2, then puts the snapshot back — exactly what a restore, or
# a host that kept an old copy, does. What is under test is the client's own record of the
# highest revision it has accepted.
#
# Assertions, each with the control that gives it meaning:
#   1. before the rewind, `get` returns revision 2 (the client really is current, so a later
#      refusal is not a client that cannot read);
#   2. after the rewind, `get` FAILS and says "rollback";
#   3. with FT_ACCEPT_ROLLBACK=1 it succeeds and returns revision 1's value — the restore path
#      an operator needs, which is why this is an override rather than a brick;
#   4. a second `get` without the override succeeds, because the accepted revision moved the
#      pin rather than leaving it refusing forever.
#
# Needs 42ctl beside this repo (C42_DIR). Skips when absent; run the battery with --strict to
# turn a skip into a failure.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../.." && pwd)
CTL="${C42_DIR:-$ROOT/../42ctl}"
IMG="${RUST_TOOLCHAIN_IMG:-mini-baas-rust-toolchain:latest}"
NET="v32-net-$$"
SRV="v32-srv-$$"
WORK=$(mktemp -d)

skip() { printf 'SKIP v32: %s\n' "$1"; exit 2; }
fail() { printf 'FAIL v32: %s\n' "$1" >&2; exit 1; }

cleanup() {
	docker rm -fv "$SRV" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
	rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

build_server() {
	docker run --rm -v "$ROOT":/work -w /work \
		-v vault42-cargo-registry:/usr/local/cargo/registry \
		-v vault42-cargo-git:/usr/local/cargo/git -v vault42-target:/work/target \
		"$IMG" cargo build --quiet --bin vault42-server >"$WORK/server-build.log" 2>&1 ||
		{ tail -20 "$WORK/server-build.log"; fail "vault42-server did not build"; }
}

build_client() {
	docker run --rm -v "$CTL":/work -w /work \
		-v 42ctl-cargo-registry:/usr/local/cargo/registry \
		-v 42ctl-cargo-git:/usr/local/cargo/git -v 42ctl-target:/work/target \
		"$IMG" cargo build --quiet >"$WORK/client-build.log" 2>&1 ||
		{ tail -20 "$WORK/client-build.log"; fail "42ctl did not build"; }
}

start_server() {
	docker network create "$NET" >/dev/null 2>&1 || true
	docker run -d --name "$SRV" --network "$NET" -v "$ROOT":/work -w /work \
		-v vault42-cargo-registry:/usr/local/cargo/registry \
		-v vault42-cargo-git:/usr/local/cargo/git -v vault42-target:/work/target \
		-v "$WORK/data":/data \
		-e VAULT42_ALLOW_UNGATED=1 -e VAULT42_HOST=0.0.0.0 -e VAULT42_PORT=8443 \
		-e VAULT42_DB=/data/vault42.db -e RUST_LOG=info "$IMG" \
		sh -c './target/debug/vault42-server' >/dev/null
	i=0
	while [ "$i" -lt 120 ]; do
		docker logs "$SRV" 2>&1 | grep -q 'listening' && return 0
		docker inspect -f '{{.State.Running}}' "$SRV" 2>/dev/null | grep -q true || break
		sleep 1
		i=$((i + 1))
	done
	docker logs "$SRV" 2>&1 | tail -20
	fail "vault42-server never listened"
}

# The database belongs to the server container (root), so the snapshot is taken and put back
# from a container with the same mount rather than from the host, which may not write it.
# The WAL is part of the state: `docker stop` does not guarantee a checkpoint, so a snapshot
# of the .db alone can be older than the write it is supposed to contain (that version of this
# gate restored a state that had no row at all and read it as `NotFound`).
snapshot_db() {
	docker run --rm -v "$WORK/data":/data "$IMG" sh -c '
		cp /data/vault42.db /data/revision-1.db
		[ ! -f /data/vault42.db-wal ] || cp /data/vault42.db-wal /data/revision-1.db-wal
	' >/dev/null 2>&1 || fail "could not snapshot the database"
}

restore_db() {
	docker run --rm -v "$WORK/data":/data "$IMG" sh -c '
		rm -f /data/vault42.db-wal /data/vault42.db-shm
		cp /data/revision-1.db /data/vault42.db
		[ ! -f /data/revision-1.db-wal ] || cp /data/revision-1.db-wal /data/vault42.db-wal
	' >/dev/null 2>&1 || fail "could not restore the older database"
}

# Stopping the only connection checkpoints the WAL, so the .db on its own is the whole state —
# which is what makes the snapshot below a faithful older revision and not a torn copy.
stop_server() {
	docker stop "$SRV" >/dev/null 2>&1 || true
	docker rm -fv "$SRV" >/dev/null 2>&1 || true
}

# The client runs as the INVOKING USER so its state directory (the pins under test) stays
# readable by the host assertions.
new_client() {
	docker run --rm --network "$NET" --user "$(id -u):$(id -g)" \
		-v "42ctl-target:/new" -v "$WORK/state":/state \
		-e HOME=/state -e FT_PASSPHRASE=v32-rollback-pass -e FT_CONFIG=/state/config.json \
		-e FT_KEYSTORE=/state/keystore.v42 -e NO_COLOR=1 "$IMG" sh -c "set -e; $*"
}

seed_client() {
	new_client 'B=/new/debug/42ctl; cd /state &&
		$B keys init >/dev/null &&
		$B config endpoint --server http://'"$SRV"':8443 --authority http://unused >/dev/null' \
		>"$WORK/seed.log" 2>&1 || { cat "$WORK/seed.log"; fail "the client could not initialise"; }
}

write_secret() {
	new_client 'B=/new/debug/42ctl; cd /state; printf "'"$1"'" | $B vault set rollback/probe' \
		>"$WORK/set-$2.log" 2>&1 || { cat "$WORK/set-$2.log"; fail "42ctl vault set failed"; }
}

# Read the secret; the caller decides whether the exit status is a pass.
read_secret() {
	new_client 'B=/new/debug/42ctl; cd /state; $B vault get rollback/probe'
}

assert_revision_two_is_current() {
	[ "$(read_secret)" = "second-value" ] ||
		fail "before the rewind, get did not return the newest value"
	printf '  before the rewind: get returned revision 2\n'
}

assert_the_rewind_is_refused() {
	if read_secret >"$WORK/rewound.log" 2>&1; then
		cat "$WORK/rewound.log"
		fail "the client accepted the restored revision 1 as current — the rollback went unnoticed"
	fi
	grep -qi 'rollback' "$WORK/rewound.log" ||
		{ cat "$WORK/rewound.log"; fail "get failed, but not with a rollback refusal"; }
	printf '  after the rewind: get refused, naming the rollback\n'
}

assert_the_override_is_the_restore_path() {
	value=$(new_client 'B=/new/debug/42ctl; cd /state; FT_ACCEPT_ROLLBACK=1 $B vault get rollback/probe') ||
		fail "FT_ACCEPT_ROLLBACK=1 did not restore access"
	[ "$value" = "first-value" ] || fail "the accepted restore returned '$value', not revision 1"
	printf '  the override accepted the restore and lowered the pin\n'
}

# The pin moved to what was accepted, so ordinary reads work again. A version that stayed
# pinned at 2 would refuse revision 1 forever, which is the brick this must not be.
assert_reads_work_again() {
	value=$(read_secret) || fail "a plain get still refuses after the accepted restore"
	[ "$value" = "first-value" ] || fail "a plain get returned '$value' after the restore"
	printf '  plain reads work again after the restore\n'
}

main() {
	command -v docker >/dev/null 2>&1 || skip "docker not installed"
	docker image inspect "$IMG" >/dev/null 2>&1 || skip "toolchain image $IMG absent"
	[ -d "$CTL/src" ] || skip "42ctl is not beside this repo (set C42_DIR)"
	mkdir -p "$WORK/state" "$WORK/data"
	build_server
	build_client
	start_server
	seed_client
	write_secret "first-value" 1
	# Snapshot the state that holds revision 1 and nothing else.
	stop_server
	[ -s "$WORK/data/vault42.db" ] || fail "the server wrote no database, so there is nothing to restore"
	snapshot_db
	start_server
	write_secret "second-value" 2
	assert_revision_two_is_current
	# The rewind: put the older state back, exactly as a restore would.
	stop_server
	restore_db
	start_server
	assert_the_rewind_is_refused
	assert_the_override_is_the_restore_path
	assert_reads_work_again
	printf 'PASS v32: a restored older revision is refused as a rollback, and the override is the restore path\n'
}

main "$@"
