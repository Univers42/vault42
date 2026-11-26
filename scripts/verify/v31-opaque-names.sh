#!/bin/sh
# v31 — the server must not learn a secret's NAME.
#
# The ZK claim covers plaintext, and for a long time that was the whole test: ciphertext on
# disk, nothing readable. But the store keyed every row by the path the user typed, so
# `secrets.path` held `prod/stripe` in the clear — the contents were secret and the names were
# not. This gate is the observation that closes it: drive the REAL client against the REAL
# server, then grep the database the server wrote.
#
# Two assertions, and the positive control is the one that makes the absence mean anything:
#   - `prod/stripe` must NOT appear in the database (nor in its WAL);
#   - `__42ctl/s/` MUST appear, proving rows were written and the scan reads them;
#   - the client must still print the label from `ls`, proving the name is recoverable by the
#     only party entitled to it;
#   - `get` must still return the sentinel, proving the handle round-trips.
#
# Needs 42ctl beside this repo (C42_DIR) because the label lives in the client. Skips cleanly
# when it is absent; run the battery under --strict to turn a skip into a failure.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../.." && pwd)
CTL="${C42_DIR:-$ROOT/../42ctl}"
IMG="${RUST_TOOLCHAIN_IMG:-mini-baas-rust-toolchain:latest}"
NET="v31-net-$$"
SRV="v31-srv-$$"
WORK=$(mktemp -d)

skip() { printf 'SKIP v31: %s\n' "$1"; exit 2; }
fail() { printf 'FAIL v31: %s\n' "$1" >&2; exit 1; }

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
	mkdir -p "$WORK/data"
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

# The client runs as the INVOKING USER so its keystore and state are readable by the host
# assertions; a root-owned keystore is one this script cannot inspect.
client() {
	shift 0
	target=$1
	shift
	docker run --rm --network "$NET" --user "$(id -u):$(id -g)" \
		-v "$target" -v "$WORK/state":/state \
		-e HOME=/state -e FT_PASSPHRASE=v31-name-pass -e FT_CONFIG=/state/config.json \
		-e FT_KEYSTORE=/state/keystore.v42 -e NO_COLOR=1 "$IMG" sh -c "set -e; $*"
}

new_client() {
	# The build wrote into a named volume, so mount that volume here rather than the host's
	# `target/` (which the volume shadows and which would be empty).
	client "42ctl-target:/new" "$@"
}

seed_client() {
	new_client 'B=/new/debug/42ctl; cd /state &&
		$B keys init >/dev/null &&
		$B config endpoint --server http://'"$SRV"':8443 --authority http://unused >/dev/null' \
		>"$WORK/seed.log" 2>&1 || { cat "$WORK/seed.log"; fail "the client could not initialise"; }
}

write_secret() {
	new_client 'B=/new/debug/42ctl; cd /state; printf "sentinel-value-31" | $B vault set prod/stripe' \
		>"$WORK/set.log" 2>&1 || { cat "$WORK/set.log"; fail "42ctl vault set failed"; }
	grep -q 'pushed prod/stripe' "$WORK/set.log" ||
		{ cat "$WORK/set.log"; fail "the client did not report storing the secret"; }
}

assert_the_label_comes_back() {
	new_client 'B=/new/debug/42ctl; cd /state; $B vault get prod/stripe' \
		>"$WORK/get.log" 2>&1 || { cat "$WORK/get.log"; fail "42ctl vault get failed"; }
	[ "$(cat "$WORK/get.log")" = "sentinel-value-31" ] ||
		fail "get returned $(cat "$WORK/get.log"), not the sentinel"
	new_client 'B=/new/debug/42ctl; cd /state; $B vault ls' >"$WORK/ls.log" 2>&1 ||
		{ cat "$WORK/ls.log"; fail "42ctl vault ls failed"; }
	grep -q '^prod/stripe' "$WORK/ls.log" ||
		{ cat "$WORK/ls.log"; fail "ls did not show the label the user typed"; }
}

# The gate proper: the name must be absent from every byte SQLite wrote, and the handle prefix
# must be present so the absence is a measurement of a populated store.
assert_the_name_is_not_on_disk() {
	docker stop "$SRV" >/dev/null 2>&1 || true
	bytes=$(cat "$WORK/data/vault42.db" "$WORK/data/vault42.db-wal" 2>/dev/null | wc -c)
	[ "$bytes" -gt 0 ] || fail "the server wrote no database bytes, so the scan proves nothing"
	if grep -qa 'prod/stripe' "$WORK/data/vault42.db" "$WORK/data/vault42.db-wal" 2>/dev/null; then
		fail "the plaintext name 'prod/stripe' is in the server database"
	fi
	# A UUID suffix, not merely the prefix: `__42ctl/s/index` carries the prefix too, and a
	# control satisfied by the index alone would not prove the SECRET row is there.
	grep -qaE '__42ctl/s/[0-9a-f]{8}-[0-9a-f]{4}-' "$WORK/data/vault42.db" \
		"$WORK/data/vault42.db-wal" 2>/dev/null ||
		fail "positive control: no opaque secret handle in the database, so the scan read nothing"
	printf '  scanned %s bytes: no secret name, handle present\n' "$bytes"
}

main() {
	command -v docker >/dev/null 2>&1 || skip "docker not installed"
	docker image inspect "$IMG" >/dev/null 2>&1 || skip "toolchain image $IMG absent"
	[ -d "$CTL/src" ] || skip "42ctl is not beside this repo (set C42_DIR)"
	mkdir -p "$WORK/state"
	build_server
	build_client
	start_server
	seed_client
	write_secret
	assert_the_label_comes_back
	assert_the_name_is_not_on_disk
	printf 'PASS v31: a real client write leaves an opaque handle, never the secret name\n'
}

main "$@"
