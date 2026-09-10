# **************************************************************************** #
#                                                                              #
#                                                            :::      :::::::: #
#   v29-old-client-compat.sh                               :+:      :+:    :+: #
#                                                          +:+ +:+         +:+ #
#   By: dlesieur <dev.pro.photo@gmail.com>                  +#+  +:+       +#+ #
#                                                            +#+#+#+#+#+   +#+ #
#   Created: 2026/06/19 00:00:00 by dlesieur                        #+#    #+# #
#   Updated: 2026/06/19 00:00:00 by dlesieur                 ###   ########.fr #
#                                                                              #
# **************************************************************************** #

#!/bin/sh
# v29 — can today's client read what an OLDER client wrote?
#
# Every other test in either repository pushes with the binary it just built and pulls with the
# same one, so none of them can see a compatibility regression: they only ever read artefacts
# written by the version under test. No fixture written by an older binary exists anywhere, which
# left the whole story resting on serde defaults that had never met a real old artefact.
#
# This builds one. It checks out 42ctl at a commit whose manifest predates `chunked` and `rev`,
# builds it — pinned to the vault42-core revision of its own day, so the crypto is period-correct
# too — pushes a project with it, and reads that project back with HEAD.
#
# THE POSITIVE CONTROL IS THE WHOLE GATE. An old-compatibility test that quietly used a current
# client would pass forever and prove nothing, so the old worktree is inspected for the fields it
# must NOT have before anything is built. Point OLD_CLIENT_REF at a recent commit and this fails
# rather than going green.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../.." && pwd)
CTL="${C42_DIR:-$ROOT/../42ctl}"
OLD_REF="${OLD_CLIENT_REF:-9d3b203}"
IMG="${RUST_TOOLCHAIN_IMG:-public.ecr.aws/docker/library/rust:1.96-slim-bookworm}"
NET="v29-net-$$"
SRV="v29-srv-$$"
WORK=$(mktemp -d)
OLDDIR="$WORK/oldc"

skip() { printf 'SKIP v29: %s\n' "$1"; exit 2; }
fail() { printf 'FAIL v29: %s\n' "$1" >&2; exit 1; }

# Containers write as root, so the workdir is cleared from a container rather than by this user.
cleanup() {
	docker rm -fv "$SRV" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
	git -C "$CTL" worktree remove --force "$OLDDIR" >/dev/null 2>&1 || true
	docker run --rm -v "$WORK":/w "$IMG" rm -rf /w/oldc /w/state >/dev/null 2>&1 || true
	rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

# The old client must be genuinely old, checked in its source before a single byte is built.
assert_the_old_client_is_old() {
	entry="$OLDDIR/src/core/manifest.rs"
	[ -f "$entry" ] || fail "no manifest.rs at $OLD_REF; the worktree is not a 42ctl checkout"
	if grep -qE '^\s*pub (chunked|rev):' "$entry"; then
		fail "OLD_CLIENT_REF=$OLD_REF already has the fields this gate exists to test reading \
without; it would pass while proving nothing"
	fi
	grep -q '^\s*pub relative_path:' "$entry" ||
		fail "positive control: $OLD_REF has no relative_path either, so it is not a manifest \
this gate can reason about"
	printf '  %s predates chunked and rev, and still has relative_path\n' "$OLD_REF"
}

build_clients() {
	docker run --rm -v "$OLDDIR":/work -w /work \
		-v 42ctl-cargo-registry:/usr/local/cargo/registry \
		-v 42ctl-cargo-git:/usr/local/cargo/git \
		-v "v42-oldclient-$OLD_REF":/work/target "$IMG" \
		cargo build --quiet >"$WORK/old-build.log" 2>&1 ||
		{ tail -20 "$WORK/old-build.log"; fail "the $OLD_REF client did not build"; }
	docker run --rm -v "$CTL":/work -w /work \
		-v 42ctl-cargo-registry:/usr/local/cargo/registry \
		-v 42ctl-cargo-git:/usr/local/cargo/git "$IMG" \
		cargo build --quiet >"$WORK/new-build.log" 2>&1 ||
		{ tail -20 "$WORK/new-build.log"; fail "the current client did not build"; }
	printf '  built the %s client and the current one\n' "$OLD_REF"
}

start_server() {
	docker network create "$NET" >/dev/null 2>&1 || true
	docker run -d --name "$SRV" --network "$NET" -v "$ROOT":/work -w /work \
		-v vault42-cargo-registry:/usr/local/cargo/registry \
		-v vault42-cargo-git:/usr/local/cargo/git -v vault42-target:/work/target \
		-e VAULT42_HOST=0.0.0.0 -e VAULT42_PORT=8443 -e VAULT42_DB=/tmp/v29.db \
		-e RUST_LOG=info -e NO_COLOR=1 "$IMG" \
		sh -c 'cargo run -q --locked --bin vault42-server' >/dev/null
	i=0
	while [ "$i" -lt 900 ]; do
		docker logs "$SRV" 2>&1 | grep -q 'listening' && return 0
		state=$(docker inspect -f '{{.State.Running}}' "$SRV" 2>/dev/null || echo gone)
		[ "$state" = "true" ] || break
		sleep 1
		i=$((i + 1))
	done
	printf '  server did not announce itself; last log lines:\n'
	docker logs "$SRV" 2>&1 | tail -20
	fail "vault42-server never listened (it logs that at INFO, so RUST_LOG must permit it)"
}

# Both clients run against ONE keystore and ONE project directory on the host, because the
# question is what a single operator's project looks like across an upgrade — not what two
# different identities can do.
client() {
	bin_mount="$1"
	bin_path="$2"
	shift 2
	docker run --rm --network "$NET" -v "$bin_mount" -v "$WORK/state":/state \
		-e FT_PASSPHRASE=v29-compat-pass -e FT_CONFIG=/state/config.json \
		-e FT_KEYSTORE=/state/keystore.v42 "$IMG" sh -c "set -e; B=$bin_path; $*"
}

old_client() {
	client "v42-oldclient-$OLD_REF:/old" /old/debug/42ctl "$@"
}

new_client() {
	client "$CTL/target:/new" /new/debug/42ctl "$@"
}

# A project shaped like Inception: configuration in srcs/.env, credentials under secrets/.
#
# The old client scans only *.env* and *.secrets, so it will push the env files and skip the
# credentials — which is the defect fixed in bd7f87e and is exactly the shape of a project that
# predates it. Both halves matter here: what it wrote must still be readable, and what it missed
# must be pushable afterwards without disturbing what it wrote.
seed_project() {
	mkdir -p "$WORK/state/proj/srcs" "$WORK/state/proj/secrets" "$WORK/state/restored"
	printf 'DOMAIN_NAME=compat.42.fr\nMYSQL_USER=wpuser\n' >"$WORK/state/proj/srcs/.env"
	printf 'API_TOKEN=old-client-sentinel-7712\n' >"$WORK/state/proj/.env"
	for f in db_password.txt server.key; do
		printf 'compat-secret-%s\n' "${f%.*}" >"$WORK/state/proj/secrets/$f"
	done
	chmod 600 "$WORK/state/proj/secrets/server.key"
	cp "$WORK/state/proj/srcs/.env" "$WORK/expect-srcs-env"
	cp "$WORK/state/proj/.env" "$WORK/expect-root-env"
}

push_with_the_old_client() {
	old_client 'cd /state/proj && $B keys init >/dev/null &&
		$B config endpoint --server http://'"$SRV"':8443 --authority http://unused >/dev/null &&
		$B push --project compat' >"$WORK/old-push.log" 2>&1 ||
		{ cat "$WORK/old-push.log"; fail "the $OLD_REF client could not push"; }
	grep -q 'pushed' "$WORK/old-push.log" ||
		{ cat "$WORK/old-push.log"; fail "the old client reported no push"; }
	printf '  %s pushed: %s\n' "$OLD_REF" "$(grep -o 'pushed [0-9]* file(s)' "$WORK/old-push.log")"
}

# The wipe is an assertion. Without it every comparison below would pass against files that were
# never removed, and the run would report a successful restore having restored nothing.
wipe_the_working_copy() {
	docker run --rm -v "$WORK/state":/state "$IMG" \
		sh -c 'rm -f /state/proj/srcs/.env /state/proj/.env' >/dev/null
	[ ! -e "$WORK/state/proj/srcs/.env" ] || fail "the wipe left srcs/.env behind"
	[ ! -e "$WORK/state/proj/.env" ] || fail "the wipe left the root .env behind"
	printf '  the working copy of both env files is gone\n'
}

pull_with_the_current_client() {
	new_client 'cd /state/proj && $B pull --project compat --apply' \
		>"$WORK/new-pull.log" 2>&1 ||
		{ cat "$WORK/new-pull.log"; fail "the current client could not read the old project"; }
	for pair in "srcs/.env:expect-srcs-env" ".env:expect-root-env"; do
		got="$WORK/state/proj/${pair%%:*}"
		want="$WORK/${pair##*:}"
		[ -f "$got" ] || fail "${pair%%:*} was never restored from the old client's manifest"
		cmp -s "$want" "$got" || fail "${pair%%:*} came back with different bytes"
	done
	printf '  the current client read the %s manifest byte-exactly\n' "$OLD_REF"
}

# The upgrade path: a project written by an old client must accept a push from a new one, and the
# new one must pick up what the old scanner could not see.
assert_the_project_upgrades_in_place() {
	new_client 'cd /state/proj && $B push --project compat' >"$WORK/new-push.log" 2>&1 ||
		{ cat "$WORK/new-push.log"; fail "the current client could not push over an old project"; }
	docker run --rm -v "$WORK/state":/state "$IMG" sh -c 'rm -rf /state/proj/secrets' >/dev/null
	[ ! -d "$WORK/state/proj/secrets" ] || fail "the second wipe left secrets/ behind"
	new_client 'cd /state/proj && $B pull --project compat --apply' \
		>"$WORK/new-pull2.log" 2>&1 ||
		{ cat "$WORK/new-pull2.log"; fail "the upgraded project would not pull"; }
	for f in db_password.txt server.key; do
		[ -f "$WORK/state/proj/secrets/$f" ] ||
			fail "secrets/$f is still missing after the current client pushed it"
	done
	mode=$(stat -c %a "$WORK/state/proj/secrets/server.key")
	[ "$mode" = "600" ] || fail "the restored private key is $mode, not 600"
	printf '  the old project took a new push, and secrets/ arrived at mode 600\n'
}

main() {
	command -v docker >/dev/null 2>&1 || skip "docker not installed"
	command -v git >/dev/null 2>&1 || skip "git not installed"
	docker image inspect "$IMG" >/dev/null 2>&1 || skip "toolchain image $IMG absent"
	[ -d "$CTL/.git" ] || skip "42ctl is not beside this repo (set C42_DIR)"
	git -C "$CTL" cat-file -e "$OLD_REF^{commit}" 2>/dev/null ||
		skip "42ctl has no commit $OLD_REF (shallow clone?)"
	git -C "$CTL" worktree add --detach "$OLDDIR" "$OLD_REF" >/dev/null 2>&1 ||
		fail "could not check out $OLD_REF"
	assert_the_old_client_is_old
	build_clients
	start_server
	seed_project
	push_with_the_old_client
	wipe_the_working_copy
	pull_with_the_current_client
	assert_the_project_upgrades_in_place
	printf 'PASS v29: a project written by the %s client is read byte-exactly by HEAD, and upgrades\n' "$OLD_REF"
}

main "$@"
