# **************************************************************************** #
#                                                                              #
#                                                            :::      :::::::: #
#   v30-project-isolation.sh                               :+:      :+:    :+: #
#                                                          +:+ +:+         +:+ #
#   By: dlesieur <dev.pro.photo@gmail.com>                  +#+  +:+       +#+ #
#                                                            +#+#+#+#+#+   +#+ #
#   Created: 2026/06/19 00:00:00 by dlesieur                        #+#    #+# #
#   Updated: 2026/06/19 00:00:00 by dlesieur                 ###   ########.fr #
#                                                                              #
# **************************************************************************** #

#!/bin/sh
# v30 — many projects, one owner, and nested credentials.
#
# The question this answers is the one an operator asks before putting a second repository in:
# if two projects have the same file laid out at the same relative path, does one overwrite the
# other? The derivation says no — a blob's id is `secret_id(principal, "{project_id}/{rel}")` and
# its server path carries the project id as well — but that is an argument, and an argument is not
# a test.
#
# It also covers what a submodule looks like from the outside: a nested directory with its OWN
# secrets/, which is the shape of every project our operator described putting in here.
#
# The nested module sits under modules/ rather than vendor/ on purpose. A directory named vendor
# is in the client's dependency skip list, so a submodule parked there is dropped and the push
# still reports success — a real defect, tracked as R25, and not something this gate should freeze
# by asserting today's behaviour.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../.." && pwd)
CTL="${C42_DIR:-$ROOT/../42ctl}"
IMG="${RUST_TOOLCHAIN_IMG:-public.ecr.aws/docker/library/rust:1.96-slim-bookworm}"
NET="v30-net-$$"
SRV="v30-srv-$$"
WORK=$(mktemp -d)

skip() { printf 'SKIP v30: %s\n' "$1"; exit 2; }
fail() { printf 'FAIL v30: %s\n' "$1" >&2; exit 1; }

cleanup() {
	docker rm -fv "$SRV" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
	docker run --rm -v "$WORK":/w "$IMG" rm -rf /w/state >/dev/null 2>&1 || true
	rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

start_server() {
	docker network create "$NET" >/dev/null 2>&1 || true
	docker run -d --name "$SRV" --network "$NET" -v "$ROOT":/work -w /work \
		-v vault42-cargo-registry:/usr/local/cargo/registry \
		-v vault42-cargo-git:/usr/local/cargo/git -v vault42-target:/work/target \
		-e VAULT42_ALLOW_UNGATED=1 \
		-e VAULT42_HOST=0.0.0.0 -e VAULT42_PORT=8443 -e VAULT42_DB=/tmp/v30.db \
		-e RUST_LOG=info -e NO_COLOR=1 "$IMG" \
		sh -c 'cargo run -q --locked --bin vault42-server' >/dev/null
	i=0
	while [ "$i" -lt 900 ]; do
		docker logs "$SRV" 2>&1 | grep -q 'listening' && return 0
		[ "$(docker inspect -f '{{.State.Running}}' "$SRV" 2>/dev/null || echo gone)" = "true" ] || break
		sleep 1
		i=$((i + 1))
	done
	docker logs "$SRV" 2>&1 | tail -20
	fail "vault42-server never listened"
}

client() {
	docker run --rm --network "$NET" -v "$CTL/target":/c -v "$WORK/state":/state \
		-e FT_PASSPHRASE=v30-isolation-pass -e FT_CONFIG=/state/config.json \
		-e FT_KEYSTORE=/state/keystore.v42 "$IMG" sh -c "set -e; B=/c/debug/42ctl; $*"
}

# Two projects, same relative paths, different bytes. A submodule-shaped nested directory with its
# own secrets/ lives inside the first, because that is the layout our operator described.
seed_projects() {
	for p in alpha beta; do
		mkdir -p "$WORK/state/$p/srcs" "$WORK/state/$p/secrets" "$WORK/state/pull-$p"
		printf 'DOMAIN_NAME=%s.42.fr\n' "$p" >"$WORK/state/$p/srcs/.env"
		printf 'db-password-for-%s\n' "$p" >"$WORK/state/$p/secrets/db_password.txt"
	done
	mkdir -p "$WORK/state/alpha/modules/inner/secrets"
	printf 'INNER=submodule-of-alpha\n' >"$WORK/state/alpha/modules/inner/.env"
	printf 'inner-key-material\n' >"$WORK/state/alpha/modules/inner/secrets/server.key"
	chmod 600 "$WORK/state/alpha/modules/inner/secrets/server.key"
	cmp -s "$WORK/state/alpha/srcs/.env" "$WORK/state/beta/srcs/.env" &&
		fail "positive control: the two projects must differ, or isolation proves nothing"
	printf '  two projects share every relative path and differ in every byte\n'
}

push_both() {
	client '$B keys init >/dev/null &&
		$B config endpoint --server http://'"$SRV"':8443 --authority http://unused >/dev/null &&
		cd /state/alpha && $B push --project alpha &&
		cd /state/beta && $B push --project beta' >"$WORK/push.log" 2>&1 ||
		{ cat "$WORK/push.log"; fail "pushing two projects failed"; }
	printf '  %s\n' "$(grep -c 'pushed' "$WORK/push.log" | sed 's/^/pushes reported: /')"
}

assert_each_project_pulls_its_own_bytes() {
	client 'cd /state/pull-alpha && $B pull --project alpha --apply &&
		cd /state/pull-beta && $B pull --project beta --apply' >"$WORK/pull.log" 2>&1 ||
		{ cat "$WORK/pull.log"; fail "pulling the two projects failed"; }
	for p in alpha beta; do
		got="$WORK/state/pull-$p/srcs/.env"
		[ -f "$got" ] || fail "$p did not restore srcs/.env"
		cmp -s "$WORK/state/$p/srcs/.env" "$got" ||
			fail "$p restored another project's srcs/.env — the projects are not isolated"
		cmp -s "$WORK/state/$p/secrets/db_password.txt" "$WORK/state/pull-$p/secrets/db_password.txt" ||
			fail "$p restored another project's credential"
	done
	printf '  each project restored its own bytes at the same relative paths\n'
}

# The nested directory belongs to alpha and must not appear in beta, which is the submodule case
# stated as an isolation property rather than as a structure one.
assert_the_nested_secrets_travel_with_their_project() {
	inner="$WORK/state/pull-alpha/modules/inner"
	[ -f "$inner/.env" ] || fail "the nested .env did not restore"
	[ -f "$inner/secrets/server.key" ] ||
		fail "a secrets/ directory inside a nested module did not restore"
	mode=$(stat -c %a "$inner/secrets/server.key")
	[ "$mode" = "600" ] || fail "the nested private key restored $mode, not 600"
	[ ! -e "$WORK/state/pull-beta/modules" ] ||
		fail "alpha's nested module appeared inside beta"
	printf '  a nested module kept its own secrets/ at mode 600, and stayed out of the other project\n'
}

# The server must hold two distinct blobs for the same relative path, not one shared row.
#
# Reads the write-ahead log alongside the database, because SQLite in WAL mode leaves recent rows
# in the -wal file and the .db can be a nearly empty shell. Grepping only the .db is how an
# absence assertion here passes while proving nothing — the same trap that made an earlier
# zero-knowledge check vacuous for its whole life.
assert_the_server_kept_them_apart() {
	rows=$(docker exec "$SRV" sh -c "cat /tmp/v30.db /tmp/v30.db-wal 2>/dev/null | strings | grep -c '__42ctl/b/' || true")
	[ "$rows" -gt 0 ] ||
		fail "positive control: no blob paths found in the store, so the count below means nothing"
	leaked=$(docker exec "$SRV" sh -c "cat /tmp/v30.db /tmp/v30.db-wal 2>/dev/null | strings | grep -c 'srcs/.env' || true")
	[ "$leaked" = "0" ] || fail "the real relative path reached the server $leaked time(s)"
	printf '  the store holds opaque blob paths and no real path\n'
}

main() {
	command -v docker >/dev/null 2>&1 || skip "docker not installed"
	docker image inspect "$IMG" >/dev/null 2>&1 || skip "toolchain image $IMG absent"
	[ -d "$CTL/src" ] || skip "42ctl is not beside this repo (set C42_DIR)"
	docker run --rm -v "$CTL":/work -w /work \
		-v 42ctl-cargo-registry:/usr/local/cargo/registry \
		-v 42ctl-cargo-git:/usr/local/cargo/git "$IMG" cargo build --quiet \
		>"$WORK/build.log" 2>&1 || { tail -20 "$WORK/build.log"; fail "the client did not build"; }
	start_server
	seed_projects
	push_both
	assert_each_project_pulls_its_own_bytes
	assert_the_nested_secrets_travel_with_their_project
	assert_the_server_kept_them_apart
	printf 'PASS v30: two projects sharing every path stay apart, and a nested module keeps its own\n'
}

main "$@"
