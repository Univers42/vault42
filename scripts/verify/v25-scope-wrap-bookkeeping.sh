#!/bin/sh
# v25-scope-wrap-bookkeeping.sh — prove a scope-key wrap describes one environment at one epoch,
# and that a rotation cannot strand the environment it rotates.
#
# This gate exists because rotation once destroyed whole environments while reporting success.
# It re-sealed every secret to a new epoch, wrapped the new key to nobody, and printed
# "rotated scope". The new key lived only in the rotating client's memory, so it went away with
# the process, and an epoch never regresses, so there was no way back.
#
# The root cause was bookkeeping that named no scope: wraps keyed by grant and account alone.
# That made `missing` wrong in two directions. A project-wide grant covers every environment,
# so a wrap for one dropped the member from `missing` in the others and they were never
# provisioned there. And a stale row still claimed a wrap existed after a rotation had replaced
# the key, so the client's re-wrap set came back empty.
#
# Two batteries earn this gate. The authority half proves the coordinates are required and
# load-bearing: cross-environment isolation, a rotation reporting every member missing again,
# `members` staying the authorized set while `missing` empties, and an uncovered environment
# being refused. The server half proves the backstop: a rotation carrying no wrap for the
# caller is refused outright, whether the batch is partial or empty, so no client bug can
# reach the terminal outcome however it computed its re-wrap set.
#
# The assertion is cargo's own exit status, never a grep for a test count.
set -eu

IMAGE="${RUST_TOOLCHAIN_IMG:-mini-baas-rust-toolchain:latest}"
# shellcheck disable=SC1007  # CDPATH= clears CDPATH for this cd only, not a stray assignment
ROOT="$(CDPATH= cd "$(dirname "$0")/../.." && pwd)"

skip() {
	printf 'SKIP v25: %s\n' "$1"
	exit 0
}

run_authority() {
	docker run --rm -v "$ROOT":/work -w /work \
		-v vault42-cargo-registry:/usr/local/cargo/registry \
		-v vault42-cargo-git:/usr/local/cargo/git \
		-v vault42-target:/work/target \
		"$IMAGE" sh -c "cargo test -p vault42-authority --locked -- e2e_wraps::; status=\$?; \
			chown -R $(id -u):$(id -g) /work; exit \$status"
}

run_server() {
	docker run --rm -v "$ROOT":/work -w /work \
		-v vault42-cargo-registry:/usr/local/cargo/registry \
		-v vault42-cargo-git:/usr/local/cargo/git \
		-v vault42-target:/work/target \
		"$IMAGE" sh -c "cargo test -p vault42-server --locked -- ops_rotate::; status=\$?; \
			chown -R $(id -u):$(id -g) /work; exit \$status"
}

main() {
	command -v docker >/dev/null 2>&1 || skip "docker not installed"
	docker image inspect "$IMAGE" >/dev/null 2>&1 || skip "toolchain image $IMAGE absent (run a build first)"
	run_authority || {
		printf 'FAIL v25: wrap bookkeeping is not scoped to one environment and epoch\n'
		exit 1
	}
	run_server || {
		printf 'FAIL v25: a rotation that strands the caller was not refused\n'
		exit 1
	}
	printf 'PASS v25: wraps are per-environment per-epoch and a rotation keeps its caller\n'
}

main "$@"
