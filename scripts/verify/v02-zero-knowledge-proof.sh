#!/bin/sh
# v02-zero-knowledge-proof.sh — prove the zero-knowledge claim end to end, against the
# SHIPPED binary: launch `vault42-server` on a scratch database, push a sentinel plaintext
# through a real signed client, then scan the bytes SQLite wrote, everything the server
# printed at RUST_LOG=trace, and what it served back. Both the per-owner secret path and the
# shared-environment env-secret path are covered. Every absence assertion has a positive
# control (the owner fingerprint / scope id must be findable, the startup line must be in the
# log), so a scan of an empty buffer cannot pass.
#
# Skips cleanly if Docker is unavailable; run the battery under --strict to turn a skip into
# a failure. The assertion is cargo's exit status — nothing here greps for a test count.
set -eu

IMAGE="${RUST_TOOLCHAIN_IMG:-mini-baas-rust-toolchain:latest}"
# shellcheck disable=SC1007  # CDPATH= clears CDPATH for this cd only; not a stray assignment
ROOT="$(CDPATH= cd "$(dirname "$0")/../.." && pwd)"

skip() {
	printf 'SKIP v02: %s\n' "$1"
	exit 0
}

run_gate() {
	docker run --rm -v "$ROOT":/work -w /work \
		-v vault42-cargo-registry:/usr/local/cargo/registry \
		-v vault42-cargo-git:/usr/local/cargo/git \
		-v vault42-target:/work/target \
		"$IMAGE" sh -c "cargo test -p vault42-server --test zero_knowledge; status=\$?; \
			chown -R $(id -u):$(id -g) /work; exit \$status"
}

main() {
	command -v docker >/dev/null 2>&1 || skip "docker not installed"
	docker image inspect "$IMAGE" >/dev/null 2>&1 || skip "toolchain image $IMAGE absent (run a build first)"
	if run_gate; then
		printf 'PASS v02: no sentinel plaintext on disk, in the logs, or on the wire\n'
	else
		printf 'FAIL v02: the zero-knowledge gate did not pass\n'
		exit 1
	fi
}

main "$@"
