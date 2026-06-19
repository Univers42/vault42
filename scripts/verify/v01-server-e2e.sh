#!/bin/sh
# v01-server-e2e.sh — prove the zero-knowledge server end-to-end. Runs the in-process
# gRPC battery (v01 roundtrip byte-identical, v02 no-plaintext-on-the-wire, v03
# cross-owner isolation, signature tamper/method-binding, version conflict) in the
# Docker toolchain image — no host cargo. Skips cleanly if Docker is unavailable.
set -eu

IMAGE="${RUST_TOOLCHAIN_IMG:-mini-baas-rust-toolchain:latest}"
ROOT="$(CDPATH= cd "$(dirname "$0")/../.." && pwd)"

skip() {
	printf 'SKIP v01: %s\n' "$1"
	exit 0
}

run_battery() {
	docker run --rm -v "$ROOT":/work -w /work \
		-v vault42-cargo-registry:/usr/local/cargo/registry \
		-v vault42-cargo-git:/usr/local/cargo/git \
		-v vault42-target:/work/target \
		"$IMAGE" sh -c "cargo test -p vault42-server e2e:: 2>&1 | tee /tmp/v01.log; \
			grep -q '6 passed; 0 failed' /tmp/v01.log; \
			chown -R $(id -u):$(id -g) /work"
}

main() {
	command -v docker >/dev/null 2>&1 || skip "docker not installed"
	docker image inspect "$IMAGE" >/dev/null 2>&1 || skip "toolchain image $IMAGE absent (run a build first)"
	if run_battery; then
		printf 'PASS v01: server zero-knowledge e2e battery green (6/6)\n'
	else
		printf 'FAIL v01: server e2e battery did not pass\n'
		exit 1
	fi
}

main "$@"
