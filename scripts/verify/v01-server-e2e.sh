#!/bin/sh
# v01-server-e2e.sh — prove the zero-knowledge server end-to-end. Runs the in-process
# gRPC battery (roundtrip byte-identical, no-plaintext-on-the-wire, cross-owner
# isolation, signature tamper/method-binding, version conflict, contract gate, scope
# keys) in the Docker toolchain image — no host cargo. Skips cleanly if Docker is
# unavailable; run the battery under --strict to turn a skip into a failure.
#
# The assertion is cargo's own exit status. It deliberately does NOT grep for a test
# count: the previous form ran `cargo test; grep -q '6 passed; 0 failed'; chown ...`
# inside one `sh -c`, so the shell returned chown's status and discarded the grep
# result — the gate reported PASS whatever the tests did, and the hardcoded 6 had
# already drifted. Keep `exit $status` last so the container status is the test status.
set -eu

IMAGE="${RUST_TOOLCHAIN_IMG:-mini-baas-rust-toolchain:latest}"
# shellcheck disable=SC1007  # CDPATH= clears CDPATH for this cd only; not a stray assignment
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
		"$IMAGE" sh -c "cargo test -p vault42-server e2e::; status=\$?; \
			chown -R $(id -u):$(id -g) /work; exit \$status"
}

main() {
	command -v docker >/dev/null 2>&1 || skip "docker not installed"
	docker image inspect "$IMAGE" >/dev/null 2>&1 || skip "toolchain image $IMAGE absent (run a build first)"
	if run_battery; then
		printf 'PASS v01: server zero-knowledge e2e battery green\n'
	else
		printf 'FAIL v01: server e2e battery did not pass\n'
		exit 1
	fi
}

main "$@"
