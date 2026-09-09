#!/bin/sh
# v18-authority-scope-bridge.sh — prove the scope bridge between the org model and the crypto.
#
# Runs the projects, environments, groups, member-key and grant battery against a real
# temporary SQLite database through the real router, plus the proof-of-possession unit tests.
#
# The assertions that earn this gate are the ones a structural check cannot make. A proof of
# possession must bind the organization's canonical id, so a proof signed over the slug is
# refused — the client and server would otherwise frame different bytes and no proof would
# ever verify. A grant must not name a grantee from another organization or an environment
# from another project. `missing` must be exactly the authorized set still lacking a wrap,
# because the client drives both provisioning and rotation from it. A scope epoch must
# advance, so a stale client cannot roll an environment back to a key removed members hold.
# And a project id must be a UUID, or its derived scope id does not exist.
#
# The assertion is cargo's own exit status, never a grep for a test count.
set -eu

IMAGE="${RUST_TOOLCHAIN_IMG:-mini-baas-rust-toolchain:latest}"
# shellcheck disable=SC1007  # CDPATH= clears CDPATH for this cd only, not a stray assignment
ROOT="$(CDPATH= cd "$(dirname "$0")/../.." && pwd)"

skip() {
	printf 'SKIP v18: %s\n' "$1"
	exit 0
}

run_battery() {
	docker run --rm -v "$ROOT":/work -w /work \
		-v vault42-cargo-registry:/usr/local/cargo/registry \
		-v vault42-cargo-git:/usr/local/cargo/git \
		-v vault42-target:/work/target \
		"$IMAGE" sh -c "cargo test -p vault42-authority --locked -- e2e_scope:: pop::; status=\$?; \
			chown -R $(id -u):$(id -g) /work; exit \$status"
}

main() {
	command -v docker >/dev/null 2>&1 || skip "docker not installed"
	docker image inspect "$IMAGE" >/dev/null 2>&1 || skip "toolchain image $IMAGE absent (run a build first)"
	if run_battery; then
		printf 'PASS v18: projects, environments, groups, member keys and grants green\n'
	else
		printf 'FAIL v18: authority scope-bridge battery did not pass\n'
		exit 1
	fi
}

main "$@"
