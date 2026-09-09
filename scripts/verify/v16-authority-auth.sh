#!/bin/sh
# v16-authority-auth.sh — prove the authority's account layer end to end.
#
# Runs the in-process route battery: signup, login, me, logout, password change, the
# Bearer guard, and re-served contract issuance, each against a real temporary SQLite
# database through the real router. The security assertions it carries are that a token
# dies on logout and on password change, that an unknown email and a wrong password are
# indistinguishable, that a tenant name cannot be stolen, that a small-order author key is
# refused, and that the invite gate admits only its configured token.
#
# The assertion is cargo's own exit status — never a grep for a test count, which is what
# made v01 pass vacuously for as long as it existed.
set -eu

IMAGE="${RUST_TOOLCHAIN_IMG:-mini-baas-rust-toolchain:latest}"
# shellcheck disable=SC1007  # CDPATH= clears CDPATH for this cd only, not a stray assignment
ROOT="$(CDPATH= cd "$(dirname "$0")/../.." && pwd)"

skip() {
	printf 'SKIP v16: %s\n' "$1"
	exit 0
}

run_battery() {
	docker run --rm -v "$ROOT":/work -w /work \
		-v vault42-cargo-registry:/usr/local/cargo/registry \
		-v vault42-cargo-git:/usr/local/cargo/git \
		-v vault42-target:/work/target \
		"$IMAGE" sh -c "cargo test -p vault42-authority --locked; status=\$?; \
			chown -R $(id -u):$(id -g) /work; exit \$status"
}

main() {
	command -v docker >/dev/null 2>&1 || skip "docker not installed"
	docker image inspect "$IMAGE" >/dev/null 2>&1 || skip "toolchain image $IMAGE absent (run a build first)"
	if run_battery; then
		printf 'PASS v16: authority accounts, sessions, guard and contract issuance green\n'
	else
		printf 'FAIL v16: authority auth battery did not pass\n'
		exit 1
	fi
}

main "$@"
