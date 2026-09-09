#!/bin/sh
# v17-authority-org-model.sh — prove the organization model's authorization rules.
#
# Runs the org battery against a real temporary SQLite database through the real router.
# The assertions that earn this gate are the negative ones: a plain member cannot invite;
# a non-member gets 404 rather than 403 so slugs cannot be enumerated; an invite is
# single-use and bound to the address it was sent to; a junk role is refused at the
# boundary; and a team member must already belong to the organization, which the schema
# enforces with a composite foreign key so no handler can bypass it.
#
# The assertion is cargo's own exit status, never a grep for a test count.
set -eu

IMAGE="${RUST_TOOLCHAIN_IMG:-mini-baas-rust-toolchain:latest}"
# shellcheck disable=SC1007  # CDPATH= clears CDPATH for this cd only, not a stray assignment
ROOT="$(CDPATH= cd "$(dirname "$0")/../.." && pwd)"

skip() {
	printf 'SKIP v17: %s\n' "$1"
	exit 0
}

run_battery() {
	docker run --rm -v "$ROOT":/work -w /work \
		-v vault42-cargo-registry:/usr/local/cargo/registry \
		-v vault42-cargo-git:/usr/local/cargo/git \
		-v vault42-target:/work/target \
		"$IMAGE" sh -c "cargo test -p vault42-authority --locked -- e2e_orgs:: rbac::; status=\$?; \
			chown -R $(id -u):$(id -g) /work; exit \$status"
}

main() {
	command -v docker >/dev/null 2>&1 || skip "docker not installed"
	docker image inspect "$IMAGE" >/dev/null 2>&1 || skip "toolchain image $IMAGE absent (run a build first)"
	if run_battery; then
		printf 'PASS v17: organizations, teams, invites and role checks green\n'
	else
		printf 'FAIL v17: authority org-model battery did not pass\n'
		exit 1
	fi
}

main "$@"
