#!/bin/sh
# v26-authority-offboarding.sh — prove access can actually be taken away.
#
# The authority once had 29 routes and not one DELETE. Nobody could stop being a member of an
# organization, a team or a group, and no grant could be revoked, so rotation's promise — "a
# revoked member loses access by absence at the new epoch" — described a state that was
# unreachable. For a secrets vault, offboarding is the operation that matters most after storing
# a secret.
#
# The assertion that carries the security model is that after a removal the grant's `members`
# list no longer names the departed member. That list is what a rotation re-wraps to, so a
# removal that left it unchanged would hand somebody a fresh key on their way out. Three separate
# things make it true and the battery pins each: team and group memberships and published public
# keys cascade from a composite foreign key onto `org_members`, a direct grant is revoked in the
# same transaction as the removal, and `authorized_members` resolves membership at read time so
# no removal path can forget.
#
# That third one needs a white-box test and the first version of this gate did not have one, so it
# passed with the membership join deleted: the route-level assertions were each covered by one of
# the other two protections. `a_grant_never_authorizes_a_non_member` strips a membership row
# directly, leaving the grant live, which is the only way to reach the rule on its own.
#
# Two refusals matter as much as the removals. An organization can never lose its last owner, by
# leaving or by erasing the account, because an organization with no owner cannot be administered
# or repaired. And an admin cannot unseat an owner, or one admin could remove every owner and
# inherit the organization.
#
# Finally the battery pins honesty: every removal response says a rotation is still required.
# Removal cannot reach a scope key already wrapped to somebody — that lives in vault42 under
# their own key — and an operator who reads "removed" as "locked out" has been misled at the
# worst possible moment.
#
# The assertion is cargo's own exit status, never a grep for a test count.
set -eu

IMAGE="${RUST_TOOLCHAIN_IMG:-mini-baas-rust-toolchain:latest}"
# shellcheck disable=SC1007  # CDPATH= clears CDPATH for this cd only, not a stray assignment
ROOT="$(CDPATH= cd "$(dirname "$0")/../.." && pwd)"

skip() {
	printf 'SKIP v26: %s\n' "$1"
	exit 0
}

run_battery() {
	docker run --rm -v "$ROOT":/work -w /work \
		-v vault42-cargo-registry:/usr/local/cargo/registry \
		-v vault42-cargo-git:/usr/local/cargo/git \
		-v vault42-target:/work/target \
		"$IMAGE" sh -c "cargo test -p vault42-authority --locked -- e2e_offboard:: offboard::; \
			status=\$?; chown -R $(id -u):$(id -g) /work; exit \$status"
}

main() {
	command -v docker >/dev/null 2>&1 || skip "docker not installed"
	docker image inspect "$IMAGE" >/dev/null 2>&1 || skip "toolchain image $IMAGE absent (run a build first)"
	if run_battery; then
		printf 'PASS v26: removal cascades, refuses to strand an org, and admits a rotation is still needed\n'
	else
		printf 'FAIL v26: offboarding battery did not pass\n'
		exit 1
	fi
}

main "$@"
