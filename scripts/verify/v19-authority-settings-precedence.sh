#!/bin/sh
# v19-authority-settings-precedence.sh — prove variable precedence and real authorization.
#
# Two things earn this gate. Precedence must be a property of the data: a key set at several
# levels resolves to the most specific one, the response names which level supplied it, and
# deleting the specific value lets the next level resurface.
#
# And a grant must actually decide something. A plain organization member with no grant cannot
# write; with only `read` still cannot; with `write` can, including when the grant reaches them
# through a team. A project-level `admin` grant must NOT confer organization-level writes.
# Until those hold, grants are bookkeeping rather than authorization.
#
# Values are opaque throughout: what goes in comes back byte-for-byte, because a secret is a
# blob the client sealed and the authority holds no key that could open it.
#
# The assertion is cargo's own exit status, never a grep for a test count.
set -eu

IMAGE="${RUST_TOOLCHAIN_IMG:-mini-baas-rust-toolchain:latest}"
# shellcheck disable=SC1007  # CDPATH= clears CDPATH for this cd only, not a stray assignment
ROOT="$(CDPATH= cd "$(dirname "$0")/../.." && pwd)"

skip() {
	printf 'SKIP v19: %s\n' "$1"
	exit 0
}

run_battery() {
	docker run --rm -v "$ROOT":/work -w /work \
		-v vault42-cargo-registry:/usr/local/cargo/registry \
		-v vault42-cargo-git:/usr/local/cargo/git \
		-v vault42-target:/work/target \
		"$IMAGE" sh -c "cargo test -p vault42-authority --locked -- e2e_vars::; status=\$?; \
			chown -R $(id -u):$(id -g) /work; exit \$status"
}

main() {
	command -v docker >/dev/null 2>&1 || skip "docker not installed"
	docker image inspect "$IMAGE" >/dev/null 2>&1 || skip "toolchain image $IMAGE absent (run a build first)"
	if run_battery; then
		printf 'PASS v19: variable precedence and grant-based write authorization green\n'
	else
		printf 'FAIL v19: authority settings-precedence battery did not pass\n'
		exit 1
	fi
}

main "$@"
