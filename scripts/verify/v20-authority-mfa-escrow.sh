#!/bin/sh
# v20-authority-mfa-escrow.sh — prove the authority mints and enforces its own second factor.
#
# Rejecting grobase removed the thing that used to issue these codes: proofs were minted by GoTrue
# under a shared secret and this authority only verified them. It now does both, which is why the
# Titan transport matters and why this gate exists.
#
# Six digits is a million possibilities, and that is only survivable because everything around the
# code is strict. So the battery asserts each rule separately: a code works exactly once, expires,
# dies on its fifth wrong guess, is bound to the address it was mailed to, and is replaced rather
# than added to by a second request. A code that is merely usually right is worse than no second
# factor, because it is trusted.
#
# Two assertions are about what is NOT said. Requesting a code for an address with no account still
# answers 200, so the route cannot be used to enumerate who has an account here, and nothing is
# mailed. And every way a code can fail answers 401 with an identical body, so nobody can tell
# "expired" from "wrong" from "already used" and learn whether an address has a live code.
#
# The switch is the part most worth attacking. Once an account requires a factor, every path that
# mints a session must demand it. There is exactly one such path by construction, and the battery
# asserts the behaviour that construction is meant to guarantee: a password alone is refused, a
# forged proof is refused, a proof minted for another address is refused, and turning the factor
# back off needs a fresh proof so a stolen session cannot strip it.
#
# The GitHub device flow is attacked with a stub standing in for github.com, because an external
# service's answer feeding session minting is where a forgotten check lives. The stub is hostile on
# purpose: it approves a sign-in for an address the signer never proved they own, for an address
# with no account here, and for an account that requires a second factor. GitHub refuses none of
# those, so the authority must refuse all three. An unconfigured deployment says so rather than
# 404, and the GitHub token is never handed to the client.
#
# The mail seam is asserted too, because it is what makes any of this testable: the file transport
# renders the same message SMTP would send, the code is in the body and never in the subject, and
# an address cannot steer the written path. An authority with second factors on and no usable
# transport refuses to start rather than accepting codes it will drop.
#
# The assertion is cargo's own exit status, never a grep for a test count.
set -eu

IMAGE="${RUST_TOOLCHAIN_IMG:-mini-baas-rust-toolchain:latest}"
# shellcheck disable=SC1007  # CDPATH= clears CDPATH for this cd only, not a stray assignment
ROOT="$(CDPATH= cd "$(dirname "$0")/../.." && pwd)"

skip() {
	printf 'SKIP v20: %s\n' "$1"
	exit 0
}

run_battery() {
	docker run --rm -v "$ROOT":/work -w /work \
		-v vault42-cargo-registry:/usr/local/cargo/registry \
		-v vault42-cargo-git:/usr/local/cargo/git \
		-v vault42-target:/work/target \
		"$IMAGE" sh -c "cargo test -p vault42-authority --locked -- \
			e2e_secondfactor:: e2e_github:: otp:: mail:: config:: handlers::github::; \
			status=\$?; chown -R $(id -u):$(id -g) /work; exit \$status"
}

run_proof_format() {
	docker run --rm -v "$ROOT":/work -w /work \
		-v vault42-cargo-registry:/usr/local/cargo/registry \
		-v vault42-cargo-git:/usr/local/cargo/git \
		-v vault42-target:/work/target \
		"$IMAGE" sh -c "cargo test -p vault42-contract --locked -- otp::; \
			status=\$?; chown -R $(id -u):$(id -g) /work; exit \$status"
}

main() {
	command -v docker >/dev/null 2>&1 || skip "docker not installed"
	docker image inspect "$IMAGE" >/dev/null 2>&1 || skip "toolchain image $IMAGE absent (run a build first)"
	run_battery || {
		printf 'FAIL v20: one-time codes, escrow or the second-factor switch did not hold\n'
		exit 1
	}
	run_proof_format || {
		printf 'FAIL v20: the proof the authority mints is not the proof the contract verifies\n'
		exit 1
	}
	printf 'PASS v20: codes are single-use and bounded, escrow needs a proof, and the factor gates every login\n'
}

main "$@"
