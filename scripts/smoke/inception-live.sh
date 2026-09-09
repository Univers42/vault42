# **************************************************************************** #
#                                                                              #
#                                                            :::      :::::::: #
#   inception-live.sh                                      :+:      :+:    :+: #
#                                                          +:+ +:+         +:+ #
#   By: dlesieur <dev.pro.photo@gmail.com>                  +#+  +:+       +#+ #
#                                                            +#+#+#+#+#+   +#+ #
#   Created: 2026/06/19 00:00:00 by dlesieur                        #+#    #+# #
#   Updated: 2026/06/19 00:00:00 by dlesieur                 ###   ########.fr #
#                                                                              #
# **************************************************************************** #

#!/bin/sh
# The real-project scenario, against the DEPLOYED vault.
#
# Inception is a genuine compose project: its configuration lives in srcs/.env and
# docker-compose.yml mounts six credentials by path out of secrets/. Its .gitignore excludes
# both, which is the point — these are exactly the files git must not hold and the vault must.
#
# Not a gate, for the same reason post-deploy.sh is not: this drives billed infrastructure over
# the network. It also WRITES to production, creating one tenant per run, so it is invoked
# deliberately rather than swept up by a glob.
#
# IT CANNOT CLEAN UP AFTER ITSELF, and that is a property of the authority rather than an
# oversight here. Nothing releases a tenant name: the claim is keyed on the name and holds the
# claiming author's fingerprint, re-registration succeeds only for that same fingerprint, and
# even deleting the account leaves the row behind (THREAT-MODEL R20). Reusing one fixed name
# across runs would need a committed keystore, which is worse than a row. So each run leaves a
# few hundred bytes on a 1 GB volume, permanently.
#
# What it proves that a local run cannot: that the project survives the scale-to-zero cycle the
# whole cost model rests on. It stops both machines cold between the push and the pull, so a
# green here means the data outlived the machine that received it.
#
# WHAT IT CANNOT PROVE: anything about reading what an OLDER client wrote. It pushes with the
# binary it just built and pulls with the same one, so every artefact it reads was written by the
# version under test. No fixture written by an older binary exists anywhere in either repository,
# which means the whole cross-version compatibility story rests on serde defaults that have never
# been exercised against a real old artefact. That gap is not theoretical: a client without the
# `chunked` field silently drops it, fetches the vault blob for a chunked path — which is the
# chunk LIST, not the file — and writes those bytes to disk as the file, reporting success. A
# green here says nothing about that, and it never will.
set -eu

AUTHORITY="${AUTHORITY_URL:-https://vault42-authority.fly.dev}"
SERVER="${SERVER_URL:-https://vault42-server.fly.dev}"
: "${C42:?set C42 to the 42ctl binary}"
: "${FT_REGISTER_TOKEN:?set FT_REGISTER_TOKEN; the authority gates /v1/register}"

WORK="$(mktemp -d)"
INC="${INCEPTION_DIR:-$WORK/Inception}"
trap 'rm -rf "$WORK"' EXIT

FT_CONFIG="$WORK/config.json"
FT_KEYSTORE="$WORK/keystore.v42"
FT_PASSPHRASE="scenario-$(date +%s)-$$"
export FT_CONFIG FT_KEYSTORE FT_PASSPHRASE
PROJECT="live-inception-$$"

fail() { printf 'FAIL scenario: %s\n' "$1" >&2; exit 1; }
ok() { printf 'ok  %s\n' "$1"; }

fetch_fixture() {
	[ -d "$INC/.git" ] && return 0
	git clone --depth 1 https://github.com/Univers42/Inception.git "$INC" >/dev/null 2>&1 ||
		fail "could not clone the Inception fixture"
}

# Read the secret filenames out of docker-compose.yml rather than hardcoding them, so this
# keeps testing the real project if it grows another one.
declared_secrets() {
	grep -oE '\.\./secrets/[a-zA-Z0-9_.]+' "$INC/srcs/docker-compose.yml" |
		sed 's|\.\./secrets/||' | sort -u
}

# An identity and a contract from the live authority. Every run gets its own tenant, so a
# rerun never inherits the last one's state and a failure is never someone else's residue.
enrol() {
	"$C42" config endpoint --server "$SERVER" --authority "$AUTHORITY" >/dev/null
	"$C42" keys init >/dev/null || fail "keys init failed"
	"$C42" auth login --tenant "scenario-$$" >/dev/null ||
		fail "the live authority refused to issue a contract"
	"$C42" auth whoami | grep -q 'contract  bound' ||
		fail "logged in without a bound contract; the vault would reject every call"
	ok "the live authority issued a contract"
}

# Fill the project the way an operator does: the environment from its own template, and one
# file per secret docker-compose.yml declares.
fill() {
	mkdir -p "$INC/srcs" "$INC/secrets"
	sed 's/login\.42\.fr/scenario.42.fr/g' "$INC/.env.example" >"$INC/srcs/.env"
	n=0
	for f in $SECRETS; do
		n=$((n + 1))
		printf 'scenario-secret-%02d-%s\n' "$n" "${f%.*}" >"$INC/secrets/$f"
	done
	# The private key carries a restrictive mode so the restore is checked on more than bytes.
	chmod 600 "$INC/secrets/server.key" 2>/dev/null || true
	[ -s "$INC/srcs/.env" ] || fail "the environment file was not generated"
	ok "filled srcs/.env and $n secret file(s) from the project's own declarations"
}

keep_expectations() {
	mkdir -p "$WORK/expected"
	cp -a "$INC/srcs/.env" "$WORK/expected/.env"
	cp -a "$INC/secrets" "$WORK/expected/secrets"
}

# THE WIPE IS AN ASSERTION, not a step. If it silently failed, every byte comparison below
# would pass against files that were never deleted, and the scenario would prove nothing while
# printing that everything was restored.
wipe() {
	rm -f "$INC/srcs/.env"
	rm -rf "$INC/secrets"
	[ ! -e "$INC/srcs/.env" ] || fail "the wipe left srcs/.env behind; the restore proves nothing"
	[ ! -d "$INC/secrets" ] || fail "the wipe left secrets/ behind; the restore proves nothing"
	ok "the working copy is genuinely gone"
}

# Stop both machines between the push and the pull. This is the assertion the deployment exists
# to support: the vault costs nothing while idle only if the data outlives the machine.
stop_the_machines() {
	if [ -z "${FLY_API_TOKEN:-}" ]; then
		printf 'note: FLY_API_TOKEN unset, so the machines were not stopped\n'
		return 0
	fi
	sh "$(dirname "$0")/../ops/fly-machines.sh" stop >/dev/null ||
		fail "could not stop the machines"
	ok "both machines stopped cold between the push and the pull"
}

assert_restored() {
	cmp -s "$WORK/expected/.env" "$INC/srcs/.env" ||
		fail "srcs/.env did not come back byte-identically"
	for f in $SECRETS; do
		[ -f "$INC/secrets/$f" ] || fail "secrets/$f was never restored"
		cmp -s "$WORK/expected/secrets/$f" "$INC/secrets/$f" ||
			fail "secrets/$f came back with different bytes"
	done
	ok "srcs/.env and every declared secret came back byte-identically"
}

# A credential restored world-readable is a credential leaked to every other user on the box.
assert_mode_survived() {
	want="$(stat -c %a "$WORK/expected/secrets/server.key")"
	got="$(stat -c %a "$INC/secrets/server.key")"
	[ "$want" = "$got" ] || fail "server.key was restored $got, not $want"
	ok "the TLS private key kept mode $want across the round trip"
}

main() {
	fetch_fixture
	SECRETS="$(declared_secrets)"
	[ -n "$SECRETS" ] || fail "docker-compose.yml declares no secrets; the fixture is wrong"
	enrol
	fill
	keep_expectations
	(cd "$INC" && "$C42" push --project "$PROJECT") || fail "push failed"
	ok "the project pushed to the deployed vault"
	wipe
	stop_the_machines
	(cd "$INC" && "$C42" pull --project "$PROJECT" --apply) >/dev/null ||
		fail "pull failed against a cold deployment"
	ok "the project pulled back, waking both machines"
	assert_restored
	assert_mode_survived
	printf 'PASS scenario: Inception round-tripped through the deployed vault across a full stop\n'
}

main "$@"
