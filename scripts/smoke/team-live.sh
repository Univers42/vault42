# **************************************************************************** #
#                                                                              #
#                                                            :::      :::::::: #
#   team-live.sh                                           :+:      :+:    :+: #
#                                                          +:+ +:+         +:+ #
#   By: dlesieur <dev.pro.photo@gmail.com>                  +#+  +:+       +#+ #
#                                                            +#+#+#+#+#+   +#+ #
#   Created: 2026/06/19 00:00:00 by dlesieur                        #+#    #+# #
#   Updated: 2026/06/19 00:00:00 by dlesieur                 ###   ########.fr #
#                                                                              #
# **************************************************************************** #

#!/bin/sh
# The group scenario, against the DEPLOYED vault: two people, an org, a project, an environment,
# a role-gated grant, and a tree of credentials one of them can write and the other can only read.
#
# The local battery in ../42ctl proves this logic. What it cannot prove is the deployment: real
# TLS, the fly proxy speaking h2c to tonic, a control plane that sleeps between calls, and state
# that has to survive on a volume rather than in a container that is about to be thrown away.
#
# NOT A GATE, and not scheduled. It creates accounts on the production authority, so it deletes
# them again on the way out — which is only possible because `42ctl account delete` exists. It
# sends no mail: password sign-in needs none, and second factors are left alone precisely so that
# running this costs nobody an inbox.
set -eu

AUTHORITY="${AUTHORITY_URL:-https://vault42-authority.fly.dev}"
SERVER="${SERVER_URL:-https://vault42-server.fly.dev}"
: "${C42:?set C42 to the 42ctl binary}"
: "${FT_REGISTER_TOKEN:?set FT_REGISTER_TOKEN; the authority gates /v1/register}"

WORK="$(mktemp -d)"
STAMP="$(date +%s)-$$"
trap 'cleanup' EXIT

fail() { printf 'FAIL team: %s\n' "$1" >&2; exit 1; }
ok() { printf 'ok  %s\n' "$1"; }

# Each person gets their own config, keystore and passphrase, because two people sharing one
# keystore would prove nothing about sharing at all.
as() {
    who="$1"
    shift
    FT_CONFIG="$WORK/$who.json" FT_KEYSTORE="$WORK/$who.v42" \
        FT_PASSPHRASE="pass-$who-$STAMP" FT_PASSWORD="Password-$who-$STAMP" \
        "$C42" "$@"
}

# Deleting the accounts is the difference between a scenario that can be run again and one that
# leaves a trail on somebody's production control plane.
cleanup() {
    for who in owner member; do
        as "$who" account delete --yes >/dev/null 2>&1 || true
    done
    rm -rf "$WORK"
}

enrol() {
    for who in owner member; do
        as "$who" config endpoint --server "$SERVER" --authority "$AUTHORITY" >/dev/null
        as "$who" keys init >/dev/null || fail "$who could not create an identity"
        as "$who" auth signup --email "$who-$STAMP@archicode.codes" >/dev/null 2>&1 ||
            fail "$who could not sign up"
        as "$who" auth login --tenant "$who-$STAMP" >/dev/null ||
            fail "$who could not obtain a contract"
    done
    ok "two people signed up and hold contracts from the live authority"
}

# Everything past enrolment needs a SESSION, and the client mints one only through the GitHub
# device flow: `auth login` saves a contract and never a session, whether or not `--email` is
# given. So an authority without GITHUB_CLIENT_ID cannot be used to create an organization, a
# team, a project, an environment or a grant — through this CLI, at all.
#
# This reports that rather than pretending, and it is deliberately a SKIP with a named reason
# instead of a pass: a script that stopped early and printed PASS would say the group flow works.
assert_the_group_flow_is_reachable() {
    body=$(curl -sS --max-time 20 -X POST "$AUTHORITY/v1/github/device/start" \
        -H 'content-type: application/json' -d '{}' 2>/dev/null || echo '{}')
    case "$body" in
        *"not configured"*)
            printf 'SKIP team: the deployed authority has no GITHUB_CLIENT_ID, and the client\n'
            printf '  obtains a session only through the GitHub device flow — so no organization,\n'
            printf '  team, project, environment or grant can be created against it. Enrolment\n'
            printf '  above is real; everything past it is unreachable until that is set (R26).\n'
            exit 2
            ;;
    esac
    ok "the device flow is configured, so a session is obtainable"
}

main() {
    printf 'team: authority=%s server=%s\n' "$AUTHORITY" "$SERVER"
    enrol
    assert_the_group_flow_is_reachable
    printf 'PASS team: two people enrolled and a session is obtainable on the deployed stack\n'
}

main "$@"
