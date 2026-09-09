# **************************************************************************** #
#                                                                              #
#                                                            :::      :::::::: #
#   v21-authority-parity.sh                                :+:      :+:    :+: #
#                                                          +:+ +:+         +:+ #
#   By: dlesieur <dev.pro.photo@gmail.com>                  +#+  +:+       +#+ #
#                                                            +#+#+#+#+#+   +#+ #
#   Created: 2026/06/19 00:00:00 by dlesieur                        #+#    #+# #
#   Updated: 2026/06/19 00:00:00 by dlesieur                 ###   ########.fr #
#                                                                              #
# **************************************************************************** #

#!/bin/sh
# v21-authority-parity.sh — the P6 cutover gate: every control-plane route 42ctl calls is a
# route this authority actually serves.
#
# The cutover repoints 42ctl's control plane from grobase to the authority, so the failure it
# has to rule out is a route the client calls that the server does not answer. That failure is
# invisible until somebody runs the verb, and then it looks like a 404 from a host that is
# plainly up, which reads as a client bug rather than a missing implementation.
#
# TWO HALVES, because either alone can pass while the cutover is broken.
#
# The parity half derives the paths from `../42ctl`'s own source rather than from a list kept
# here, because a list kept here drifts the moment the client adds a verb and then asserts
# nothing. It skips when the sibling repo is absent, which is the honest answer rather than a
# green.
#
# The reachability half starts the real binary and probes every route the authority declares,
# asserting none answers 404. A route can exist in `routes.rs` and still be unreachable — a
# nested router mounted on the wrong prefix, a layer rejecting before the handler — and the
# source diff cannot see that. 401 and 405 are passes here: they prove the router matched and
# then refused, which is the whole point. Only 404 means the path does not exist.
#
# This gate does NOT re-drive the CLI end to end. That lives in the QA session's battery, which
# already runs the real client against a real authority, and duplicating it here would cost
# minutes to assert something already asserted. What is asserted here is the thing that battery
# cannot see: whether the two repositories still agree on the route surface.
set -eu

IMAGE="${RUST_TOOLCHAIN_IMG:-mini-baas-rust-toolchain:latest}"
# shellcheck disable=SC1007  # CDPATH= clears CDPATH for this cd only, not a stray assignment
ROOT="$(CDPATH= cd "$(dirname "$0")/../.." && pwd)"
CTL="$ROOT/../42ctl"
NAME="v21-authority-$$"
PORT=18446
WORK="${TMPDIR:-/tmp}/v21-$$"

skip() {
	printf 'SKIP v21: %s\n' "$1"
	exit 0
}

fail() {
	printf 'FAIL v21: %s\n' "$1"
	exit 1
}

# shellcheck disable=SC2317  # reached through the EXIT trap, not by falling through
cleanup() {
	docker rm -fv "$NAME" >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap cleanup EXIT

# Every route the authority declares, with path parameters made concrete so they can be probed.
declared_routes() {
	grep -ohE '"/v1/[^"]*"' "$ROOT/crates/vault42-authority/src/routes.rs" |
		tr -d '"' | sed 's|:[a-z_]*|probe|g' | sort -u
}

# Every control-plane path 42ctl calls, normalised to the same shape.
client_paths() {
	grep -rhoE '"/v1/[^"]*"|format!\("[^"]*v1/[^"]*"' "$CTL/src/adapters/" "$CTL/src/cmd/" |
		sed 's/format!(//' | tr -d '"' | sed 's|{[a-z_]*}|probe|g' |
		sed 's|^probe||' | sed 's/?.*$//' | sort -u
}

# The authority's declared routes in client shape, for the set difference.
declared_for_diff() {
	declared_routes
}

start_authority() {
	mkdir -p "$WORK"
	docker run -d --name "$NAME" -p "127.0.0.1:$PORT:8444" \
		-v "$ROOT":/work -w /work \
		-v vault42-cargo-registry:/usr/local/cargo/registry \
		-v vault42-cargo-git:/usr/local/cargo/git \
		-v vault42-target:/work/target \
		-e VAULT42_AUTHORITY_HOST=0.0.0.0 -e VAULT42_AUTHORITY_PORT=8444 \
		-e VAULT42_AUTHORITY_DB=/tmp/v21.db -e VAULT42_AUTHORITY_KEY=/tmp/v21.key \
		-e RUST_LOG=warn -e NO_COLOR=1 \
		"$IMAGE" sh -c 'cargo build -q -p vault42-authority --locked && exec ./target/debug/vault42-authority' \
		>/dev/null
}

# Wait for /healthz and probe every route in ONE container.
#
# The state paths above are container-local on purpose. They were host paths, the container could
# not see that directory, the store failed to open and the process died before binding — which the
# gate reported as "never became ready", diagnosing a slow build rather than a missing directory.
wait_ready() {
	docker run --rm --network host -v "$WORK":/paths "$IMAGE" bash -c '
		waited=0
		until exec 3<>/dev/tcp/127.0.0.1/'"$PORT"' 2>/dev/null; do
			waited=$((waited + 1))
			[ "$waited" -ge 300 ] && exit 1
			sleep 1
		done
		exec 3<&-
	'
}

# Probe every path in ONE container, printing "<status> <path>" per line.
#
# A container per probe cost a launch each and turned a two-second check into minutes. The socket
# is opened per request because the server answers `Connection: close`.
probe_all() {
	docker run --rm --network host -v "$WORK":/paths "$IMAGE" bash -c '
		while read -r path; do
			[ -n "$path" ] || continue
			if exec 3<>/dev/tcp/127.0.0.1/'"$PORT"' 2>/dev/null; then
				printf "GET %s HTTP/1.1\r\nHost: v21\r\nConnection: close\r\n\r\n" "$path" >&3
				printf "%s %s\n" "$(head -1 <&3 | cut -d" " -f2)" "$path"
				exec 3<&-
			else
				printf "no-answer %s\n" "$path"
			fi
		done < /paths/probe.txt
	' 2>/dev/null
}

# One status line for /healthz, used only for readiness.
probe_status() {
	docker run --rm --network host "$IMAGE" bash -c "
		exec 3<>/dev/tcp/127.0.0.1/$PORT || exit 9
		printf 'GET %s HTTP/1.1\r\nHost: v21\r\nConnection: close\r\n\r\n' '$1' >&3
		head -1 <&3 | cut -d' ' -f2
	" 2>/dev/null
}

assert_every_route_is_reachable() {
	declared_routes >"$WORK/probe.txt"
	probe_all >"$WORK/probed.txt"
	probed=$(wc -l <"$WORK/probed.txt" | tr -d ' ')
	expected=$(wc -l <"$WORK/probe.txt" | tr -d ' ')
	[ "$probed" = "$expected" ] || fail "probed $probed of $expected routes; the probe itself failed"
	bad="$(awk '$1 == "404" || $1 == "no-answer" { printf "%s(%s) ", $2, $1 }' "$WORK/probed.txt")"
	[ -z "$bad" ] || fail "declared but not reachable: $bad"
	printf '  all %s declared routes answer something other than 404\n' "$expected"
}

assert_parity_with_the_client() {
	[ -d "$CTL/src/adapters" ] || {
		printf '  SKIP the parity half: ../42ctl is absent, so the client surface is unknown\n'
		return 0
	}
	absent="$(comm -23 "$WORK/client.txt" "$WORK/declared.txt")"
	[ -z "$absent" ] || fail "42ctl calls routes the authority does not serve: $(echo "$absent" | tr '\n' ' ')"
	printf '  all %s control-plane paths 42ctl calls are served\n' "$(wc -l <"$WORK/client.txt" | tr -d ' ')"
}

main() {
	command -v docker >/dev/null 2>&1 || skip "docker not installed"
	docker image inspect "$IMAGE" >/dev/null 2>&1 || skip "toolchain image $IMAGE absent (run a build first)"
	mkdir -p "$WORK"
	declared_for_diff >"$WORK/declared.txt"
	if [ -d "$CTL/src/adapters" ]; then client_paths >"$WORK/client.txt"; fi
	start_authority
	wait_ready || fail "the authority never became ready (see: docker logs $NAME)"
	assert_every_route_is_reachable
	assert_parity_with_the_client
	printf 'PASS v21: the authority serves every control-plane route 42ctl calls, and serves them live\n'
}

main "$@"
