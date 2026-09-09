# **************************************************************************** #
#                                                                              #
#                                                            :::      :::::::: #
#   fly-machines.sh                                        :+:      :+:    :+: #
#                                                          +:+ +:+         +:+ #
#   By: dlesieur <dev.pro.photo@gmail.com>                  +#+  +:+       +#+ #
#                                                            +#+#+#+#+#+   +#+ #
#   Created: 2026/06/19 00:00:00 by dlesieur                        #+#    #+# #
#   Updated: 2026/06/19 00:00:00 by dlesieur                 ###   ########.fr #
#                                                                              #
# **************************************************************************** #

#!/bin/sh
# Machine lifecycle for the two fly.io apps: status, stop, start.
#
# The manual on/off switch. Both apps are configured to stop themselves when idle and wake on
# a request, which is what makes the standing cost two 1 GB volumes and nothing else. This is
# for the times an operator wants the decision to be theirs: stopping after a deploy rather
# than paying out the idle timeout, or holding the control plane off entirely.
#
# `flyctl machine stop` refuses to guess which machine it means when it is not attached to a
# terminal, so the ids are read from the JSON listing rather than left to a prompt that would
# hang a CI job forever.
set -eu

FLYCTL="${FLYCTL:-flyio/flyctl:v0.4.101}"
DEFAULT_APPS="vault42-authority vault42-server"

usage() {
	printf 'usage: %s <status|stop|start> [app...]\n' "$0" >&2
	printf 'apps default to: %s\n' "$DEFAULT_APPS" >&2
	exit 2
}

fly() {
	docker run --rm -e FLY_API_TOKEN "$FLYCTL" "$@"
}

# Machine ids for one app, one per line. The listing carries nested objects with their own
# fields, so this reads the top-level `id` of each machine rather than grepping for anything
# that looks like one.
machine_ids() {
	fly machines list --app "$1" --json 2>/dev/null |
		python3 -c 'import json,sys; print("\n".join(m["id"] for m in json.load(sys.stdin)))'
}

show_status() {
	printf '\n== %s ==\n' "$1"
	fly machines list --app "$1" 2>/dev/null |
		python3 -c 'import sys; [print(l, end="") for l in sys.stdin if "│" in l]' || true
}

# An app with no machines is not an error: that is the state `stop` is trying to reach, and a
# failure here would make a second stop look like a broken deployment.
act_on_each() {
	verb="$1"
	app="$2"
	ids="$(machine_ids "$app")"
	if [ -z "$ids" ]; then
		printf '%s: no machines to %s\n' "$app" "$verb"
		return 0
	fi
	for id in $ids; do
		printf '%s: %s %s\n' "$app" "$verb" "$id"
		fly machine "$verb" "$id" --app "$app"
	done
}

main() {
	[ "$#" -ge 1 ] || usage
	action="$1"
	shift
	apps="${*:-$DEFAULT_APPS}"
	: "${FLY_API_TOKEN:?set FLY_API_TOKEN before running this}"
	for app in $apps; do
		case "$action" in
			status) show_status "$app" ;;
			stop | start) act_on_each "$action" "$app" ;;
			*) usage ;;
		esac
	done
}

main "$@"
