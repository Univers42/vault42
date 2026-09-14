# **************************************************************************** #
#                                                                              #
#                                                            :::      :::::::: #
#   release-version.sh                                     :+:      :+:    :+: #
#                                                          +:+ +:+         +:+ #
#   By: dlesieur <dev.pro.photo@gmail.com>                  +#+  +:+       +#+ #
#                                                            +#+#+#+#+#+   +#+ #
#   Created: 2026/06/19 00:00:00 by dlesieur                        #+#    #+# #
#   Updated: 2026/06/19 00:00:00 by dlesieur                 ###   ########.fr #
#                                                                              #
# **************************************************************************** #

#!/bin/sh
# The workspace's release version: what it is, what the next release is, and how to set it.
#
#   release-version.sh current        the [workspace.package] version in Cargo.toml
#   release-version.sh next           the version the next release should carry: the current one
#                                     if no tag names it yet (a deliberate minor/major bump in a
#                                     pull request), else the first untagged patch after it
#   release-version.sh set X.Y.Z      write X.Y.Z to Cargo.toml and to every workspace crate's
#                                     Cargo.lock entry, and check both took
#
# Used by .github/workflows/auto-release.yml, and by hand to cut a minor or major: `set 0.3.0`
# in a pull request, and the first green CI after it releases v0.3.0 rather than a patch.
#
# Every workspace crate inherits `version.workspace = true`, so Cargo.toml has ONE version line
# that matters. Cargo.lock repeats it once per crate; those entries are the packages with no
# `source` (they come from this tree, not a registry or git) and a vault42- name. Leaving the
# lock behind would not fail a build here, which regenerates it, but it would make the tagged
# tree differ from what `cargo build --locked` accepts.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
MANIFEST="$ROOT/Cargo.toml"
LOCK="$ROOT/Cargo.lock"

die() { printf 'release-version: %s\n' "$*" >&2; exit 1; }

# The version line inside [workspace.package].
current() {
	awk '/^\[/ { in_pkg = ($0 == "[workspace.package]") }
		in_pkg && /^version = "/ { gsub(/^version = "|"$/, ""); print; exit }' "$MANIFEST"
}

# Whether a vX.Y.Z tag exists, locally or on the remote the checkout came from.
tagged() {
	git -C "$ROOT" rev-parse -q --verify "refs/tags/v$1" >/dev/null 2>&1
}

next() {
	version=$(current)
	case "$version" in
	[0-9]*.[0-9]*.[0-9]*) ;;
	*) die "Cargo.toml [workspace.package] version is '$version', not X.Y.Z" ;;
	esac
	while tagged "$version"; do
		major=${version%%.*}
		rest=${version#*.}
		minor=${rest%%.*}
		patch=${rest#*.}
		version="$major.$minor.$((patch + 1))"
	done
	highest=$(git -C "$ROOT" tag --list 'v[0-9]*.[0-9]*.[0-9]*' | sed 's/^v//' | sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1)
	if [ -n "$highest" ] && [ "$(printf '%s\n%s\n' "$highest" "$version" | sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1)" != "$version" ]; then
		die "the next release would be $version, below the released v$highest — raise Cargo.toml with \`set\`"
	fi
	printf '%s\n' "$version"
}

set_version() {
	want=$1
	case "$want" in
	[0-9]*.[0-9]*.[0-9]*) ;;
	*) die "not a version: '$want'" ;;
	esac
	old=$(current)
	awk -v v="$want" '/^\[/ { in_pkg = ($0 == "[workspace.package]") }
		in_pkg && !done && /^version = "/ { $0 = "version = \"" v "\""; done = 1 }
		{ print }' "$MANIFEST" >"$MANIFEST.tmp" && mv "$MANIFEST.tmp" "$MANIFEST"
	awk -v old="$old" -v v="$want" '
		function flush() { if (block != "") { if (ours && !sourced) sub("version = \"" old "\"", "version = \"" v "\"", block); printf "%s", block }; block = ""; ours = 0; sourced = 0 }
		/^\[\[package\]\]$/ { flush() }
		/^name = "vault42-/ { ours = 1 }
		/^source = / { sourced = 1 }
		{ block = block $0 "\n" }
		END { flush() }' "$LOCK" >"$LOCK.tmp" && mv "$LOCK.tmp" "$LOCK"
	[ "$(current)" = "$want" ] || die "Cargo.toml still says $(current)"
	stale=$(awk -v old="$old" '/^name = "vault42-/ { n = $0 } /^version = "/ && n != "" { if ($0 == "version = \"" old "\"") print n; n = "" }' "$LOCK")
	[ "$old" = "$want" ] || [ -z "$stale" ] || die "Cargo.lock still has $old for: $stale"
}

case "${1:-}" in
current) current ;;
next) next ;;
set) set_version "${2:?usage: release-version.sh set X.Y.Z}" ;;
*) die "usage: release-version.sh current | next | set X.Y.Z" ;;
esac
