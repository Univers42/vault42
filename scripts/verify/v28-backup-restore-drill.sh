# **************************************************************************** #
#                                                                              #
#                                                            :::      :::::::: #
#   v28-backup-restore-drill.sh                            :+:      :+:    :+: #
#                                                          +:+ +:+         +:+ #
#   By: dlesieur <dev.pro.photo@gmail.com>                  +#+  +:+       +#+ #
#                                                            +#+#+#+#+#+   +#+ #
#   Created: 2026/06/19 00:00:00 by dlesieur                        #+#    #+# #
#   Updated: 2026/06/19 00:00:00 by dlesieur                 ###   ########.fr #
#                                                                              #
# **************************************************************************** #

#!/bin/sh
# v28-backup-restore-drill.sh — prove a backup restores a WORKING vault, not an empty one.
#
# There were no backups of anything before this. The reason it is a gate rather than a script is
# the trap the QA session measured: with write-ahead logging the `.db` on disk can be a nearly
# empty shell while every row lives in the `-wal` beside it. So copying the `.db` alone produces a
# backup that restores CLEANLY and is EMPTY. Nothing reports an error at any point — the copy
# succeeds, the restore succeeds, the server starts, and the vault is gone. An operator finds out
# when they need the backup, which is the worst possible moment to learn it never worked.
#
# THE DRILL RESTORES AND THEN AUTHENTICATES. A restore that produces a file proves nothing; the
# file has to hold an account that can still log in. So the gate signs up a sentinel account,
# backs up, destroys the original, restores, and requires that account to authenticate against
# the restored database.
#
# AND IT ASSERTS THE NAIVE COPY FAILS. That half is the control. Without it a green means only
# "restoring worked", which stays green if somebody later simplifies the backup down to `cp`, at
# which point the gate is passing while the backup is worthless. Requiring the `.db`-only copy to
# LOSE the account keeps the reason for `VACUUM INTO` inside the test rather than in a comment.
#
# BOTH COPIES ARE TAKEN WHILE THE SERVER IS RUNNING, and that is load-bearing rather than
# convenient. My first version stopped the authority first, and the control failed: the `.db`-only
# copy restored the account perfectly well, because a clean shutdown checkpoints the log into the
# database. The trap only bites a LIVE database — which is the only kind anyone ever backs up,
# since nobody stops their vault to copy it. Taking both copies live also proves the real
# requirement, that `VACUUM INTO` works without downtime.
#
# Everything runs in one container because the property is about a real process against real
# files, and because the toolchain image has no curl — HTTP goes over bash's /dev/tcp.
set -eu

IMAGE="${RUST_TOOLCHAIN_IMG:-mini-baas-rust-toolchain:latest}"
# shellcheck disable=SC1007  # CDPATH= clears CDPATH for this cd only, not a stray assignment
ROOT="$(CDPATH= cd "$(dirname "$0")/../.." && pwd)"

skip() {
	printf 'SKIP v28: %s\n' "$1"
	exit 0
}

run_drill() {
	docker run --rm -v "$ROOT":/work -w /work \
		-v vault42-cargo-registry:/usr/local/cargo/registry \
		-v vault42-cargo-git:/usr/local/cargo/git \
		-v vault42-target:/work/target \
		"$IMAGE" bash -c "$(drill_script)"
}

drill_script() {
	cat <<'INNER'
set -eu
cargo build -q -p vault42-authority --locked || exit 70
BIN=./target/debug/vault42-authority
STATE=$(mktemp -d)
PORT=18447
export RUST_LOG=warn NO_COLOR=1
export VAULT42_AUTHORITY_HOST=127.0.0.1 VAULT42_AUTHORITY_PORT=$PORT
export VAULT42_AUTHORITY_DB="$STATE/a.db" VAULT42_AUTHORITY_KEY="$STATE/a.key"
EMAIL="drill-sentinel@archicode.codes"
PASS="drill-Sentinel-Passphrase-42"

http() {
	body="{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}"
	exec 3<>/dev/tcp/127.0.0.1/$PORT || return 9
	printf 'POST %s HTTP/1.1\r\nHost: v28\r\nContent-Type: application/json\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' \
		"$1" "${#body}" "$body" >&3
	head -1 <&3 | cut -d' ' -f2
	exec 3<&-
}

start() {
	"$BIN" >"$STATE/log" 2>&1 &
	SRV=$!
	waited=0
	until (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null; do
		waited=$((waited + 1))
		[ "$waited" -ge 60 ] && { echo "SERVER-NEVER-STARTED"; cat "$STATE/log"; exit 1; }
		sleep 1
	done
	exec 3<&-
}

stop() { kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true; }

start
code=$(http /v1/auth/signup)
[ "$code" = "201" ] || { echo "SIGNUP-FAILED code=$code"; exit 1; }
code=$(http /v1/auth/login)
[ "$code" = "200" ] || { echo "BASELINE-LOGIN-FAILED code=$code"; exit 1; }

"$BIN" backup "$STATE/good.db" >/dev/null || { echo "BACKUP-FAILED-AGAINST-A-LIVE-SERVER"; exit 1; }
cp "$STATE/a.db" "$STATE/naive.db"
stop
[ -s "$STATE/good.db" ] || { echo "BACKUP-IS-EMPTY"; exit 1; }

rm -f "$STATE/a.db" "$STATE/a.db-wal" "$STATE/a.db-shm"
cp "$STATE/good.db" "$STATE/a.db"
start
code=$(http /v1/auth/login)
stop
[ "$code" = "200" ] || { echo "RESTORE-DID-NOT-BRING-BACK-THE-ACCOUNT code=$code"; exit 1; }
echo "  restored from the snapshot: the sentinel account still authenticates"

rm -f "$STATE/a.db" "$STATE/a.db-wal" "$STATE/a.db-shm"
cp "$STATE/naive.db" "$STATE/a.db"
start
code=$(http /v1/auth/login)
stop
[ "$code" = "200" ] && { echo "CONTROL-FAILED: the .db-only copy restored the account, so this gate proves nothing about VACUUM INTO"; exit 1; }
echo "  control: the .db-only copy restores an empty vault (login answered $code)"

rm -rf "$STATE"
INNER
}

main() {
	command -v docker >/dev/null 2>&1 || skip "docker not installed"
	docker image inspect "$IMAGE" >/dev/null 2>&1 || skip "toolchain image $IMAGE absent (run a build first)"
	run_drill || {
		printf 'FAIL v28: the backup does not restore a working vault\n'
		exit 1
	}
	printf 'PASS v28: a snapshot restores an account that can still log in, and a .db-only copy does not\n'
}

main "$@"
