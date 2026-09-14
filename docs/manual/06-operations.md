# 6. Operations

## 6.1 Is it up, and what is it running?

```sh
curl -fsS -w '\n' https://vault42-authority.fly.dev/healthz        # ok
curl -fsS -w '\n' https://vault42-authority.fly.dev/version        # {"commit":"…","version":"…"}
curl -fsS -w '\n' https://vault42-authority.fly.dev/v1/contract-key
sh scripts/smoke/post-deploy.sh                                  # the deploy's own checks
```

`42ctl cloud health` checks the fly.io side as well: machines, volumes, snapshot age (42ctl manual,
chapter 12). On a Docker host, `docker ps` and `docker logs vault42-authority`.

Both services log to standard output, one line per event, at `RUST_LOG` level. No log line ever contains a
secret, a code, a password or a token.

## 6.2 Backups

What must survive:

| Data | Where | Loss means |
|---|---|---|
| authority database | `/data/authority.db` on the authority volume | accounts, organisations, grants, public keys gone |
| **contract signing key** | `/data/authority.key` on the authority volume | every contract ever issued is void; the server must be re-pinned and everyone signs in again |
| server database | `/data/vault42.db` on the server volume | **every stored secret gone** — ciphertext cannot be recreated |

### The authority

```sh
fly console --app vault42-authority --command "vault42-authority backup /data/backup-$(date +%F).db"
```

On Docker:

```sh
docker exec vault42-authority /vault42-authority backup "/data/backup-$(date +%F).db"
```

The subcommand takes a consistent snapshot (`VACUUM INTO`) of the live database, write-ahead log
included, as one file, and refuses to overwrite an existing one. Copy the snapshot **and
`/data/authority.key`** off the volume: a backup kept only on the volume it protects is not a backup.

> **Never back up by copying `authority.db` alone.** With write-ahead logging the `.db` file can be an
> almost empty shell while the rows live in `authority.db-wal` beside it. The copy restores cleanly and
> contains nothing. Gate `v28-backup-restore-drill` proves both the subcommand and that failure.

### The server

The server has no backup subcommand. Back its volume up while it is **stopped**, so its write-ahead log is
checkpointed into the database:

- on fly.io, volume snapshots — scheduled daily, and on demand with `42ctl cloud volume snapshot VOLUME_ID
  --app vault42-server` or `fly volumes snapshots create`;
- on Docker:

```sh
docker stop vault42-server
docker run --rm -v vault42-server-data:/data -v "$PWD":/backup public.ecr.aws/docker/library/debian:bookworm-slim \
  tar -C /data -czf "/backup/vault42-server-$(date +%F).tar.gz" .
docker start vault42-server
```

Requests made while it is stopped fail; run the backup when nobody is pushing.

### Restoring

1. Stop the application.
2. Authority: remove `authority.db`, `authority.db-wal` and `authority.db-shm`, put the snapshot in place as
   `authority.db`, and put back the **same** `authority.key`. Server: restore the volume's files together.
3. Start the application, and run the smoke test.

A restore to an older point loses what was written since: tell users to push again.

## 6.3 The deployment's own secrets

| Secret | Rotate by | Effect on users |
|---|---|---|
| `VAULT42_REGISTER_TOKEN` | changing the repository secret (fly.io) or the variable (Docker), and redeploying the authority | none for existing accounts; new sign-ups need the new token |
| `MAIL_PASSWORD` | the same | none |
| `VAULT42_OTP_PROOF_SECRET` | the same | codes issued in the last few minutes stop verifying |
| `FLY_API_TOKEN`, `GH_PAT`, `DOCK_PAT` | creating a new token, replacing the repository secret, revoking the old one | none |
| the **contract signing key** | only after a compromise — see below | every user must sign in again |

**The contract signing key has no rotation command and no tested rotation procedure.** The authority
deliberately refuses to start with a database and no key, so replacing the key is a manual, deliberate act:
it voids every contract, requires re-pinning the server, and makes every user sign in again. Nothing sealed
is lost by it — contracts gate access, they do not encrypt. Treat a suspected compromise of
`authority.key` as an incident: keep the old volume, and rebuild the authority with a new key under
review rather than improvising on production.

## 6.4 Upgrades

On fly.io, merging is upgrading (chapter 5). On Docker, build the new release and replace the containers,
authority first, with the same volumes (chapter 2 §2.9). Take backups first; migrations are forward-only.

## 6.5 Cost and the machines

Both fly.io applications stop when idle and wake on the next request in about 1.5 seconds. To stop or start
them deliberately:

```sh
sh scripts/ops/fly-machines.sh status
sh scripts/ops/fly-machines.sh stop
sh scripts/ops/fly-machines.sh start vault42-authority
```

or the **machines** workflow in the Actions tab. Stopping is safe for the data: a clean shutdown
checkpoints the database, and the key is on the same volume.

## 6.6 What operators can and cannot do

An operator can read metadata — account emails, organisation structure, sizes and times of stored objects
— and can deny service, restore old backups, or delete everything. An operator **cannot** read a secret,
recover a user's lost passphrase, or open a user's keystore escrow: all of those are sealed to keys only
users hold. Say so to users who ask for a recovery.
