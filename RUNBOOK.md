# vault42 — Operations Runbook

How to operate, deploy, unseal, recover, and rotate.

## What is shipped vs. designed

**Shipped & proven** (the deployed MVP, see DECISIONS **D9/D10**): the gRPC server
(Ed25519-challenge auth, owner-scoped opaque-envelope SQLite store, local hash-chained
audit, server-side authorship verification without decryption), the zero-knowledge CLI
(`init/whoami/set/get/ls/rm/rotate/share/audit`), and the live fly.io deployment. Proof: a 13-test
in-process gRPC battery (`scripts/verify/v01-server-e2e.sh`, which asserts cargo's exit status rather
than a test count) + a live round-trip against `https://vault42-server.fly.dev`.

`vault42-ssh` used to be in that list and is neither shipped nor proven. It has zero tests, no CI
job, no Dockerfile and no fly config: `deploy/Dockerfile` builds `vault42-server` and
`deploy/Dockerfile.contract` builds `vault42-contract`, and those are the only two images that
exist. It is 279 lines of network-facing code that nothing builds, runs, or deploys.

**Designed, not built**: the grobase substrate hop (`verify_key`/`decide`/`audit_append`),
operator-assisted recovery (D5), L2 CMEK at-rest (D8), seal/unseal state, the
`recover`/`rotate-keys` ceremonies, and audit-chain verification. Every section describing
one now carries **NOT IMPLEMENTED** in its own heading, because the *(designed)* marker this
paragraph used to point at was never actually applied to any of them — so those sections read
as live procedure for as long as this file has existed. Treat an unmarked heading as current
behaviour and a marked one as a specification you cannot run.

## The deployed duo (managed multi-tenancy, ~free)

Two scale-to-zero fly apps in `cdg` (D11), ~$0.30/mo total (volumes only):

- **`vault42-authority`** → `https://vault42-authority.fly.dev` — the contract authority. People
  self-register and get a signed contract; it idles after.
- **`vault42-server`** → `https://vault42-server.fly.dev` — the zero-knowledge data plane, gated
  on a valid contract (`VAULT42_CONTRACT_PUBKEY` = the authority's public key).

The app is `vault42-server`, not `vault42`. Fly app names are unique across all of fly.io and
`vault42` is held by someone else, so the short name was never ours to deploy to. Anything
still pointing at `vault42.fly.dev` is pointing at a stranger's machine.

End-to-end, a new user does:

```sh
export VAULT42_SERVER=https://vault42-server.fly.dev VAULT42_AUTHORITY=https://vault42-authority.fly.dev
vault42 init                                   # local identity (Ed25519 + X25519)
vault42 register --authority $VAULT42_AUTHORITY --tenant alice   # → saves a contract
printf my-secret | vault42 set prod/db         # sealed locally, stored opaque, contract-gated
vault42 get prod/db                            # decrypted locally
```

To wire the gate after deploying the authority: fetch its key and stage it on vault42.

```sh
KEY=$(curl -fsS https://vault42-authority.fly.dev/v1/contract-key | sed 's/.*"public_key":"//;s/".*//')
$FLY secrets set VAULT42_CONTRACT_PUBKEY="$KEY" --stage -a vault42 && $FLY deploy -a vault42
```

## Deploy (fly.io)

Deploys are automated. A push to `develop` runs `vault42-ci`; when that goes green the
`deploy` workflow builds both images, releases them, smoke-tests the result, and stops the
machines again. Nothing below needs running by hand in the normal case — it is here for the
first deploy on a new account and for the day the automation is what's broken.

flyctl is not installed on the host, so it runs from its own image. The token is read from
`../.env` and never printed:

```sh
export FLY_API_TOKEN="$(sed -n 's/^FLY_TOKEN=//p' ../.env)"
FLY="docker run --rm -e FLY_API_TOKEN flyio/flyctl:v0.4.101"
```

Creating the two apps and their volumes, once per account:

```sh
$FLY apps create vault42-authority --org personal
$FLY apps create vault42-server    --org personal
$FLY volumes create vault42_authority_data --app vault42-authority --region cdg --size 1 --yes
$FLY volumes create vault42_data           --app vault42-server    --region cdg --size 1 --yes
```

The authority's secrets are staged by the `deploy` workflow, from this repository's own
Actions secrets of the same names, in the step before the release that applies them. **Only
the two `create` commands above are manual now** — a deploy onto fresh, empty apps restores
mail and the invite gate by itself.

That step exists because it did not, and the gap was invisible: both apps were once deleted
and recreated, the workflow redeployed them green, and the authority came up with no mail
transport and an open signup while answering `/healthz` perfectly. The only symptom was
`second_factors=false` in one startup line.

The three second-factor secrets are staged together or not at all, because the authority
refuses to start when a proof secret is present with no way to deliver a code — a partial set
is a machine that never boots, so the workflow refuses rather than releasing one.

By hand, if the automation is what's broken:

```sh
$FLY secrets import --stage --app vault42-authority <<'EOF'
MAIL_FROM=…
MAIL_PASSWORD=…
VAULT42_OTP_PROOF_SECRET=…
VAULT42_REGISTER_TOKEN=…   # gates ACCOUNT CREATION (/v1/auth/signup), not /v1/register
EOF
```

Pass the token by NAME (`-e FLY_API_TOKEN`, as `$FLY` above does), never inline as
`-e FLY_API_TOKEN=$(…)`. A fly token is two words — `FlyV1 fm2_…` — so unquoted expansion
splits it and docker reads the tail as an image name.

**Deploy the authority first.** The server's `VAULT42_CONTRACT_PUBKEY` is the authority's
public key, so releasing the server first pins it to a key that does not exist yet, and every
request is then rejected by a server that looks perfectly healthy.

```sh
BUILD="-v /var/run/docker.sock:/var/run/docker.sock -v $PWD:/work -w /work"
docker run --rm -e FLY_API_TOKEN $BUILD flyio/flyctl:v0.4.101 \
  deploy --config fly.authority.toml --app vault42-authority --local-only --ha=false --yes
```

`--local-only` builds on this machine and pushes the image. The alternative, `--remote-only`,
builds on a fly remote builder, which is itself a billed machine. `--ha=false` creates one
machine; fly's default is two, which doubles the compute bill for an app serving one operator.

Then wire the gate. Check the key before storing it — this recipe used to pipe `curl` straight
into `fly secrets set`, so an authority that was briefly unreachable wrote an empty secret, and
an empty key used to mean "standalone", which accepts any self-generated keypair:

```sh
KEY=$(curl -fsS https://vault42-authority.fly.dev/v1/contract-key | sed 's/.*"public_key":"//;s/".*//')
[ "${#KEY}" -eq 64 ] || { echo "refusing a ${#KEY}-char key"; exit 1; }
printf 'VAULT42_CONTRACT_PUBKEY=%s\n' "$KEY" | $FLY secrets import --stage --app vault42-server
docker run --rm -e FLY_API_TOKEN $BUILD flyio/flyctl:v0.4.101 \
  deploy --config fly.toml --app vault42-server --local-only --ha=false --yes
```

Finally, prove the deployment rather than assuming it:

```sh
sh scripts/smoke/post-deploy.sh
```

## Cost, and turning the machines off

The standing bill is two 1 GB encrypted volumes and nothing else. Both apps set
`auto_stop_machines = "stop"` with `min_machines_running = 0`, so an idle machine stops and
bills no compute; a request wakes it in about a second and a half. Measured cold, from both
machines stopped to a green smoke run: 3.5s.

Neither app has a dedicated IPv4 (that is a paid add-on); both use fly's shared v4 and a free
dedicated v6. Each app runs ONE machine, because every deploy passes `--ha=false`; fly's default
is two, which would double the compute bill for apps serving one operator. And there is no
`fly-builder-*` app in the org, because builds happen on the machine or runner doing the deploy
rather than on a fly remote builder, which is itself a billed machine.

Audited state, which is the cheapest shape two separate apps can take:

| Resource | Count | Note |
|---|---|---|
| Apps | 2 | authority and server, separate binaries and separate volumes |
| Machines | 1 each | `shared-cpu-1x`, 256 MB, the smallest fly offers |
| Volumes | 1 GB each | the fly minimum, encrypted, with scheduled snapshots |
| Dedicated IPv4 | 0 | the only paid networking add-on, avoided |
| Managed Postgres / Redis / builders | 0 | none, and none needed |

One app instead of two would save one volume. It would also need a supervisor inside a
distroless image that has no shell, and would put the contract signing key on the same volume as
the vault's data. Neither is worth $0.15 a month.

To take control of the switch by hand, from the Actions tab run the **machines** workflow and
pick `status`, `stop`, or `start`. The same thing locally:

```sh
sh scripts/ops/fly-machines.sh status
sh scripts/ops/fly-machines.sh stop            # both apps
sh scripts/ops/fly-machines.sh start vault42-authority
```

Stopping is safe for the data. A clean shutdown checkpoints the SQLite write-ahead log into
the database, and the volume keeps both; the signing key is on the same volume and is
verified stable across a full stop/start.

To make the apps reachable **only** after pressing start, set `auto_start_machines = false` in
`fly.toml` and `fly.authority.toml`. One line each. Everything else keeps working, but 42ctl
will fail against a stopped app instead of waking it.

### Three Actions secrets are unused, and one is a live mail password

The workflows reference `FLY_API_TOKEN`, `VAULT42_REGISTER_TOKEN` and `DOCK_PAT`. The repository
also holds `MAIL_FROM`, `MAIL_PASSWORD` and `VAULT42_OTP_PROOF_SECRET`, and nothing reads them:
the authority needs those three as **fly** secrets, which they are, and no CI job needs them at
all.

`MAIL_PASSWORD` is a working Titan credential. Sitting unused in the Actions store, it is
reachable by any workflow anyone adds to this repository, on an account that also sends mail from
the project's domain. Actions secrets are not exposed to pull requests from forks, so the exposure
is to whoever can push a workflow — but that is a larger set than "nobody", and the credential
buys nothing there.

`VAULT42_OTP_PROOF_SECRET` is additionally out of step: the value on fly was regenerated when the
authority was first deployed, so the Actions copy is a different secret that matches nothing.

Removing all three is safe and is left to the operator, since deleting someone's stored
credentials is not a change to make on their behalf:

```sh
gh secret delete MAIL_PASSWORD
gh secret delete MAIL_FROM
gh secret delete VAULT42_OTP_PROOF_SECRET
```

### Mail delivery is configured and NOT proven

The Titan credential authenticates — that was checked directly against `smtp.titan.email:465`
— and the authority refuses to start when second factors are on and the mail settings are
unusable, so a running authority proves the configuration parses. It does not prove the machine
can reach Titan. Nothing has yet sent a message from the deployed app.

That gap matters more than it looks, because **a delivery failure is invisible from outside**.
`issue_code` hands delivery to a spawned task and answers `200 OK` either way, deliberately, so
the response time cannot reveal whether an account exists. The only trace of a failure is a
`could not deliver a one-time code` warning in the app logs. A user who never receives a code
sees exactly what a user with a slow inbox sees.

To prove it, request a code for an address that has an account and then look:

```sh
$FLY logs --app vault42-authority | grep -i "could not deliver"
```

Silence there, plus the code arriving, is the proof. This is deliberately not automated: every
run delivers real mail to a real inbox, which is an outward-facing side effect that belongs to
an operator's decision rather than a scheduled job's.

### The real-project scenario

`scripts/smoke/inception-live.sh` drives the deployed vault with an actual project —
Univers42/Inception, whose configuration is `srcs/.env` and whose six credentials
docker-compose mounts by path out of `secrets/`. It fills both, pushes, **stops both machines
cold**, pulls onto the wiped tree, and requires every file back byte-identically with its mode
intact.

```sh
export C42=../42ctl/target/debug/42ctl
export FT_REGISTER_TOKEN=…            # the authority gates /v1/register
export FLY_API_TOKEN="$(sed -n 's/^FLY_TOKEN=//p' ../.env)"
sh scripts/smoke/inception-live.sh
```

Stopping the machines mid-scenario is the point. Everything else could be proved against a
local container; that the data outlives the machine that received it cannot, and that is the
assumption the scale-to-zero cost model rests on.

The wipe is an assertion, not a step. If it silently failed, every byte comparison after it
would pass against files that were never deleted, and the run would prove nothing while
reporting that everything was restored.

Run it from the Actions tab as the **scenario** workflow. It is deliberately not on a schedule:
each run registers a tenant on the production authority and nothing here deletes an account, so
the residue accumulates. It also needs a 42ctl carrying the `secrets/` directory fix — point
`c42_ref` at a branch that has it.

### Live verification (round-trips the real deployment)

```sh
docker run --rm -e VAULT42_SERVER=https://vault42-server.fly.dev -e VAULT42_KEYSTORE=/tmp/ks.v42 \
  -e VAULT42_PASSPHRASE=… -v $PWD:/work -w /work <toolchain> sh -c '
    cargo build -q -p vault42-cli && B=target/debug/vault42
    $B init && printf my-secret | $B set app/key && [ "$($B get app/key)" = my-secret ] && echo OK'
```

`VAULT42_PASSPHRASE` supplies the keystore passphrase non-interactively (automation/CI);
omit it for an interactive no-echo prompt.

## Build & test (Docker-first — no host cargo)

```sh
make rust-check    # clippy -D warnings
make rust-test     # cargo test --workspace
make rust-build    # release binaries
make security      # cargo-audit + cargo-deny + gitleaks
make verify        # the v01..vNN gate battery
```

## gitflow

- `develop` is the integration branch; cut `feature/<phase>-<slug>` from it, PR back (squash).
- `release/x.y.0` off `develop` → stabilize → merge to `main` + back to `develop`; tag `vx.y.0`.
- `hotfix/x.y.z` off `main` → `main` + `develop`.
- **No co-author trailer** on any commit. Pushes/tags/deploys are operator-triggered (irreversible).

## Seal / unseal (L2 at-rest, P7/P9) — NOT IMPLEMENTED

**There is no seal state.** `VAULT42_UNSEAL_SEED` appears in no `.rs` file in the workspace, and the
`Unseal` RPC authenticates the caller and then unconditionally answers `Unsealed`, progress 100
(`vault42-server/src/grpc.rs:190-204`). Nothing is ever sealed, so nothing can be re-sealed by
restarting, and that RPC reports a constant rather than a reading. Never cite it as evidence.

L1 zero-knowledge does not depend on this — the server holds no recipient private key either way — so
what is actually missing is the ability to take the crypto plane offline during an incident.

The design below is the P7/P9 intent, kept as the spec, and is **not** current behaviour: vault42
would boot SEALED, able to store and return ciphertext but unable to run unwrap-assisting operations;
the L2 master seed would live in a fly secret and auto-unseal at boot; manual or Shamir K-of-N unseal
is the documented upgrade, and re-sealing would be a restart or a seed rotation.

## Recovery — "I lost my passphrase but can log into fly.io" (D5) — NOT IMPLEMENTED

**There is no recovery verb, and no production envelope carries a recovery wrap.** `vault42 recover`
does not exist in `vault42-cli`, and every production compose site in both clients passes
`recovery: None` (`42ctl/src/adapters/compose.rs:53,104,140,150`; `vault42-cli/src/compose.rs:50,72`),
so no shipped write has ever attached a recovery `WrappedDek`. The `Recovery` recipient kind is
implemented in `vault42-core` and covered by the conformance battery, but nothing reaches it. Today a
lost passphrase means the data is gone — say so to anyone who asks, rather than promising this
ceremony.

The steps below are the D5 spec for when that changes, not a procedure you can run. Pre-req would be
that the tenant had `recovery_optin = true` when the secrets were written (recovery is **not**
retroactive):

1. Operator proves fly.io account access (the boot-injected Transit token is present in the running
   server).
2. Generate a fresh client identity (`vault42 init` on the new device).
3. Run the admin-gated `vault42 recover --tenant <t> --user <u>` (passkey step-up if enabled).
4. The server `cmek.Open`s the per-tenant recovery private key (zeroized after the ceremony),
   unwraps each secret's DEK via the recovery `WrappedDek`, re-wraps for the fresh identity, bumps
   `rev`, re-signs as the recovery author, and stores.
5. Adopt the fresh identity; retire the lost one. Every step is recorded in the audit chain.

## Key rotation

- **Service token** (`INTERNAL_SERVICE_TOKEN`): set `INTERNAL_SERVICE_TOKEN_PREV` to the old value,
  deploy the new token to both vault42 and grobase, then clear `_PREV` after the skew window.
- **Secret DEK** (`vault42 rotate <path>`): fresh DEK, re-encrypt, re-wrap for the current recipient
  set, bump `rev`.
- **Identity**: **not implemented.** There is no `rotate-keys` verb in either client, and
  `keys init --force` mints an unrelated identity that re-wraps nothing. See THREAT-MODEL R18.
- **Transit KEK / recovery key**: see fly + Vault Transit; crypto-shred is irreversible — confirm.

## Backups

`fly console --app vault42-authority --command "vault42-authority backup /data/backup-$(date +%F).db"`

Then copy it off the volume. A backup that lives only on the volume it protects is not a backup.

**Never back up by copying `authority.db`.** With write-ahead logging that file can be a nearly
empty shell while every row lives in `authority.db-wal` beside it, so the copy restores CLEANLY
and EMPTY: the copy succeeds, the restore succeeds, the server starts, and the vault is gone. No
step reports an error, and you find out when you need it. `VACUUM INTO`, which is what the
subcommand runs, asks SQLite for a consistent snapshot of the whole database including the log,
as one file with no `-wal` or `-shm` to remember. It is safe against a live server and needs no
downtime.

The subcommand exists because the image is distroless: no shell, no `sqlite3`, nothing else on
that machine can read the database. It refuses to overwrite an existing file, so a mistyped path
cannot destroy the previous backup.

To restore: stop the app, remove `authority.db`, `authority.db-wal` and `authority.db-shm`, put
the snapshot in place as `authority.db`, and start. The signing key is a SEPARATE file and is not
in the snapshot — restore `authority.key` too, or the authority will refuse to start rather than
mint a replacement and invalidate every contract it ever issued.

Gate `v28-backup-restore-drill` runs this whole cycle on every battery: it signs up an account,
snapshots a live server, destroys the original, restores, and requires that account to still
authenticate. It also asserts that the naive `.db`-only copy LOSES the account, so the reason for
`VACUUM INTO` is enforced by a test rather than by this paragraph.

## Verify the audit chain — NOT IMPLEMENTED

**No client verifies the chain.** `audit` takes only `--since` (`42ctl/src/cli.rs:234`); there is no
`--verify` flag, and both audit clients discard `prev_hash` before printing, so the link a verifier
would need never reaches the operator at all. The chain is written correctly server-side
(`vault42-server/src/audit_store.rs:104-151`) — it is simply never checked.

Until a verifying client exists, treat the audit log as a convenience record and not as
tamper-evidence, and do not offer chain verification as a control. See THREAT-MODEL R3.
