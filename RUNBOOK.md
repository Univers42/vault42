# vault42 — Operations Runbook

How to operate, deploy, unseal, recover, and rotate.

## What is shipped vs. designed

**Shipped & proven** (the deployed MVP, see DECISIONS **D9/D10**): the gRPC server
(Ed25519-challenge auth, owner-scoped opaque-envelope SQLite store, local hash-chained
audit, server-side authorship verification without decryption), the zero-knowledge CLI
(`init/whoami/set/get/ls/rm/rotate/share/audit`), and the live fly.io deployment. Proof: a 13-test
in-process gRPC battery (`scripts/verify/v01-server-e2e.sh`, which asserts cargo's exit status rather
than a test count) + a live round-trip against `https://vault42.fly.dev`.

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

- **`grobase-nano`** → `https://grobase-nano.fly.dev` — the contract authority. People
  self-register and get a signed contract; it idles after.
- **`vault42`** → `https://vault42.fly.dev` — the zero-knowledge data plane, gated on a
  valid contract (`VAULT42_CONTRACT_PUBKEY` = the authority's public key).

End-to-end, a new user does:

```sh
export VAULT42_SERVER=https://vault42.fly.dev VAULT42_AUTHORITY=https://grobase-nano.fly.dev
vault42 init                                   # local identity (Ed25519 + X25519)
vault42 register --authority $VAULT42_AUTHORITY --tenant alice   # → saves a contract
printf my-secret | vault42 set prod/db         # sealed locally, stored opaque, contract-gated
vault42 get prod/db                            # decrypted locally
```

To wire the gate after deploying the authority: fetch its key and stage it on vault42.

```sh
KEY=$(curl -fsS https://grobase-nano.fly.dev/v1/contract-key | sed 's/.*"public_key":"//;s/".*//')
$FLY secrets set VAULT42_CONTRACT_PUBKEY="$KEY" --stage -a vault42 && $FLY deploy -a vault42
```

## Deploy (fly.io)

The deployed app is **`vault42`** → `https://vault42.fly.dev` (region `cdg`; Madrid is not
offered to this account — D10). TLS terminates at the fly edge and the proxy speaks h2c to
the tonic server (`[http_service.http_options] h2_backend = true` — required for gRPC).
Deploy the authority with `-c fly.contract.toml`. Drive fly with the prebuilt image and the
`FLY_TOKEN` (never printed/committed):

```sh
TOK=$(grep '^FLY_TOKEN=' ../../.env.local | cut -d= -f2- | tr -d '"')
FLY="docker run --rm -e FLY_API_TOKEN=$TOK -v $PWD:/work -w /work flyio/flyctl:latest"
$FLY apps create vault42 --org personal                 # once
$FLY volumes create vault42_data --app vault42 --region cdg --size 1 --yes  # encrypted, once
$FLY deploy --remote-only --ha=false --yes              # build on fly's remote builder + release
$FLY status --app vault42 ; $FLY logs --app vault42
```

`fly.toml` (repo root) is the source of truth: 256 MB shared-cpu VM, encrypted volume at
`/data`, env `VAULT42_{HOST,PORT,DB,AUTH_SKEW_SECS}`. To wire a private grobase later:
`$FLY secrets set GROBASE_URL=... INTERNAL_SERVICE_TOKEN=...` (then the audit/authz seam
activates; no redeploy of code needed).

### Live verification (round-trips the real deployment)

```sh
docker run --rm -e VAULT42_SERVER=https://vault42.fly.dev -e VAULT42_KEYSTORE=/tmp/ks.v42 \
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
