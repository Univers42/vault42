# vault42 — Operations Runbook

How to operate, deploy, unseal, recover, and rotate.

## What is shipped vs. designed

**Shipped & proven** (the deployed MVP, see DECISIONS **D9/D10**): the gRPC server
(Ed25519-challenge auth, owner-scoped opaque-envelope SQLite store, local hash-chained
audit, server-side authorship verification without decryption), the zero-knowledge CLI
(`init/whoami/set/get/ls/rm/rotate/share/audit`), the russh SSH edge, and the live fly.io
deployment. Proof: 6-test in-process gRPC battery (`scripts/verify/v01-server-e2e.sh`) +
a live round-trip against `https://vault42.fly.dev`.

**Designed, flag-gated, not yet wired into the deployed server**: the grobase substrate
hop (`verify_key`/`decide`/`audit_append` — set `GROBASE_URL`+`INTERNAL_SERVICE_TOKEN`),
operator-assisted recovery (D5), L2 CMEK at-rest (D8), and `recover`/`rotate-keys`
ceremonies. The sections below marked *(designed)* describe the target, not current
behaviour.

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

## Seal / unseal (L2 at-rest, P7/P9)

vault42 boots **SEALED**: it can store/return ciphertext but cannot run unwrap-assisting operations.
The L2 master seed lives in a fly secret (`VAULT42_UNSEAL_SEED`) and auto-unseals at boot. Manual or
Shamir K-of-N unseal is the documented upgrade. To re-seal: restart the process / rotate the seed.

## Recovery — "I lost my passphrase but can log into fly.io" (D5)

Pre-req: the tenant had `recovery_optin = true` when the secrets were written (recovery is **not**
retroactive). Steps:

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
- **Identity** (`vault42 rotate-keys`): new keypair, re-wrap all the user's secrets, retire the old.
- **Transit KEK / recovery key**: see fly + Vault Transit; crypto-shred is irreversible — confirm.

## Verify the audit chain

`vault42 audit --verify` (or grobase `GET /v1/audit/tenants/{id}/verify`) recomputes the hash chain
and reports the first broken link. Run after any suspected tampering and as a periodic integrity job.
