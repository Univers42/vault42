# Using vault42

vault42 is a **zero-knowledge secrets vault**. You store secrets (API keys, `.env` files,
passwords, notes) and the server **never sees their plaintext** — all encryption and decryption
happen on *your* machine. No other user can read your data, and neither can whoever runs the server.

This guide is for **users** (storing/sharing secrets) and **operators** (running your own vault).
For the architecture decisions see [`DECISIONS.md`](DECISIONS.md); for the security model see
[`THREAT-MODEL.md`](THREAT-MODEL.md); for ops/deploy see [`RUNBOOK.md`](RUNBOOK.md).

---

## Contents

1. [The mental model](#1-the-mental-model)
2. [The hosted duo (live)](#2-the-hosted-duo-live)
3. [Install the CLI](#3-install-the-cli)
4. [Quickstart (5 minutes)](#4-quickstart-5-minutes)
5. [Core concepts](#5-core-concepts)
6. [Command reference](#6-command-reference)
7. [Sharing a secret with someone](#7-sharing-a-secret-with-someone)
8. [Environment & files](#8-environment--files)
9. [Run your own vault (self-host)](#9-run-your-own-vault-self-host)
10. [Security model in one page](#10-security-model-in-one-page)
11. [Troubleshooting & FAQ](#11-troubleshooting--faq)

---

## 1. The mental model

- **Your identity is a keypair**, created locally by `vault42 init` and held in a passphrase-locked
  keystore. The private keys **never leave your machine**. Your identity *is* your tenant — there is
  no email/password account on the server.
- **A secret is sealed locally** (XChaCha20-Poly1305 over a random data key; that key wrapped to your
  X25519 public key; the whole thing signed by your Ed25519 key) and uploaded as an **opaque blob**.
  The server stores bytes it cannot read.
- **To use a hosted vault you register once** with a *contract authority* (`grobase-nano`), which
  signs a **contract** binding your public key to a tenant name. The vault verifies that contract
  offline on every request. Think of the contract as your membership card; your keystore is the key.
- **Two cooperating services** (the "duo"):
  - **vault42** — the data plane. Stores opaque secrets, owner-scoped to your key.
  - **grobase-nano** — the contract authority. Issues contracts at registration, then idles.

You only ever run the **CLI**. The two services are remote.

---

## 2. The hosted duo (live)

A public instance is already running (both apps scale to zero, so the first request after idle
takes a second or two to wake):

| Service | URL | Role |
|---|---|---|
| vault42 (data plane) | `https://vault42.fly.dev` | stores your encrypted secrets |
| grobase-nano (authority) | `https://grobase-nano.fly.dev` | registration / contracts |
| Sign-up portal | `https://site-one-vert-34.vercel.app` | builds your `register` command |

Registration on the hosted instance requires an **invite token** (it is a private "you + friends"
vault). Ask the operator for it; they set it with `fly secrets set VAULT42_REGISTER_TOKEN=…`.

---

## 3. Install the CLI

> **Two CLIs, one vault.** This guide documents the **`vault42`** binary — the *granular,
> per-secret* tool (`set`/`get`/`share`/`rotate`). There is also **`42ctl`** — the *umbrella*
> CLI built on the same vault that adds a **project workflow**: it pushes/pulls your whole
> `*.env` tree at once (`42ctl push --project <name>` / `pull --apply`), logs in by **email
> OTP**, and manages multi-device key escrow. For day-to-day "sync my project's secrets," use
> `42ctl` (run `42ctl --help` for its complete how-to); for surgical single-secret operations
> and sharing, use `vault42` as below. Both encrypt locally and store opaque blobs in the same
> vault42 server.

The CLI is a single Rust binary named `vault42`.

**From source (needs a Rust toolchain + a C compiler):**

```sh
cargo install --git https://github.com/Univers42/vault42 vault42-cli
# installs the `vault42` binary into ~/.cargo/bin
```

**Docker-first (no host Rust)** — build it in the toolchain image and copy it out:

```sh
git clone https://github.com/Univers42/vault42 && cd vault42
docker run --rm -v "$PWD":/work -w /work \
  public.ecr.aws/docker/library/rust:1.96-slim-bookworm \
  sh -c 'apt-get update && apt-get install -y --no-install-recommends pkg-config >/dev/null && \
         cargo build --release -p vault42-cli && cp target/release/vault42 /work/vault42'
./vault42 --help
```

Confirm it runs: `vault42 --help`.

---

## 4. Quickstart (5 minutes)

```sh
# Point the CLI at the hosted duo (or your own — see §9)
export VAULT42_SERVER=https://vault42.fly.dev
export VAULT42_AUTHORITY=https://grobase-nano.fly.dev

# 1. Create your local identity (prompts for a passphrase, no echo)
vault42 init

# 2. Register yourself — pick any tenant name; paste the invite token
vault42 register --tenant alice --token <INVITE_TOKEN>

# 3. Store a secret (read from stdin)
printf 'sk-live-abc123' | vault42 set prod/stripe

# 4. Read it back (decrypted locally, printed to stdout)
vault42 get prod/stripe          # -> sk-live-abc123

# 5. List what you have, see the tamper-evident history
vault42 ls
vault42 audit
```

That's it. The secret was encrypted before it left your machine; the server only ever held an opaque
blob owned by your key.

---

## 5. Core concepts

### Identity & keystore
`vault42 init` generates an **X25519** keypair (encryption) and an **Ed25519** keypair (signing/
identity), seals them under your passphrase (Argon2id), and writes them to the keystore file
(`~/.config/vault42/keystore.v42` by default). Your **principal** is the 16-byte fingerprint of your
Ed25519 public key — that, not a username, is what scopes your data. Back up this file; losing it (and
the passphrase) loses your secrets (there is no server-side recovery in this edition — see
[`THREAT-MODEL.md`](THREAT-MODEL.md)).

### The contract (membership)
`vault42 register` sends only your **public** key to the authority, which returns a **signed contract**
`(tenant, your-key-fingerprint, expiry)`. It is saved to `~/.config/vault42/contract.tok` and attached
to every request. The vault verifies it offline. The contract is a public credential — it holds no
secret. If a vault is configured without an authority (`VAULT42_CONTRACT_PUBKEY` unset), registration
isn't needed and any identity works ("standalone" mode).

### Secrets, paths, versions
A secret is addressed by a **path** you choose (e.g. `prod/stripe`, `ssh/laptop`, `notes/wifi`). Each
`set`/`rotate` appends a new **version** (1, 2, 3, …); `get` returns the latest by default, or a
specific `--version`. Paths and version numbers are visible to the server; **values are not**.

### Addresses (for sharing)
`vault42 whoami` prints your **address** — `v42:<base64url(ed25519_pub‖x25519_pub)>`. Give it to
someone who wants to share a secret *with you*. It contains only public keys.

---

## 6. Command reference

Global flag: `--server <url>` (or `VAULT42_SERVER`, default `http://127.0.0.1:8443`).
The passphrase is prompted (no echo); set `VAULT42_PASSPHRASE` to supply it non-interactively (CI).

### `vault42 init [--force]`
Generate a new identity + keystore. Refuses to overwrite an existing keystore unless `--force`.
Prints your principal and shareable address. Runs fully offline.

```sh
vault42 init
# identity created
# principal: a3b2164332724bcb...
# address:   v42:F2_9bmBA7-G2YFmd...
```

### `vault42 register --authority <url> --tenant <name> [--token <t>]`
Claim a tenant name with the authority and save the returned contract. Sends only your public key.
`--authority` defaults to `$VAULT42_AUTHORITY`; `--token` to `$VAULT42_REGISTER_TOKEN`. Tenant names
are `[A-Za-z0-9_-]`, 1–64 chars.

```sh
vault42 register --tenant alice --token $VAULT42_REGISTER_TOKEN
# registered tenant 'alice' (contract valid until 1813...) ; contract saved to ~/.config/vault42/contract.tok
```

### `vault42 whoami`
Print your principal and shareable address (and confirm the server recognizes you).

### `vault42 set <path> [--file <path>]`
Seal a secret and push it as the next version. Reads the value from `--file`, else from **stdin**.

```sh
printf 'hunter2' | vault42 set notes/wifi
vault42 set prod/key --file ./service-account.json
```

### `vault42 get <path> [--version <n>]`
Fetch and **locally decrypt** a secret to stdout. `--version 0` (default) = latest.

```sh
vault42 get prod/stripe
vault42 get prod/stripe --version 2 > old.txt
```

### `vault42 ls [prefix]`
List your secrets (path, latest version, updated-at), optionally filtered by prefix.

```sh
vault42 ls
vault42 ls prod/
```

### `vault42 rm <path>`
Delete every version of a secret you own.

### `vault42 rotate <path>`
Re-seal the current value under a **fresh** data key and push it as a new version (key rotation
without changing the value).

### `vault42 share <path> --to <address>`
Re-seal `<path>` for another registered identity and deposit it in *their* space at
`shared/<your-principal>/<path>`. They read it with their own key. (You cannot share to your own
address — that's a duplicate-recipient error.)

```sh
vault42 share prod/stripe --to v42:AbCd...   # the recipient's `whoami` address
# shared prod/stripe to v42:AbCd... at shared/a3b21643.../prod/stripe
```
The recipient then runs: `vault42 get shared/a3b21643.../prod/stripe`.

### `vault42 audit [--since <unix-seconds>]`
Stream your tamper-evident audit chain (each entry chains a hash onto the previous). `--since 0`
(default) returns the full chain so the links can be re-verified.

```sh
vault42 audit
# seq 1 ts 1781890852 push <owner>/prod/stripe hash=96f0bcc34b4a
# seq 2 ts 1781890857 rotate <owner>/prod/stripe hash=8430cf8cbfc0
```

---

## 7. Sharing a secret with someone

Zero-knowledge sharing re-encrypts the secret for the recipient — the server still never sees plaintext.

1. **The recipient** registers (so they have an identity + contract) and gives you their address:
   ```sh
   vault42 whoami          # copy the v42:... address line
   ```
2. **You** share the secret to that address:
   ```sh
   vault42 share prod/stripe --to v42:<recipient-address>
   # ... at shared/<your-principal>/prod/stripe
   ```
3. **The recipient** reads it from their own space:
   ```sh
   vault42 get shared/<your-principal>/prod/stripe
   ```

Notes: sharing is a one-time deposit (re-run it to update). Both parties must be registered with the
same authority. Removing access is forward-secure — `rotate` the secret so future versions exclude them.

---

## 8. Environment & files

### Client (CLI)
| Variable | Default | Meaning |
|---|---|---|
| `VAULT42_SERVER` | `http://127.0.0.1:8443` | vault42 data-plane URL (use `https://…` for TLS) |
| `VAULT42_AUTHORITY` | — | contract authority URL (for `register`) |
| `VAULT42_REGISTER_TOKEN` | — | invite token for `register` |
| `VAULT42_KEYSTORE` | `~/.config/vault42/keystore.v42` | your sealed identity |
| `VAULT42_CONTRACT` | `~/.config/vault42/contract.tok` | your saved contract |
| `VAULT42_PASSPHRASE` | — | non-interactive passphrase (CI); else prompted |

### Files on disk
- **Keystore** (`keystore.v42`, `0600`): your passphrase-sealed private keys. **Back this up.**
- **Contract** (`contract.tok`): your signed membership credential (public; re-fetchable by
  re-registering).

Run separate identities by pointing `VAULT42_KEYSTORE`/`VAULT42_CONTRACT` at different paths.

---

## 9. Run your own vault (self-host)

The duo is two tiny apps. The cheapest shape is fly.io with both **scaled to zero** (≈ free). Full
deploy commands are in [`RUNBOOK.md`](RUNBOOK.md); the short version:

```sh
TOK=$(grep '^FLY_TOKEN=' .env.local | cut -d= -f2- | tr -d '"')
FLY="docker run --rm -e FLY_API_TOKEN=$TOK -v $PWD:/work -w /work flyio/flyctl:latest"

# 1. Authority
$FLY apps create grobase-nano --org personal
$FLY volumes create grobase_nano_data --app grobase-nano --region cdg --size 1 --yes
$FLY secrets set VAULT42_REGISTER_TOKEN="$(openssl rand -hex 16)" --stage -a grobase-nano
$FLY deploy --remote-only --ha=false --yes -c fly.contract.toml

# 2. Wire the authority's public key into vault42, then deploy vault42
KEY=$(curl -fsS https://grobase-nano.fly.dev/v1/contract-key | sed 's/.*"public_key":"//;s/".*//')
$FLY apps create vault42 --org personal
$FLY volumes create vault42_data --app vault42 --region cdg --size 1 --yes
$FLY secrets set VAULT42_CONTRACT_PUBKEY="$KEY" --stage -a vault42
$FLY deploy --remote-only --ha=false --yes        # uses ./fly.toml
```

**Server env** (`vault42`): `VAULT42_PORT` (8443), `VAULT42_DB` (`/data/vault42.db`),
`VAULT42_AUTH_SKEW_SECS` (120), `VAULT42_MAX_SECRETS` (per-owner cap; 0 = unlimited, prod uses 1000),
`VAULT42_CONTRACT_PUBKEY` (hex; setting it turns the contract gate **on**). gRPC needs HTTP/2 to the
app — fly.toml sets `[http_service.http_options] h2_backend = true`.

#### Storage backend: SQLite (default) vs **GrobaseStore** (production)

By default the server keeps the opaque-envelope store in a local SQLite file (`VAULT42_DB`). For
production it can instead **delegate storage to a grobase backend** — so grobase owns the Postgres
database (ACID, WAL, backups) and vault42 is the zero-knowledge *motor* on top. This is how the live
`vault42.fly.dev` runs. The server auto-selects GrobaseStore when `VAULT42_STORE != sqlite` and all of
these are set (else it falls back to SQLite):

| Var | Meaning |
|---|---|
| `VAULT42_STORE` | set to `grobase` to select the grobase backend |
| `GROBASE_QUERY_URL` | grobase Kong base, e.g. `https://grobase-stack.fly.dev` (`/query/v1`) |
| `GROBASE_ANON_KEY` | grobase anon apikey (Kong key-auth) |
| `GROBASE_APP_KEY` | a least-privilege scoped key (`mbk_…`) for the vault42 mount |
| `GROBASE_DB_ID` | the vault42 Postgres mount id in grobase |
| `JWT_SECRET` | = grobase's `GOTRUE_JWT_SECRET`; the server mints a per-owner HS256 JWT (sub = uuid5(principal)) so grobase owner-scopes each `/query/v1` write |

The grobase side stores each envelope as base64 **TEXT** in `public.vault42_secrets`, owner-scoped per
request (mount `read_scoped=true`). The server still never holds a key or a plaintext — grobase only
ever sees the opaque blob + the owner id. Provision the vault42 mount + emit these values with grobase's
generic contract provisioner: `bash scripts/provision-contract.sh infra/config/contracts/vault42.json`.

**Authority env** (`grobase-nano`): `VAULT42_CONTRACT_PORT` (8443), `VAULT42_CONTRACT_DB`,
`VAULT42_CONTRACT_KEY` (the signing key, persisted on the volume), `VAULT42_CONTRACT_TTL_DAYS` (365),
`VAULT42_REGISTER_TOKEN` (invite gate). Endpoints: `GET /healthz`, `GET /v1/contract-key`,
`POST /v1/register {tenant, author_pubkey, token?}`.

**Run locally** instead of fly: `docker run` each binary with the env above on `127.0.0.1`, point
the CLI at `http://127.0.0.1:<port>` (plaintext is fine on loopback).

---

## 10. Security model in one page

**Guaranteed:** a full compromise of the host, the vault42 process, or its datastore yields **no
plaintext** and **no cross-tenant access**. The server stores only opaque envelopes; isolation is by
your key fingerprint, enforced per request.

- **Encryption:** XChaCha20-Poly1305 (random per-secret data key) → DEK wrapped per recipient via
  X25519 ECDH+HKDF → Ed25519 author signature over a frozen, length-prefixed canonical AAD.
- **Transport:** HTTPS at the edge; each request is Ed25519-signed (binds the method + a fresh
  timestamp) so it can't be replayed onto a different operation; a valid contract is required.
- **Integrity:** the server verifies your envelope's author signature **without decrypting** before
  storing; reads are bound to the requested secret-id + minimum revision (anti-substitution,
  anti-rollback); a per-owner tamper-evident audit hash-chain records every operation.
- **Guardrails:** invite-token registration (anti-squatting/DoS), per-owner secret quota.

**Honestly NOT covered in this edition** (documented in `THREAT-MODEL.md`): metadata (paths, sizes,
sharing graph) is not encrypted; there is no server-side passphrase recovery; an attacker *inside*
the server's private network could replay a captured read within the 120 s skew window (the request
body isn't signature-bound yet); a compromised client with the keystore unlocked can read its own
secrets.

---

## 11. Troubleshooting & FAQ

**`Unauthenticated: missing auth metadata` / `invalid or expired contract`** — you're not registered
(or the contract expired). Run `vault42 register …`. On the hosted duo you need the invite token.

**`PermissionDenied: contract not bound to this key`** — the contract belongs to a different identity.
Re-register with the keystore you're actually using (check `VAULT42_KEYSTORE`).

**`NotFound: no such secret`** — that path doesn't exist *for your identity*. Each identity has its own
space; another tenant's secret is invisible by design. For shared secrets, read
`shared/<sharer-principal>/<path>`.

**`FailedPrecondition: version conflict`** — someone (or another device) updated the secret between
your read and write. Just re-run the command.

**`ResourceExhausted: per-owner secret quota exceeded`** — you hit the operator's per-owner cap
(distinct paths). Remove unused secrets or ask the operator to raise `VAULT42_MAX_SECRETS`.

**First request hangs ~1–2 s** — the hosted apps scale to zero; the first call wakes them. Normal.

**Lost passphrase / keystore** — there is no recovery in this edition; the secrets are unrecoverable
by design (that is the zero-knowledge guarantee). Keep a backup of `keystore.v42` and your passphrase.

**Can I run two identities?** Yes — set `VAULT42_KEYSTORE` and `VAULT42_CONTRACT` to different files
per identity.

**Is my data readable by the operator?** No. The operator holds only ciphertext and your public keys.
That is the entire point.
