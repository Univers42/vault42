# vault42

A self-hosted, **zero-knowledge** secrets vault — the small, operator-owned cousin of HashiCorp
Vault / Bitwarden. It enciphers secrets (API keys, `.env`, notes, archives) so the **server can
never read plaintext**, and no tenant can read another's data — even under full compromise of the
host, the vault42 process, **or** the grobase datastore it rides on.

Surfaces: a Rust **CLI** (primary), **gRPC/HTTPS**, and **SSH**. Multi-tenant. Built entirely in
Rust on top of [grobase](https://github.com/Univers42/grobase) (a private REST substrate providing
auth, ABAC, tenant isolation, a tamper-evident audit chain, and an at-rest CMEK envelope).

## The one guarantee

> A full compromise of the infrastructure, the vault42 process, **or** the grobase datastore must
> not yield a single secret's plaintext, nor let one tenant read another's data.

All plaintext crypto happens **client-side** (XChaCha20-Poly1305 over a random DEK; the DEK wrapped
per recipient via X25519; an Ed25519 author signature over a frozen canonical AAD; Argon2id keystore).

## Using it → [`USERDOC.md`](USERDOC.md)

Full user guide (install, the CLI, registration, sharing, self-hosting, troubleshooting):
**[`USERDOC.md`](USERDOC.md)**. A live instance is running as a two-app, scale-to-zero duo:

| Service | URL | Role |
|---|---|---|
| vault42 (data plane) | `https://vault42.fly.dev` | stores your encrypted secrets |
| grobase-nano (authority) | `https://grobase-nano.fly.dev` | registration / signed contracts |
| Sign-up portal | `https://site-one-vert-34.vercel.app` | builds your `register` command |

```sh
export VAULT42_SERVER=https://vault42.fly.dev VAULT42_AUTHORITY=https://grobase-nano.fly.dev
vault42 init                                          # local identity (keys never leave your machine)
vault42 register --tenant alice --token <INVITE>      # one-time, sends only your public key
printf 'sk-live-…' | vault42 set prod/stripe          # sealed locally, stored opaque
vault42 get prod/stripe                               # decrypted locally
```

## Layout

```
contracts/        protobuf (vault/v1 + authz/v1) — the typed wire spine
crates/
  vault42-core/   the pure, I/O-free crypto heart (the zero-knowledge boundary)
  vault42-server/ public gRPC/HTTPS edge — a stateless orchestrator (never sees plaintext)
  vault42-cli/    the zero-knowledge client (all plaintext crypto local)
  vault42-ssh/    hardened SSH edge (russh; transport-only auth)
  vault42-conformance/  property + fuzz battery
scripts/verify/   the v01..vNN gate battery (mirrors grobase)
deploy/           fly.io topology, secrets templates, network policy
```

## Build (Docker-first — no host cargo)

```sh
make rust-check   # clippy -D warnings
make rust-test    # cargo test --workspace
make rust-build   # release binaries
make security     # cargo-audit + cargo-deny + gitleaks
make verify       # the gate battery
```

## Status

**v0.1.1 — deployed and live.** The zero-knowledge core, the gRPC server, the CLI, the russh edge,
and the managed multi-tenant duo (vault42 + the `grobase-nano` contract authority) are built,
tested (thousands of property/edge cases + multi-tenant + live), and running on fly.io (scale-to-zero,
≈ free). See [`USERDOC.md`](USERDOC.md) (how to use it), `DECISIONS.md` (architecture, incl. D9–D11),
`THREAT-MODEL.md` (adversaries + the recovery trade-off), `RUNBOOK.md` (operate / deploy), and
`HUMAN-ATOMS.md` (remaining human/money/account actions).

## License

AGPL-3.0-only (see `LICENSE`). SDKs/clients calling a vault42 server are not bound by the copyleft.
