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

Mid-build. See `DECISIONS.md` (locked architecture), `THREAT-MODEL.md` (adversaries + the recovery
trade-off), `RUNBOOK.md` (operate / unseal / recover), and `HUMAN-ATOMS.md` (the human/money/account
actions left to reach GA).

## License

AGPL-3.0-only (see `LICENSE`). SDKs/clients calling a vault42 server are not bound by the copyleft.
