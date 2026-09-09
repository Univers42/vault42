# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

vault42 is a self-hosted **zero-knowledge** secrets vault, all Rust. All plaintext crypto happens
client-side; the server stores an opaque `Envelope` blob it cannot decrypt. Read `.claude/AGENTS.md`
(binding repo rules) and `DECISIONS.md` (D0–D12, the architecture record) before non-trivial work.

**Precedence in this repo** overrides the global default: `security ≈ correctness > performance >
minimalism > readability > style` (D0). Record every trade-off in `DECISIONS.md`.

## Build, test, lint

There is **no host cargo** — everything runs in Docker via the `Makefile`.

```sh
make fmt-check    # cargo fmt --all -- --check
make rust-check   # clippy --workspace --all-targets -- -D warnings
make rust-test    # cargo test --workspace
make rust-build   # release binaries
make security     # cargo-audit + cargo-deny + gitleaks
make verify       # scripts/verify gate battery
```

**The Makefile default image `mini-baas-rust-toolchain:latest` is built by grobase and is usually
absent here.** Override it, and add the components the slim image lacks (verified: plain
`rust:1.96-slim-bookworm` ships neither rustfmt nor clippy, so a bare override fails):

```sh
export RUST_TOOLCHAIN_IMG=public.ecr.aws/docker/library/rust:1.96-slim-bookworm
docker run --rm -v "$PWD":/work -w /work \
  -v vault42-cargo-registry:/usr/local/cargo/registry \
  -v vault42-cargo-git:/usr/local/cargo/git -v vault42-target:/work/target \
  "$RUST_TOOLCHAIN_IMG" sh -c 'rustup component add rustfmt clippy && cargo fmt --all -- --check'
```

Swap the final `cargo` command for any other lifecycle step. CI does the same thing
(`.github/workflows/ci.yml`). Note `Cargo.toml` declares `rust-version = 1.91` while CI and
`deploy/Dockerfile` build on 1.96.

**A single test** — reuse the same `docker run …` prefix and pass a crate plus a filter:

```sh
cargo test -p vault42-server e2e::                                    # the gRPC battery (13 tests)
cargo test -p vault42-conformance every_single_byte_flip_is_rejected  # one proptest case
cargo test -p vault42-core aad::                                      # one module's inline tests
```

`protoc` is vendored by `protoc-bin-vendored`; never install a system protoc.

### The verify gates

`scripts/verify/run-gate-battery.sh [--fast|--all|<gate>...] [--strict]`. Twelve gates pass under
`--all --strict` today: v01, v12, v16-v21, v25-v28. **The discipline that keeps them honest lives in
`.claude/rules/verify-gates.md` and every rule in it was written by a gate that lied — read it before
adding or trusting one.**

## Architecture

Crate graph, inner to outer. Only `vault42-core` may produce or consume an `Envelope`.

| Crate | Role |
|---|---|
| `vault42-core` | the crypto heart — pure, I/O-free, the zero-knowledge boundary |
| `vault42-proto` | tonic codegen from `contracts/` (`vault.v1`, `authz.v1`) |
| `vault42-cli` | the client; owns *all* filesystem I/O and the plaintext boundary |
| `vault42-server` | stateless gRPC edge; validates and stores opaque bytes |
| `vault42-grobase` | REST+HMAC client seam to a private grobase control plane |
| `vault42-contract` | contract signing, **lib+bin**: the authority consumes the lib |
| `vault42-authority` | accounts, sessions, orgs, teams, RBAC — the standalone control plane |
| `vault42-ssh` | russh edge, publickey allowlist only |
| `vault42-conformance` | test-only proptest/edge battery, excluded from `default-members` |

`vault42-core` is I/O-free **structurally, not by lint** — its dependency list simply contains no
filesystem, network, or async crate. Keep it that way; if you need I/O, it belongs in the caller.
`unsafe_code = "forbid"` workspace-wide.

### Seal / open

`seal()` builds the canonical AAD, generates a random DEK and 24-byte nonce, encrypts the payload
with XChaCha20-Poly1305, wraps the DEK per recipient (ephemeral X25519 ECDH → HKDF-SHA256 → a
one-time KEK → AEAD), then Ed25519-signs `canonical_aad ‖ blake3(ciphertext)`. `open()` runs every
check *before* any decryption: scope and rollback (`rev >= min_rev`), the recovery-wrap gate,
duplicate recipient rejection, then `verify_strict` against a fingerprint-pinned author key.

### The canonical AAD is FROZEN

`crates/vault42-core/src/aad.rs` — domain tag `vault42/aad/v2`, then every field length-framed in
fixed positional order. It is injective, and it is the *only* thing the author signature covers, so
its bytes must never change. A golden BLAKE3 digest pins it in that module's tests. **A failing
golden digest is the alarm working, not a value to update** — changing the AAD invalidates every
signature ever produced. New fields need a `version` bump and a migration path, per D6/R8.

### Server request path

`main.rs` → `grpc.rs` (a deliberately logic-free adapter: authenticate, then delegate) → `authn.rs`
→ `ops_read.rs` / `ops_write.rs` → the `SecretStore` trait in `store_trait.rs`.

Identity is the client's **Ed25519 author key**, not an API key (D9). Every request carries
`x-v42-ts` / `x-v42-pub` / `x-v42-sig`, an Ed25519 signature over `"{ts}\n{grpc-method}"` — so a
signature is bound to one method and replay-bounded by `VAULT42_AUTH_SKEW_SECS`. The principal is the
key's fingerprint, which is also the storage owner scope and the envelope author: one identity, no
password, no server-side secret. When `VAULT42_CONTRACT_PUBKEY` is set, `x-v42-contract` is also
verified **offline** (signature, expiry, author-fingerprint binding) — the authority is never on the
request path, which is what lets it scale to zero (D11).

The server enforces integrity without decrypting: `verify_envelope_author` checks the blob's
signature against the caller's transport key, and non-share writes require
`envelope.metadata.owner == caller.id`. `share` is the only path that may write a foreign owner.

### The authority

`vault42-authority` is the standalone replacement for the grobase control plane: grobase cannot run
inside the fly.io budget it protects, so identity and permissions live here instead. It is axum over
embedded SQLite with versioned migrations in `store/migrate.rs`, and it scales to zero.

**Its API is not a design choice.** 42ctl already implements the whole client against grobase, so the
authority must satisfy routes that exist and are exercised. `42ctl/src/adapters/rbac.rs` is the
authoritative schema for org, team, group, environment, invite, grant and pubkey shapes. Read it
before changing a response body.

Two details carry the security model. Taking `Principal` as an axum extractor makes a route
authenticated by construction, so the check cannot be forgotten inside a handler body. And the store
uses a `max_size(1)` pool on purpose: it serializes statements through one connection, which is what
makes read-then-write sequences atomic without explicit locking.

Sessions hold only a BLAKE3 hash of an opaque 32-byte random bearer token. There is no JWT: a token
with no claims cannot be tampered with, and revocation is a row update rather than waiting out an
expiry.

**`auth::handlers::mint_session` is the only place a sign-in mints a session**, and the second-factor
check is inside it. That is the design, not an implementation detail: a new sign-in route cannot
forget the check because it cannot mint a session without going through it. The GitHub device flow
arrives the same way. Do not insert `insert_session` into a new login path — call `mint_session`.

Two constraints in the wrap bookkeeping are worth knowing before touching grants. `fulfilled`
returns `members` AND `missing`, and they answer different questions: `missing` is a provisioning
worklist that empties as members are wrapped, `members` is everyone the grant authorizes. Rotation
must read `members` — reading `missing` re-wraps nobody once provisioning has converged, which
silently strands the environment. And a wrap is addressed by `(env_id, epoch)`, both required,
because a project-wide grant spans environments and every rotation replaces the key.

`authorized_members` resolves organization membership at read time rather than trusting the grant
row, so no removal path can forget to revoke. `grants.grantee_id` is polymorphic and carries no
foreign key, which is why the join is there.

### Second factors and mail

One-time codes are minted and verified here now; grobase used to do it. The proof format lives in
`vault42-contract::otp`, which both mints and verifies it, so the two services cannot drift — a
round-trip test in that one file is the guard. `VAULT42_OTP_PROOF_SECRET` is the shared secret, with
`GOTRUE_JWT_SECRET` honoured as a legacy fallback.

`MAIL_TRANSPORT` chooses delivery: `smtp` is production and the default, `file` plus `MAIL_OUTBOX`
writes each message to a directory so a battery can read a code without a mailbox. **There is
deliberately no transport that logs a code** — "a code never appears in a log line" is a property
worth keeping true. Delivery is spawned, not awaited, so the response time cannot reveal whether an
address has an account; a harness must therefore wait for a message beyond the ones already
delivered, because a new request replaces the previous code rather than adding to it.

`MAIL_FROM` and `MAIL_PASSWORD` have no defaults, and second factors refuse to start without them.
`MAIL_TITAN` in the operator's `.env` is an address, not a credential — do not wire it as the SMTP
password.

## Trip-wires

Things that will mislead you if you assume otherwise:

- **grobase is rejected for this product's business model** and the authority replaces it, but its
  seams are still in `vault42-server` and still reachable, but no longer by accident: the grobase
  store now needs `VAULT42_STORE=grobase` explicitly. It used to win whenever all five of
  `GROBASE_QUERY_URL`, `GROBASE_ANON_KEY`, `GROBASE_APP_KEY`, `GROBASE_DB_ID` and `JWT_SECRET`
  happened to be set, with only a `tracing::info!` line naming the winner. The two grobase seams are unrelated despite the shared
  prefix: `GROBASE_URL` + `INTERNAL_SERVICE_TOKEN` is the HMAC control plane, `GROBASE_QUERY_URL` is
  the data plane behind Kong. The backends are not equivalent either — SQLite serializes
  read-then-write through its one-connection pool so audit-chain links are atomic, while
  `GrobaseStore` does read-head-then-insert over HTTP, a real TOCTOU. Storage errors all collapse to
  `Status::internal("storage error")`, so misconfiguration needs `RUST_LOG=debug`.
- **ABAC is not enforced.** `authz.v1` is generated, and `decide` / `verify_key` are implemented, but
  none of it is called. The only live authorization is owner-scoping. Only `audit_append` is wired.
- **Prose is not proof, and this repo's prose has lied.** `THREAT-MODEL.md` and `RUNBOOK.md` each
  claimed seven controls no code provided, including a `v02-zero-knowledge-proof` gate that has never
  existed in any commit. Both now carry `**Status:**` lines and `NOT IMPLEMENTED` headings; grep for
  those before citing either doc as evidence, and when you add a claim, name the file that provides
  it. Two live instances: `Unseal` authenticates then always reports 100% unsealed, so there is no
  seal state, and no client can set `recovery_optin`, so D5 recovery is unreachable, not just
  unwired.
- **`VAULT42_PORT` and `VAULT42_CONTRACT_PORT` both default to 8443** — those two collide locally.
  `VAULT42_AUTHORITY_PORT` defaults to 8444 to stay clear of both.
- **Scope keys are flag-gated off.** `keyset.rs`, `ops_scope`, `ops_env`, `ops_rotate` and the seven
  scope/env RPCs are on `develop` but return `UNIMPLEMENTED` unless `VAULT42_SCOPE_KEYS_ENABLED` is
  set. 42ctl's scope verbs need it on.
- **Never widen `.gitignore` to `keystore*`** — it silently swallows `keystore.rs` and
  `keystore_io.rs`. The runtime keystore is matched by `*.v42`; there is a comment saying so.

## Conventions binding on every edit

Vendored copies of grobase's rules live in `.claude/rules/` and apply to all code here.

- **Every source file starts with the 42-school header.** Without exception across the tree today.
  Generate it for new files with `python3 scripts/ops/gen-42-header.py <file>` (idempotent).
- **No prose comment inside a function body.** All commentary goes in one `///` doc comment above the
  declaration. The only tolerated in-body comments are the greppable tags `// sec:`, `// ponytail:`,
  `// perf:`, `// SAFETY:`. If you want a comment mid-body, split the function instead.
- **No global mutable state** — no `static mut`, no `lazy_static`/`once_cell` globals. Inject
  dependencies from the composition root.
- **Never roll your own crypto primitive.** Compose the audited RustCrypto crates (D6). If a
  construction has no audited implementation, stop and flag it.
- **Plaintext and key material are radioactive** — never logged, never in errors or traces, always
  `Zeroize`d. `Metadata.relative_path` must stay empty for leaf blobs so the server never learns
  plaintext paths.
- **TDD for crypto, protocol, auth, and RBAC** — a failing test first; property tests count.
- Libraries use `thiserror`, binaries use `anyhow`, the gRPC layer uses `tonic::Status`.
- Tests are inline `#[cfg(test)] mod tests` next to the primitive they cover. End-to-end and property
  coverage lives in `crates/vault42-conformance/tests/`, deliberately outside core.
- **grobase stays private; vault42 is the only public surface.** A missing security capability gets
  added to grobase as a reusable feature, not patched around inside vault42 (the SSH edge excepted).

### Git

gitflow: `feature/*` → `develop` → `release/x.y.0` → `main`, `hotfix/*` off `main`. **No
`Co-Authored-By` and no "Generated with" trailer on any commit or PR body.** Pushes, tags, deploys,
`fly secrets set`, and crypto-shred are irreversible — they need an explicit operator go-ahead, and
the target must be re-verified at that moment rather than from an earlier scan.

## Doc map

`USERDOC.md` full user guide and the CLI reference · `DECISIONS.md` D0–D12 architecture record ·
`THREAT-MODEL.md` adversaries and residual risks R1–R18 · `RUNBOOK.md` deploy, rotation, and what is
shipped versus merely designed · `HUMAN-ATOMS.md` remaining human/account actions. `RUNBOOK.md` is
the intended authority on which flag-gated features are live, but it was the source of three false
claims until 4ed2264, so trust a `NOT IMPLEMENTED` heading over its prose and trust this file's
trip-wires over both. `fuzz/` still does not exist despite doc comments referencing cargo-fuzz.

## Sibling repo

`../42ctl` is the umbrella platform CLI that supersedes `vault42-cli` (D12). It consumes
`vault42-core` and `vault42-proto` as **pinned git dependencies, never copies**, so a breaking change
to either crate's public API breaks 42ctl at its pinned rev.

It is far ahead of its own README: org, team, group, project, env, invite, note, push and pull are all
implemented, along with scope keys, escrow and device-flow login. Its `qa/` directory holds a spec
battery that builds vault42 from a **pinned SHA**, not from this working tree, and whose `assert_spec`
entries stay red until a route answers. Announce a new SHA when a phase merges rather than expecting
it to track `develop`.
