# vault42 — Architecture Decision Records

Locked decisions for the build. Each is a deliberate, reversible-where-possible choice; the
security-weakening one (D5 recovery) is fenced and documented loudly.

## D0 — Precedence

`security ≈ correctness > performance > minimalism > readability > style`. When two conflict the
higher wins, and the trade-off is recorded here.

## D1 — All of vault42 is Rust

The brief's §2 proposed a Go server edge; the operator overrode it: **server, crypto-core, CLI, and
SSH are all Rust**. grobase stays Go/REST and is reused as a private substrate. Rationale: one
correctness-critical language for everything touching keys/plaintext; a single toolchain; the
`.claude/rules/refactor-rust.md` discipline applies uniformly.

## D2 — Repo independence (developed in-tree, owned by its own remote)

vault42 is developed at `grobase/vendor/vault42/` for convenience, but is **entirely its own repo**
(`git@github.com:Univers42/vault42.git`) committed/pushed only from its own remote under **gitflow**
(`main` ← `release/*` ← `develop` ← `feature/*`). grobase ignores `/vendor/vault42/` so it can never
embed it as an orphan gitlink. `.claude/rules/` here are **copied** (not symlinked) from grobase at a
pinned commit so a standalone clone/CI/fly checkout is self-contained.

## D3 — Transport: gRPC for vault42, REST+HMAC to grobase

`contracts/` protobuf (`vault/v1` + `authz/v1`) is vault42's typed spine: the server is a tonic gRPC
service (+HTTPS via the gateway), the CLI a tonic client. The internal hop to the **private** grobase
is **REST + `X-Service-Auth` HMAC** (grobase's existing serviceauth scheme, reproduced byte-for-byte
in Rust). No gRPC is added to grobase. `authz/v1.Check` maps to grobase `POST /permissions/decide`.

## D4 — Storage: opaque envelope in an owner-scoped grobase table

Secrets live in a grobase Postgres table `vault42_secrets` (migration 071), reached via the data
plane `POST /query/v1/execute` with owner-scope + RLS per request (**SharedRls** — owner_id, not
schema-per-tenant). The row stores the **full serialized `Envelope` protobuf as one opaque `bytea`**
(so multi-recipient + recovery + author signature all fit) plus indexed scope columns
`(owner_id, secret_id, path, version)`. **Zero plaintext columns** — that is what makes it a
zero-knowledge substrate. The server treats the envelope as opaque bytes; only `vault42-core` can
produce/consume it.

## D5 — Recovery: operator-assisted, fly-rooted (an explicit zero-knowledge trade-off)

> For tenants with `recovery_optin = true`, vault42 is **NOT** pure zero-knowledge. A per-tenant
> recovery keypair's **public** key is added as a `WrappedDek{RECOVERY}` on every write while opt-in
> is on; its **private** key is sealed under a dedicated HashiCorp Vault Transit KEK whose token is a
> **fly.io secret** (the "seed proving the account is mine"). Therefore **anyone who can log into the
> fly.io account and reach Transit can decrypt every secret written while opt-in was on.** This is the
> operator's deliberate choice so a lost passphrase is recoverable via fly account access.
>
> Defaults: **ON for the operator's own tenant**, **OFF (opt-in) for friend tenants**. Recovery is
> **not retroactive** (secrets written opt-OFF carry no recovery wrap). Every recovery step is
> permanently recorded in grobase's tamper-evident audit chain. Upgrade path: split the recovery
> private key with Shamir K-of-N (ceremony-only change, no envelope migration).

## D6 — Crypto: hand-composed RustCrypto, not age/rage

The custom canonical AAD (binding `rev`, recipient-set, owner/tenant/secret_id), the Ed25519 author
signature, and per-secret versioning are the security contract; the `age` format can carry none of
them, so it would only ever wrap the DEK step we can do directly in ~40 lines. We borrow age's
*design* (per-recipient X25519+HKDF DEK-wrap), not its *format*. Primitives: `x25519-dalek`,
`ed25519-dalek`, `chacha20poly1305` (XChaCha20 — 192-bit nonce ⇒ random nonces safe), `argon2`,
`hkdf`+`sha2`, `blake3`, `zeroize`, `subtle`, `getrandom`. The wire format is **FROZEN** and fuzzed
like grobase's `audit/chain.go` canonical form.

## D7 — RBAC roles with time-bound grants

Roles **read / write / update / admin** (matrix in the plan). Each grant is a `vault42_grants` lease
row `{grantee, role, scope, expires_at, revoked_at}` **plus** a grobase ABAC `time_window` condition.
Three independent expiry gates: grant `expires_at` short-circuit → ABAC `time_window` in
`/permissions/decide` → the grobase API-key's own `expires_at`.

## D8 — L2/L3 defense in depth

L1 = client zero-knowledge (the real guarantee). L2 = grobase CMEK envelope (AES-256-GCM + Vault
Transit) wrapping the row at rest, master seed in a fly secret, auto-unseal at boot. L3 = fly
Firecracker microVM + encrypted volumes + 6PN. A breach must pass all three; L1 wins even if L2/L3
fall. The recovery Transit key (D5) is **separate** from the row-CMEK key so crypto-shredding one
does not kill the other.
