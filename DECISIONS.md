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

## D9 — As-built server: Ed25519 client identity + own SQLite store (grobase seam optional)

The deployed server (P5) refines D3/D4 to match shippable reality:

- **Identity is the client's Ed25519 author key**, not a grobase API key. Every gRPC
  request carries `x-v42-ts/-pub/-sig` — an Ed25519 signature over `ts\n<grpc-method>` —
  proving key possession, binding the call to its method, and replay-bounding it to the
  skew window. The principal (owner) is the key's fingerprint — the *same* identity that
  authors envelopes — so storage owner-scoping and authorship are one value with **no
  password and no server secret**. This is *more* zero-knowledge than an API-key model.
- **Storage is the server's own embedded SQLite** on an encrypted volume (the D4
  `vault42_secrets` shape, owner-scoped per request), not the grobase data plane. Reason:
  no grobase is deployed on fly to point at, and deploying the whole grobase stack is out
  of scope. The blob is still an opaque envelope; the server cannot decrypt it, so the L1
  zero-knowledge guarantee is identical. Migration `071` + the `vault42-grobase` REST
  client (`verify_key`/`decide`/`audit_append`) remain in-tree, flag-gated, ready for when
  a private grobase is stood up (set `GROBASE_URL` + `INTERNAL_SERVICE_TOKEN`).
- **Server-side integrity without decryption:** the server verifies each envelope's
  Ed25519 author signature against the caller's key via `vault42_core::verify_envelope_author`
  before storing — rejecting forged/misattributed blobs while never seeing plaintext.
- **Audit is a local per-owner hash chain** (grobase `chain.go` discipline), mirrored to
  grobase when wired. Proven by the 6-test in-process gRPC battery + the live fly round-trip.

## D10 — Region cdg, not mad

fly.io does not offer Madrid (`mad`) to this account; `cdg` (Paris) is the nearest EU
region it provides and matches the org's existing apps. Deployed app: `vault42` →
`https://vault42-server.fly.dev` (TLS at the fly edge, plaintext h2c to the app), 12 MB
distroless image, encrypted 1 GB volume `vault42_data` at `/data`.

## D11 — Managed multi-tenancy via a nano contract authority (the deployed duo)

The product is a **duo of two scale-to-zero fly apps**, costing ~$0.30/mo (volumes only):

- **`grobase-nano`** (`vault42-contract`, the authority): a tiny axum HTTP service. A
  person self-registers (`POST /v1/register {tenant, author_pubkey}`); it claims the
  tenant name (SQLite registry) and returns an **Ed25519-signed contract** binding that
  public key to the tenant for a TTL. It exposes `GET /v1/contract-key`. After issuing it
  idles — it is **never on vault42's request path**.
- **`vault42`** (the data plane): when `VAULT42_CONTRACT_PUBKEY` is set, every request
  must carry a valid `x-v42-contract`; vault42 **verifies it OFFLINE** with the authority
  public key (signature + expiry + author-fingerprint binding) — no call back to the
  authority. So the authority bears ~zero resource and the consuming server does the
  work, exactly as intended. The tenant comes from the contract; storage stays
  owner-scoped by the Ed25519 fingerprint (one identity = one isolated vault).

**Why a purpose-built nano authority, not grobase itself:** grobase's full stack
(PG + Kong + Go control plane + …) cannot run on fly's free tier, and the contract role
needs only "sign a claim + keep a tenant list" — a 5-MB SQLite binary. This *is* the
"nano" the brief asked for; it is trivially swappable for real grobase later (vault42 only
needs an authority public key + the `/v1/register` contract shape).

**Security:** the contract is a signed, public credential (no secret in it). Registration
sends only the public key. HTTPS at the fly edge on both apps. A per-owner **quota**
(`VAULT42_MAX_SECRETS`, default off; prod 1000) guardrails the cross-owner share-spam DoS.
Proven live: unregistered access denied; two tenants register and are isolated.

## D8 — L2/L3 defense in depth

L1 = client zero-knowledge (the real guarantee). L2 = grobase CMEK envelope (AES-256-GCM + Vault
Transit) wrapping the row at rest, master seed in a fly secret, auto-unseal at boot. L3 = fly
Firecracker microVM + encrypted volumes + 6PN. A breach must pass all three; L1 wins even if L2/L3
fall. The recovery Transit key (D5) is **separate** from the row-CMEK key so crypto-shredding one
does not kill the other.

## D12 — 42ctl supersedes vault42-cli (umbrella platform CLI)

`42ctl` (its own org repo `Univers42/42ctl`) becomes the front-door CLI for the whole stack;
the vault verbs become its `42ctl vault`/`secrets` group, `unseal` becomes `42ctl unseal`. The
existing `vault42-cli` (shipped in v0.1.1, deployed + proven) is **kept but superseded** — not
deleted (deletion-gate discipline); it remains a thin reference client. The crypto core
(`vault42-core`) is the future standalone **`vault-crypto`** crate; until it is published to
crates.io (a gated, irreversible step), `42ctl` depends on it — and on `vault42-proto` (the
contract client) — via **pinned git dependencies** at tag `v0.1.1`, never a copy. Full 42ctl
reconciliation + decisions live in that repo's `DECISIONS.md`.

## D13 — The contract is issued to an ACCOUNT, not to a shared string

`/v1/register` is the most powerful route the authority has: it claims a tenant name and
issues the signed contract that `vault42-server` accepts as authorization to write. Until
now it was the only significant route that took no `Principal`. It was guarded instead by
`VAULT42_REGISTER_TOKEN`, one shared static string checked in constant time.

That put the weakest credential in front of the strongest capability, while the account
layer built for exactly this job — accounts, sessions, a `Principal` extractor that makes a
route authenticated by construction — sat unused beside it. The shared token has no
identity, no revocation, no expiry and no audit trail: it cannot say who registered, cannot
be withdrawn from one person, and once leaked is leaked permanently. It also failed
operationally in the most ordinary way possible — the operator no longer had the value, and
because fly and GitHub both store secrets write-only, nothing could read it back. A valid
account with a valid session could not obtain a contract.

**Decided.** `register` takes `Principal`. The contract is issued to the authenticated
account, and the tenant row records `account_id` as owner (the column already existed and
was always written `NULL`). Three consequences follow from ownership:

- **The owner may re-key.** Re-claiming a name you own rebinds it to the presented key.
  Previously a lost keystore stranded the name forever: the old fingerprint could never be
  presented again and no path anywhere released it.
- **Deleting an account releases its names.** `release_tenants` deletes the rows inside
  `erase_account`'s transaction. The schema's `ON DELETE SET NULL` never fired, because the
  account row is tombstoned rather than deleted — which is why 42ctl's `account delete` help
  had to warn that a tenant name outlives the account and nothing releases one.
- **A quota bounds squatting.** `VAULT42_MAX_TENANTS_PER_ACCOUNT` (default 8). This is what
  replaces the shared token's role of limiting how much one party can take, and it is
  enforced inside the same serialized connection as the claim, so concurrent claims cannot
  both pass it.

**Admission control moves to `signup`, and that is the point rather than a side effect.**
The gate exists to bound who enters the system at all, and `signup` is the only route an
unauthenticated stranger can reach. `VAULT42_REGISTER_TOKEN` is still honoured, still
compared in constant time, still optional — it is simply checked where the anonymous caller
actually is. Gating `register` while leaving `signup` open had it backwards: anyone could
create an account, and the hard step was the authenticated one.

**The trade-off, stated plainly.** On a deployment with the token unset, registration is now
reachable by anyone who can create an account, where before it needed the shared secret. The
mitigations are the quota, the fact that an account is revocable and attributable where a
string is neither, and `VAULT42_REGISTER_TOKEN` at signup for any deployment that wants a
closed door. An operator who wants the old posture sets that variable and gets a strictly
better version of it, because now they can also see and revoke who came through.

Falsified before being trusted, per `.claude/rules/verify-gates.md`: removing
`release_tenants` turns `deleting_an_account_releases_its_tenant_names` red (409 vs 200), and
disabling the quota check turns `an_account_may_not_hoard_tenant_names` red (200 vs 403).
