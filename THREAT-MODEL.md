# vault42 — Threat Model

**Assets:** secret plaintext · all key material (DEKs, identity privkeys, KSK, recovery key) ·
audit-log integrity · recipient public-key authenticity.

**The guarantee:** a full compromise of the host, the vault42 process, **or** the grobase datastore
yields only ciphertext + wrapped DEKs + metadata — never plaintext, never a usable key; and no tenant
can read another's data.

## Adversaries & required outcomes

| Adversary | Capability assumed | Required outcome |
|---|---|---|
| Compromised host / co-tenant | reads volumes, RAM, host network | no plaintext, no usable keys (L1 ZK + L2 at-rest) |
| Network attacker (MITM) | full path control | TLS 1.3 / SSH confidentiality+integrity; downgrade impossible |
| Compromised `vault42` process | RCE on the public edge | cannot decrypt (no recipient privkey); RBAC + audit still enforced by grobase |
| Compromised `grobase` / DB exfil | steals the datastore | only ciphertext + wrapped DEKs + at-rest-encrypted metadata leak |
| Malicious tenant ("friend") | valid account, tries cross-tenant / priv-esc | hard tenant isolation; IDOR impossible; RBAC denies |
| Brute-forcer | offline guesses on passphrases | Argon2id memory-hardness + online lockout |
| Stolen client device | has the encrypted keystore | locked behind Argon2id passphrase only — **no revocation exists** (R18) |

## Residual risks (honest — each has a mitigation or is an accepted non-goal)

- **R1 Recovery breaks pure ZK for opted-in tenants** (D5). fly account + Transit ⇒ plaintext.
  Mitigate: per-tenant opt-in (OFF for friends), every recovery audited, Shamir upgrade path.
  **Status:** this risk cannot currently materialise, which is worth stating because the rest of this
  entry reads as if it can. No shipped client can opt in: `recovery_optin` is hardcoded `false` at
  every production compose site (`42ctl/src/adapters/compose.rs:33,96,132`,
  `vault42-cli/src/compose.rs:32`) and every one passes `recovery: None`, so no envelope in existence
  carries a recovery wrap. D5 is unreachable rather than merely unwired (see RUNBOOK).
- **R2 Metadata is not encrypted** — counts, sharing graph, blob sizes, timing are visible to the
  server. v1 accepted; `content_type` is an opaque label, never a key name. v2 may encrypt names.
- **R3 Server is trusted for availability/ordering** — it can DoS or serve a stale rev, but cannot
  read. Mitigate: `rev` in the AAD + expected-prev-rev optimistic concurrency, enforced server-side
  (`ops_env.rs:109`) and regression-tested (`stale_expected_prev_rev_is_rejected`); the client treats
  a missing/old rev as an error, not silent success. **Status:** audit-chain omission detection is
  **not implemented**. The chain is written correctly — each append re-reads the head and links
  `prev_hash`→`hash` under a single connection (`vault42-server/src/audit_store.rs:104-151`) — but
  nothing verifies it. Both audit clients print `seq`, `ts`, `action`, `target` and a hash prefix,
  discarding `prev_hash` before display (`42ctl/src/ops/audit.rs:27-33`,
  `vault42-cli/src/verbs_audit.rs:27-33`), so a server that drops or rewrites an event is caught by
  nothing that ships. A verifying client is the fix and it is not written.
- **R4 CMEK crypto-shred footgun** — revoking a Transit KEK makes data permanently undecryptable.
  Mitigate: separate recovery vs row-CMEK keys; admin+passkey-fenced; KEK lifecycle runbook.
- **R5 Recipient removal is forward-secure only** — a removed party keeps anything already read and
  may have cached the old DEK. Removal ⇒ ROTATE (fresh DEK); stated, not hidden.
- **R6 Passphrase is the weakest link** — Argon2id hardened params (memory ≥ 64 MiB, ≥ 3 passes);
  optional passkey/FIDO2 step-up for high-privilege ops.
- **R7 Shared `X-Service-Auth` token compromise** — an attacker can impersonate the server to grobase
  (read ciphertext, drive the PDP, DoS) but **cannot decrypt**. Mitigate: HMAC binds
  method+path+body+timestamp (replay window `SERVICE_AUTH_SKEW_SECS`); dual-key rotation
  (`INTERNAL_SERVICE_TOKEN_PREV`); token in a fly secret, rotated on schedule.
- **R8 Hand-rolled wire format** (the cost of rejecting age, D6). Mitigate: the canonical AAD is
  FROZEN + injective (it binds metadata, the recipient set, AND each recipient's `kind`); the bincode
  codec is fixed-int + size-bounded (64 MiB) + reject-trailing, so `from_bytes` on untrusted bytes is
  decode-safe and DoS-bounded; `wrapped` is stored sorted for a canonical per-envelope encoding; and
  `Metadata.version` is bound into the AAD (`aad.rs:42`), so an envelope's format era cannot be
  altered without breaking the author signature. **Status:** that version field does **not** gate
  migrations. Nothing dispatches on it, every producer hardcodes `version: 2`, and `open` never reads
  it (`open.rs:77-91`); the only version branch in the tree is `contract.rs:79`, which rejects rather
  than migrates. Cross-era confusion is prevented by the AAD domain tag (`vault42/aad/v2`), not by
  the field — which is sound, but it is a different mechanism than the one claimed, and it offers no
  migration path. Unit tests pin roundtrip/tamper/injectivity/dedup; a `cargo-fuzz` target over the
  decoder and golden vectors remain a P2 follow-up (no `fuzz/` directory exists yet).
- **R9 Author-pubkey trust (TOFU)** — `open` pins the author key the caller passes and `verify_strict`
  proves authorship against *that* key, but the *expected* key still comes from the (untrusted) server
  on first fetch. This is trust-on-first-use: a server that lies about the owner key on the initial
  fetch defeats the pin. Mitigate: pin the owner pubkey in the tenant's grobase identity record
  (owner-scoped, CMEK at rest) and surface any owner-key change in the audit chain — but the initial
  key-distribution problem is **not** fully solved; an out-of-band anchor is the real fix (future work).
- **R10 RNG dependence (accepted)** — vault42 relies entirely on the OS CSPRNG (`getrandom`) with no
  fallback. A *broken/predictable* RNG compromises the DEK directly (plaintext recoverable) regardless
  of nonce width — the 192-bit nonce only removes *reuse* hazard from a *working* RNG, it does not
  defend a broken one. This is an accepted dependency on the platform CSPRNG, stated plainly.
- **R11 Recovery key has no forward secrecy / no rotation (D5)** — the per-tenant recovery keypair is a
  single long-lived key; every recovery-wrapped envelope is wrapped to it, so a fly/Transit compromise
  decrypts the *entire historical corpus* of opted-in writes, not one secret. Toggling opt-in does not
  re-key, and a `rotate` re-attaches the current recovery key. `recovery_optin=false` is now enforced
  on read (`open` rejects a Recovery wrap when opt-in is off), so "not retroactive" is crypto-checked —
  but key rotation/forward-secrecy is **future work**: per-epoch recovery keys (epoch in metadata) +
  the Shamir K-of-N split bound the blast radius. The operator's own tenant is *intended* to be
  explicitly **operator-escrowed, not zero-knowledge** (DECISIONS.md D5) — but it is not: no client can
  turn opt-in on, so that tenant is zero-knowledge in fact, and its data is unrecoverable on a lost
  passphrase like everyone else's (R1). Do not describe it as escrowed until a client can opt in.

### Org/team/group RBAC + per-environment scope keys (R12–R17)

These cover the zero-knowledge per-environment secret model — control-plane authorization (grobase,
flags `ORG_MODEL_ENABLED`/`RBAC_HIERARCHY_ENABLED`/`ENVIRONMENTS_ENABLED`/`GROUPS_ENABLED`/`INVITES_ENABLED`/`USER_PUBKEYS_ENABLED`,
migrations 077–084) vs crypto-plane decryption (vault42, flag `VAULT42_SCOPE_KEYS_ENABLED`, RPCs
`WrapScopeKey`/`GetScopeKey`/`ListScopeMembers`/`RotateScope`/`PutEnvSecret`/`GetEnvSecret`/`ListEnvSecrets`).
All default OFF (a missing flag = byte-parity). Design: `grobase/wiki/architecture/org-team-group-rbac.md`.
**Status:** the proof this section used to cite did not exist. It named grobase gates
m162/m166/m168/m170/m172, vault42 gates v14/v15, and `scripts/test/e2e-rbac-scope-keys-live.sh`;
grobase is rejected and cannot run, and neither vault42 gate nor that script appears in any commit
on any branch. What actually covers R12–R17 today: gates `v18-authority-scope-bridge` and
`v25-scope-wrap-bookkeeping`, plus the QA session's scope-authz, scope-lifecycle, scope-attack and
grant-scoping specs driving the real client. R12's specific claim that a removed member is blocked
on the new-epoch revision is covered there and not by a vault42 gate.

- **R12 Scope-key revocation is forward-secure only** — a removed member keeps anything already read
  and may have cached the old scope key; only post-rotation revisions are protected. Mitigate: removal
  ⇒ `42ctl vault rotate-scope` (new epoch, re-seal env secrets, re-wrap only to remaining members);
  v15 proves a removed member is blocked on the new-epoch revision. Stated, not hidden.
- **R13 Provisioning lag** — a grant is authorized the instant it is written but does not *decrypt*
  until a key-holding admin runs `42ctl vault sync-keys` (only a key-holder can wrap the scope key, the
  server cannot). Mitigate: the gap is surfaced as an explicit `pending-provision` state via
  `42ctl vault scope-status` — never a silent failure.
- **R14 An admin is the scope's decryption root** — a current scope admin can `WrapScopeKey` to any
  registered pubkey, so a compromised/rogue admin can provision an attacker's key. Mitigate: the
  `pubkey_sig` proof-of-possession on the registry (`082`), every wrap is audited, and
  `42ctl vault scope-status` exposes a rogue granter.
- **R15 Registry TOFU** — the first wrap trusts the member's pubkey as published in the user-pubkey
  registry (`081`); a server that lies on first fetch can substitute a key. Mitigate: the self-signed
  `pubkey_sig` and auditing pubkey changes; an out-of-band anchor is future work (same shape as R9).
- **R16 Rotation cost** — `42ctl vault rotate-scope` re-seals *every* env secret to the new scope
  public key, an O(secrets) operation. Mitigate: the rotation is idempotent + epoch-tagged, so a
  partial rotation is detectable and re-runnable.
- **R17 Recovery interaction** — scope keys are recovery-wrapped only under the *same* explicit
  per-tenant opt-in as secrets (R1/R11), and audited; a scope key never silently inherits recovery
  escrow.

### Tenant claims (R20)

- **R20 Nothing ever releases a tenant name** — `/v1/register` calls `claim_tenant`, which inserts
  a row keyed on the name and holding the claiming author's fingerprint
  (`crates/vault42-authority/src/store/tenants.rs:29`). There is no delete, release or unclaim
  anywhere in the store. A re-registration succeeds only when it presents the SAME fingerprint,
  so a name whose keystore is lost is permanently unusable by anybody, including the person who
  registered it, with no operator recourse. This is R18 seen from the other side: losing the
  passphrase loses the identity, and the name goes with it.
  **Status:** live. The mitigation is to pick a new name.

- **R20a Deleting an account orphans its tenant claims rather than releasing them** — the schema
  declares `account_id TEXT REFERENCES accounts(id) ON DELETE SET NULL`
  (`store/migrate.rs:48`), and `erase_account` touches grants, invites, memberships and the
  account tombstone but never the `tenants` table (`store/offboard.rs:124`). So
  `42ctl account delete --yes` reports success and leaves the name claimed by a fingerprint that
  may no longer belong to a living account. Signing up again with a new keystore and trying to
  reclaim your own tenant answers 409 Conflict, and nothing in that answer explains why.
  **Status:** live, and it is the deletion path's most surprising residue.

  Releasing the claim would be safe with respect to DATA, which is worth recording because it is
  the first thing to worry about: the server derives an owner id from the author key's
  fingerprint and not from the tenant (`vault42-server/src/principal.rs:29`), so a new holder of
  a released name reads a different namespace and inherits nothing. What release would create is
  two parties who each believe they hold one name, both with contracts that verify. Which of
  those costs is worse is a product decision, so nothing here changes the semantics.

- **R20b Automated runs burn a name each** — `scripts/smoke/inception-live.sh` registers a fresh
  tenant per run because reusing one would need a committed keystore, and the claim is idempotent
  only for the same fingerprint. Each run therefore leaves one permanent row. It is a few hundred
  bytes on a 1 GB volume and the namespace is 64 arbitrary characters wide, so the practical cost
  is nil; it is recorded because "the test cannot clean up after itself" should be a known
  property rather than a discovery.

### Chunk deduplication (R19)

- **R19 Deterministic chunk sealing tells the store which chunks are equal** — `seal_chunk`
  (`crates/vault42-core/src/chunk.rs`) deliberately abandons the random nonce that every other
  seal in the crate uses. Identical plaintext under one environment's scope secret produces
  byte-identical ciphertext, which is the only way two members of that environment can share one
  stored object instead of paying for two. The cost is that whoever runs the store learns the
  equality relation over chunks: how much its tenants share, which members hold the same bytes,
  and how many distinct chunks an environment really has behind a deduplicated count.
  **Scope of the leak:** bounded to one environment on purpose. Every key descends from that
  environment's scope secret via HKDF, so the same bytes in two environments seal to two
  unrelated names and equality does not cross the boundary. This is what the per-environment key
  scope buys, and `identical_bytes_in_two_scopes_do_not_converge` pins it.
  **Status:** accepted, and chosen over per-tenant scope with the cost stated.

- **R19a A departed member keeps a confirmation oracle** — convergent encryption gives anyone
  holding the scope secret the ability to test whether a plaintext they can guess is present:
  seal the guess, look for the name. Removing a member from the environment does not take the
  secret out of their hands, so until that environment is rotated they can confirm the presence
  of any file they can reconstruct. The random-nonce path never offered this, so chunk dedup adds
  it. **Mitigation:** `rotate-scope` after any removal, which the offboarding path already says is
  required (`v26`). **Status:** the rotation exists; nothing forces it, so this is live whenever an
  operator skips it.

- **R19b A hostile member can poison a shared chunk** — if a name did not have to be the digest
  of the bytes stored under it, a member of the environment could store chosen bytes under the
  name another member's deduplicated fetch will ask for. The AAD binding cannot catch this,
  because the writer binds the same lie into it. `open_chunk` therefore recomputes the name from
  the recovered plaintext and refuses a mismatch. **Status:** mitigated, and held in place by
  `a_chunk_stored_under_a_lying_name_is_refused`, which was watched failing with the check removed.

### Identity lifecycle (R18)

- **R18 A stolen device cannot be revoked** — the keystore on a lost laptop is protected by the
  Argon2id passphrase and by nothing else, because there is no identity-key rotation in either client.
  The `keys` surface is `init`/`export-pub`/`enroll`/`escrow`/`recover` (`42ctl/src/cli.rs:174-201`),
  and every `rotate` verb in the tree rotates a secret's DEK (`vault42 rotate <path>`) or a scope key
  (`42ctl vault rotate-scope`) — never an identity keypair. `keys init --force` mints an *unrelated*
  identity and re-wraps nothing, so it abandons every personal secret rather than rotating into them.
  The consequence is that a compromised passphrase is a permanent compromise of everything that
  identity can reach. Mitigate today: remove the member from the org and `rotate-scope` every
  environment they held — which protects shared environment secrets and does nothing for their
  personal ones. **Status:** a real `keys rotate` (new keypair, re-wrap every reachable secret, retire
  the old fingerprint) is **not implemented**, and is the highest-value gap in this section.

## Accepted non-goals (documented, not solved)

- A compromised client **with unlocked keys** can read that user's own secrets. Hardware keys and
  identity rotation are the intended mitigations; neither is built (R18).
- We are not building an HSM.
- A malicious operator would be the trust root for any escrowed tenant, which is the point of D5
  recovery. Today no tenant is escrowed (R1) and there is no unseal key to hold, since seal state is
  unimplemented (see RUNBOOK). This non-goal describes the intended posture, not the current one.

## Validation

OWASP ASVS + Top 10 as the rubric. Every finding → a failing regression test → fix → green.

The ZK invariant is exercised by the `vault42-conformance` proptest battery
(`crates/vault42-conformance/tests/`: roundtrip, tamper→auth-failure, non-recipient-cannot-unwrap,
signature-forgery-rejected, and the recovery-opt-in gate). **Status:** gate
`v02-zero-knowledge-proof` — the end-to-end check that no sentinel plaintext appears in a stored row,
a log line, or server memory — **does not exist**. `git log --all --diff-filter=A` finds it in no
commit on any branch, and no script in `scripts/verify/` bears that name. The property most central
to this document is therefore argued from unit-level crypto tests rather than from an end-to-end
observation of a running server. Writing v02 is the largest verification gap in the repo. The
`cargo-fuzz` half of the conformance battery does not exist either (no `fuzz/` directory).
