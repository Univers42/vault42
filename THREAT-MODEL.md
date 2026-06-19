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
| Stolen client device | has the encrypted keystore | locked behind Argon2id passphrase; revocable via key rotation |

## Residual risks (honest — each has a mitigation or is an accepted non-goal)

- **R1 Recovery breaks pure ZK for opted-in tenants** (D5). fly account + Transit ⇒ plaintext.
  Mitigate: per-tenant opt-in (OFF for friends), every recovery audited, Shamir upgrade path.
- **R2 Metadata is not encrypted** — counts, sharing graph, blob sizes, timing are visible to the
  server. v1 accepted; `content_type` is an opaque label, never a key name. v2 may encrypt names.
- **R3 Server is trusted for availability/ordering** — it can DoS or serve a stale rev, but cannot
  read. Mitigate: `rev` in the AAD + expected-prev-rev optimistic concurrency + audit-chain omission
  detection; the client treats a missing/old rev as an error, not silent success.
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
  decode-safe and DoS-bounded; `wrapped` is stored sorted for a canonical per-envelope encoding; a
  `version` field gates migrations. **Status:** unit tests pin roundtrip/tamper/injectivity/dedup; a
  `cargo-fuzz` target over the decoder and golden vectors are a P2 follow-up (not yet committed).
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
  the Shamir K-of-N split bound the blast radius. Until then, the operator's own (default-ON) tenant is
  explicitly **operator-escrowed, not zero-knowledge** (DECISIONS.md D5).

## Accepted non-goals (documented, not solved)

- A compromised client **with unlocked keys** can read that user's own secrets (mitigate: hardware
  keys + rotation).
- We are not building an HSM.
- A malicious operator who holds the unseal key is the trust root (that is the point of D5 recovery).

## Validation

OWASP ASVS + Top 10 as the rubric. Every finding → a failing regression test → fix → green. The ZK
invariant is proven by gate `v02-zero-knowledge-proof` (inspect row + logs + server memory for a
sentinel plaintext) and the `vault42-conformance` proptest/fuzz battery.
