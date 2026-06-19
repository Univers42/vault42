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
- **R8 Hand-rolled wire format** (the cost of rejecting age, D6). Mitigate: FROZEN format,
  injectivity + decode-safety fuzzed, golden vectors committed, a `version` field gates migrations.
- **R9 Author-pubkey trust** — a reader trusts `author_pubkey_id`; the server could lie about the
  owner key. Mitigate: owner pubkey pinned in the tenant's grobase identity record (owner-scoped,
  CMEK at rest), cross-checked client-side; audit-chain visibility on any owner-key change.
- **R10 RNG dependence** — a broken `getrandom` would be catastrophic. Mitigate: XChaCha20's 192-bit
  nonce makes random nonces collision-safe by construction; DEK is fresh per write; no
  deterministic-nonce path exists in the format.

## Accepted non-goals (documented, not solved)

- A compromised client **with unlocked keys** can read that user's own secrets (mitigate: hardware
  keys + rotation).
- We are not building an HSM.
- A malicious operator who holds the unseal key is the trust root (that is the point of D5 recovery).

## Validation

OWASP ASVS + Top 10 as the rubric. Every finding → a failing regression test → fix → green. The ZK
invariant is proven by gate `v02-zero-knowledge-proof` (inspect row + logs + server memory for a
sentinel plaintext) and the `vault42-conformance` proptest/fuzz battery.
