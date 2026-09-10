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

### Reachability of the group model (R26)

- **R26 The organization model was unreachable on the deployed stack — FIXED** — every RBAC verb
  needs a SESSION, and `42ctl auth login` saved a CONTRACT and never a session, with or without
  `--email`. The only path that minted one was the GitHub device flow, and the deployed authority
  answers `POST /v1/github/device/start` with `{"error":"GitHub sign-in is not configured here"}`.
  So for a period nobody could create an organization, a team, a project, an environment or a
  grant against the running system.
  **Status:** closed by `42ctl auth login --password --email`, which mints a session from the
  password login the authority had served all along.

  **The authority was never the problem.** `POST /v1/auth/login` returned a session token from the
  first day; the CLI simply had no verb that saved one. The door existed and nothing opened it —
  which is why neither test suite saw it: the client's harness minted tokens by hand, and the
  authority's tests never went through the client.

  **Verified live**, not inferred: two people sign up, obtain password sessions, create an org,
  invite, accept, and the membership is load-bearing
  (`scripts/smoke/team-live.sh`, against the deployed pair).

  The consequence for the standing list is that a GitHub OAuth client id is a convenience again
  rather than the only key. Proven mail delivery remains load-bearing for the one-time-code paths.

- **R27 `GET /v1/orgs/{org}/members` cannot be displayed by the client** — the authority sends
  `created_at` as a unix integer and 42ctl's `Member` declares it a `String`, so the response fails
  to decode and `42ctl org members` errors. The membership itself is intact; only the listing is
  unreadable. **Status:** LIVE. The authority is consistent — every timestamp it emits is an
  integer — so the fix belongs in the client, and it is one field.

  Found because the live scenario asserted membership through a LISTING first. Asserting it through
  capability instead is both the way past a display bug and the better assertion: a listing shows
  what the control plane is willing to display, while acting inside the org shows the membership is
  load-bearing.

### Project layout (R25)

- **R25 A submodule parked under a dependency directory is dropped, silently** — the client's scan
  never descends into `vendor`, `node_modules`, `target`, `dist`, `build` or `.cache`, which is
  right for vendored source and wrong for a submodule someone put there. Its environment file and
  its whole `secrets/` directory are skipped, and `push` reports success.
  **Status:** LIVE, and it is directly the operator's stated shape — "a lot of projects and
  submodules with their own things to store". Found while building `v30`, which is why that gate
  places its nested module under `modules/` rather than freezing today's behaviour by asserting it.

  Same family as the `secrets/` omission fixed in 42ctl bd7f87e: a write that decides not to
  happen, reported as success. The proposed rule is to descend into a skipped directory for any
  entry that is itself a git repository — a submodule is a git boundary, separate projects are the
  things that have secrets, and vendored source almost never carries either. It lives in the
  client, and is 42ctl's `qa/specs/s15` expected-red.

- **R25a Two projects sharing every relative path stay apart — verified** — a blob's id is
  `secret_id(principal, "{project_id}/{rel}")` and its server path carries the project id as well,
  so one owner's two projects cannot collide even when laid out identically. That was an argument
  from the derivation until `v30` made it a test: each project restores its own bytes, a nested
  module keeps its own `secrets/` at mode 600, and neither tree appears inside the other.

### Sharing (R29)

- **R29 Nothing revokes a share once it has been handed out** — `Share` re-seals a secret to a
  second recipient, so the recipient holds their OWN envelope in their own namespace. Rotating the
  owner's copy mints a new DEK for the owner and does not reach it. There is no `revoke`, no
  `unshare`, and no verb anywhere that removes it.
  **Status:** LIVE, and it is a MISSING FEATURE rather than a defect — nothing in the product
  claims it works. Recorded here because a threat model that omits a missing protection is the
  same failure as one that claims a protection it lacks, and this had been carried as a loose note
  rather than written down.

  **The design, agreed with the client's author and not built.** A shared envelope lives in the
  recipient's namespace, so revoking means deleting a row somebody else owns. The only claim the
  server can check without new state is that the caller's key is the one that AUTHORED the row,
  which the stored `author_pubkey` already records. Anything richer would put the authority on the
  delete path — the coupling refused for environment writes, and refused for the same reason.

  **It would stop future reads and nothing else.** The recipient had the plaintext and may have
  kept it. A verb whose help text reads "they can no longer see it" would be exactly the class of
  sentence removed from this file all day: prose asserting a property the code does not have. It
  should say what it removes — their copy — and what it does not.

  **The test that matters is the direction that is not obvious.** Not "the recipient can no longer
  read", which is the easy half, but that the OWNER's own copy survives and that revoking one
  recipient leaves every other recipient intact. A delete keyed on the author's key could
  plausibly take more than it was asked for, and that failure would look exactly like successful
  revocation.

### Deployment posture (R28)

- **R28 Forgetting the contract key ran the server open, silently — FIXED** — without
  `VAULT42_CONTRACT_PUBKEY` the server accepts any self-generated keypair: no authority vouches
  for anybody and the only remaining limit is the per-owner cap. That is a legitimate way to run,
  and it is how every local harness runs. It was also what you got by FORGETTING the variable, so
  a deployment that lost the secret, or a config with a typo in the name, came up looking healthy
  and gated nobody.
  **Status:** closed. The open posture needs `VAULT42_ALLOW_UNGATED=1`, and the refusal names it.

  Refusing a MALFORMED key was already the rule, for exactly this reasoning — the two postures are
  opposite and there is no safe third reading. An ABSENT key was the same question with a quieter
  failure, and it had been left alone because absence looks like a default rather than a decision.

  Nothing explicit changes meaning. What changes is that the two ways of being wrong — forgetting
  the key, and meaning to run open — no longer look identical from outside.

  Held by `running_ungated_requires_saying_so`, which also requires the refusal to NAME the opt-in:
  an operator who cannot see the way out debugs the wrong layer and eventually disables the right
  one.

### Guessing and spending (R23)

- **R23 Nothing limited password guessing — FIXED** — twenty wrong passwords in a row followed by
  the right one let the right one through. No lockout, no backoff, no refusal. The only thing
  between an attacker with a leaked address list and an account was patience.
  **Status:** closed. Five attempts per address per hour, then a refusal.

  **The correct password is refused while throttled**, which is the whole property: a limit a
  correct guess walks through is not a limit, and an attacker's last guess is a correct one.
  `the_correct_password_is_refused_while_throttled` holds it. A successful login clears the count,
  so somebody who mistypes twice carries nothing into their next hour.

- **R23a Nothing limited one-time-code requests — FIXED** — ten in a row all answered 200, and in
  production each is a real message through a real mail credential: somebody's inbox, this
  project's sending reputation, and the bill. **Status:** closed, same limit, same primitive.

- **R23b The limit is counted BEFORE the account lookup, or it becomes the oracle it defends
  against** — the code path already answers identically for an address with an account and one
  without, which is what stops an attacker enumerating users. A limit applied after the lookup
  undoes exactly that: the throttled answer would arrive only for addresses that exist, and the
  defence would hand over what the original design refused.
  `the_code_request_limit_answers_the_same_for_a_known_and_an_unknown_address` drives both to the
  limit and requires their sequences of statuses to be identical at every step, not merely both
  eventually refused. Moving the guard after the lookup fails it.

- **R23c Keyed on the address, not the source, and that is a trade** — behind a proxy the only
  source available is a header the client can set, and a limit keyed on a value the attacker
  chooses is not a limit. Keying on the address means an attacker can slow a real person down by
  guessing at them. That is why this backs off rather than locking out: bounded, self-decaying,
  and cleared by a success. A hard lockout would hand any attacker indefinite denial of an account,
  which is the worse trade. **Status:** accepted.

- **R24 Signup still enumerates accounts** — `POST /v1/auth/signup` answers 201 for a fresh address
  and 409 for one that exists, so an attacker learns who has an account by trying to register them,
  no password required. Login is careful about precisely this and returns an identical refusal
  either way; signup undoes it.
  **Status:** LIVE. Rate limiting does not help — each address gets its own bucket, so enumerating
  across many addresses is unaffected.

  Not fixed here because it is a contract change: 42ctl reads `account_id` from the signup response
  and prints it, so hiding existence breaks the client. The design is for signup to answer the same
  for both cases and for the account id to move behind authentication, where `GET /v1/auth/me`
  already returns it to a caller who has proved they own the account. It lands when the client is
  ready for it, in that order.

### Environment secrets (R22)

- **R22 Writing an environment secret was authorized by nothing — FIXED** —
  `op_put_env_secret` verified exactly one thing: that the envelope was authored by whoever sent
  it, which an attacker satisfies by authoring their own. No membership, no grant, no role. So any
  account that could reach the port could overwrite any `(scope_id, epoch, path)`, and scope ids
  are `blake3(project ‖ env)`, so an attacker need not ever have seen one.
  **Status:** closed. A write now requires the caller to hold a wrap for the scope.

  **The contrast is what made it stark.** Reading was already protected, and cryptographically
  rather than by the server's goodwill: a member with no wrap cannot open the envelope, whatever
  the server serves them. So an organisation member with read-only access, or a total stranger,
  could destroy what they could not read.

  **Why it was destruction and not substitution.** The next reader gets an envelope sealed to the
  scope key by an author they do not expect, so `get-env` fails rather than returning
  attacker-chosen plaintext. That is the one mercy in it, and it is not a defence: an environment
  whose secrets any stranger can erase is not a vault.

  Held by `a_stranger_cannot_overwrite_an_env_secret`, watched failing with the rule removed.

- **R22a Read and write are separated — FIXED** — a write of an environment secret now requires
  the caller's wrap AT THE REQUESTED EPOCH to carry `Writer`. At that epoch specifically, not the
  newest they hold: each epoch has its own keyset, so a `Writer` wrap at E-1 says nothing about
  what may be done at E, and a rotation is where a demotion takes effect.
  **Status:** closed, held by `a_read_only_member_cannot_write_an_env_secret`, which also requires
  the same reader to still READ — a split that denies reading is not a split.

- **R22g The rule was correct and inert for one commit** — worth recording, because R22a reads as
  closed and for a period it was closed and had no effect. `GET .../grants` did not report a
  grant's role, so the client (which fails closed on a missing role) minted `Reader` for everybody:
  a team granted `write` could not write, and the only writer was a scope creator whose self-wrap
  is `Writer` by construction rather than by any grant. Silent both ways — the grant said write,
  the wrap said read, only the wrap is enforced and only the grant is displayed.

  It was found because a teammate's assertion "a read-only member cannot write" went GREEN when
  enforcement landed, and it was green because NOBODY could write. **The negative half of a
  permission test is satisfied by a system that refuses everyone, and it reads as extra safety
  rather than as a fault** — worse than a vacuous pass, which at least looks like nothing. The
  positive control they had not yet written, that a member granted write CAN write, was the only
  thing that showed it.

  Neither test suite could have found it alone. The server's own tests build a grant directly, so
  the path from a grant's role to a wrap's role never appears in them; the client's tests cannot
  reach the deposit rule that R22e closes. The defect lived in the seam.
  `the_grant_listing_reports_each_grants_role` covers it now, asserting both roles because a
  listing hard-coded to `write` would satisfy a one-role test.

- **R22e Depositing a grant requires `Writer`, and this is what makes the role real** — the rule
  above is bypassable on its own, and that was measured rather than argued. A `Reader` holds the
  scope secret, because reading requires it, so they can mint a grant to THEMSELVES carrying
  `Writer`, validly signed by their own key. Under R21's membership-only deposit rule they
  satisfied caller-is-granter and granter-is-a-member, and the upsert on
  `(owner, scope_id, epoch)` replaced their own `Reader` wrap with it. Four steps, no forgery, and
  every check passed.

  So both rules landed together: depositing requires the caller's newest wrap for the scope to say
  `Writer`. Newest rather than strongest across epochs, because taking the strongest would let a
  wrap from before a demotion outvote the one that recorded it — the demotion never taking effect
  at all rather than taking effect on the next sync.
  `a_reader_cannot_promote_their_own_wrap_to_writer` failed before the fix and holds it now.

  **The bootstrap exception survives unchanged and is the only way into an unclaimed scope**, still
  restricted to granting to yourself (R21c). A grant whose blob will not parse yields no role and
  is refused; "I cannot read your wrap" must never render as permitted.

- **R22f The pre-role grant path is deleted** — a grant without the `v42g2` prefix used to read as
  `Writer` so pre-role grants kept working while the client learned to mint roles. That branch is
  gone in the same commit that started requiring `Writer`, because it was the one path a pre-role
  grant could take to satisfy the requirement. An operator holding one re-runs `sync-keys`.

  The test guarding it was described, in the commit that added it, as failing when the branch was
  deleted. IT DID NOT: it was written to tolerate either outcome, so it passed before and after and
  was never a tripwire — a claim about a test's ability to fail, made without checking, which is
  the same error as a gate nobody has broken. It asserts the refusal now, which can be false.

- **R22d The role in a wrap is a snapshot, not a live reading of the grant** — decided, not
  incidental. The role is fixed when the wrap is minted, so demoting somebody from write to read
  in the control plane does not change the wrap they already hold: the demotion takes effect on
  the next `sync-keys`, exactly as a removal takes effect on the next `rotate-scope`.

  The alternative is for the server to consult the authority's grant on every write and treat the
  wrap's role as a ceiling. That is rejected because it would put the authority on the per-request
  path, which is the one thing this architecture is built to avoid: the contract is verified
  offline precisely so the authority can idle at zero cost, and coupling writes to its
  availability would mean the vault stops accepting writes when the control plane sleeps.

  **The demotion lag is real and is the price.** `sync-keys` re-wraps every authorized member
  unconditionally and the store upserts on `(owner, scope_id, epoch)`, so the new role replaces
  the old — there IS a path, and an operator who demotes somebody for cause should run it
  immediately, and rotate as well if they also want reading closed, which was already true before
  roles existed. **Status:** accepted; the lag is documented rather than discovered.

- **R22b How it stayed open** — the doc comment on the write path carried the sentence "the row is
  NOT owner-scoped — the seal to the scope public key is the access control". That is TRUE of
  reading and was never true of writing: sealing to a public key is something anyone holding a
  public key can do, and the scope public key is published. A confidentiality argument sat on an
  integrity path and read as though it covered both. The read path's own version of that sentence
  is correct and is three lines below.

  This is the same defect class as the overstated comments corrected in `THREAT-MODEL` earlier and
  in `aead.rs`: prose asserting a property the code does not have, believed because it is specific.

- **R22c Reading and listing are members-only now too** — tightened in the same change. The seal
  always protected the plaintext, so this is genuine defence in depth rather than the load-bearing
  check it is on the write path. But serving them to any authenticated caller handed a stranger the
  existence of a path, its version count, its author's public key and its ciphertext length. None
  of that is plaintext and all of it is somebody's business.
  `a_stranger_can_neither_list_nor_fetch_env_secrets` holds it.

  Membership is checked BEFORE the envelope is parsed, so a malformed envelope from a stranger
  answers `permission_denied` rather than `invalid_argument` and an outsider does not learn that
  their envelope parsed. That ordering created a trap of its own: the pre-existing
  `unsigned_env_secret_is_rejected` would have passed on the membership refusal alone, testing
  nothing about signatures. It enrols its author now, and
  `a_stranger_is_refused_before_the_envelope_is_examined` pins the ordering so a reorder cannot
  make it vacuous again in silence.

### Scope-key deposit (R21)

- **R21 Any authenticated caller could overwrite any member's scope-key wrap — FIXED** —
  `WrapScopeKey` deposited a wrap into `req.member_id`'s namespace, verifying only that the
  grant carried a valid signature by `req.granter_pubkey`, a key **taken from the same request**.
  An attacker generated a keypair, signed their own grant wrapping a secret of their choosing to
  the victim's public key, and deposited it; the store upserts on `(owner, scope_id, epoch)`, so
  it REPLACED the victim's legitimate wrap. `RotateScope` reached the same store the same way.
  **Status:** closed. A deposit now requires the caller to be the granter AND the granter to
  already hold a wrap for that scope.

  **Why membership is the right rule and is decidable here.** Holding a wrap IS the capability:
  opening one is the only way to have the scope secret, and having the secret is the only way to
  re-wrap it to somebody else, so "is a member" and "may grant" are the same condition. It needs
  no knowledge the server lacks — an earlier version of this entry claimed the fix required the
  authority's RBAC on a per-request path, which was wrong. The server can answer it from
  `scope_keys` alone, and does, in one statement so a concurrent deposit cannot be judged against
  a scope that changed between two reads.

  Held by `an_attacker_signing_their_own_grant_cannot_overwrite_a_victims_wrap` and
  `an_outsider_cannot_rotate_a_scope_they_do_not_hold`, both watched failing with the rule
  removed. Rotation is checked once for the whole batch before anything persists, because a
  per-rewrap check would let the caller's own rewrap land first and then authorize the rest by
  the row it had just created.

- **R21c A scope id can be squatted before its owner claims it** — the new residual, and the
  price of the bootstrap exception. Creating a scope has to be allowed for somebody, and at that
  instant nobody holds a wrap, so a deposit into an UNCLAIMED scope is accepted when the caller
  grants to themselves. Scope ids are `blake3(project ‖ env)`, so anyone who knows both can
  self-wrap first and make the real `vault env-init` fail. **Status:** live, and deliberately
  preferred to the alternative: it is a loud refusal at the point of collision rather than a
  silent substitution, it requires guessing a project UUID, and it grants the squatter nothing —
  they hold a scope in their own namespace that no legitimate member will ever use.
  `creating_a_scope_is_only_allowed_as_a_self_wrap` pins the exception to self-wraps, so a
  squatter cannot use it to enrol anybody else.

- **R21a A client check limits what a substitution could have achieved** — `42ctl` compares the
  recovered scope secret's public half against the key the environment publishes and refuses by
  name when they differ (`42ctl/src/cmd/scope_recover.rs`). Retained as defence in depth. It is
  skipped when the environment advertises no key yet, so it never covered the enrolment window;
  R21's fix is what closes that, and this remains the second line rather than the first.

- **R21d The rejected grobase backend refuses rather than guesses** — deciding membership needs
  every wrap for a scope across all owners, and that store is owner-scoped by construction, which
  is the property that makes it safe. Answering from an owner-scoped view would report an
  established scope as unclaimed and hand a bootstrap to anyone who asked, so it returns
  `Unsupported` and the RPC fails closed. That backend is off unless `VAULT42_STORE=grobase`
  names it exactly.

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

- **R19 Deduplication tells the store which chunks are equal** — a chunk is named by a keyed digest
  of its plaintext under a key derived from the environment's scope secret, and a writer that finds
  the name already present uploads nothing. Whoever runs the object store therefore learns the
  equality relation over chunks: how much an environment's members share, and how many distinct
  chunks sit behind a deduplicated count.
  **Scope of the leak:** bounded to one environment. The naming key descends from that
  environment's scope secret, so the same bytes in two environments produce two unrelated names.
  **Status:** accepted, and chosen over per-tenant scope with the cost stated.

  **The mechanism is NOT the one an earlier version of this entry described.** It said identical
  plaintext produced identical ciphertext through a convergent sealer in `vault42-core`. That
  sealer existed, was never called by anything, and has been deleted. Identical NAMES turn out to
  be sufficient: the second writer finds the name present and stores nothing, and any member can
  open the single copy because it is sealed to the ENVIRONMENT rather than to a person. The
  already-present check does the work convergent encryption was going to do, without giving up a
  random nonce.

  Recorded at this length because a threat model describing a construction nobody uses is the same
  defect as a comment asserting a property the code lacks, and this file has been full of those.

- **R19a A departed member keeps a confirmation oracle** — survives the change of mechanism intact.
  Anyone holding the scope secret can compute the NAME for a plaintext they can guess and look for
  it, which is the same oracle by a different route. Removing somebody from the environment does
  not take the secret out of their hands. **Mitigation:** `rotate-scope` after any removal, which
  the offboarding path already says is required. **Status:** live whenever an operator skips it.

- **R19b A member can poison a shared chunk** — and deduplication is what creates the route rather
  than merely exposing it. A member may seal honestly FOR a name while putting unrelated bytes
  inside; every later writer of that content then finds the name present, stores nothing, and
  restores the poisoner's bytes. Valid seal, valid signature, correct secret id, nothing else
  notices. **Mitigation:** the reader recomputes the name from the recovered plaintext and refuses
  a mismatch. **Status:** mitigated in the client's `open_chunk`.

  The reason that check is needed is sharper than "the cipher demands it": deduplication makes one
  member's stored bytes into every member's stored bytes, and at that point "who wrote this" stops
  being answerable from outside the plaintext.

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
