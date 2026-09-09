# Scope Keys + Env Secrets

vault42's server surface for **zero-knowledge per-environment secrets**: a team shares one
environment's secrets without the server ever holding a plaintext or a private key. This is the
**crypto plane** ("who CAN decrypt") of the grobase RBAC design; the **control plane** ("who MAY
access") is `project_grants` + `user_pubkeys` — see
[`../../wiki/architecture/org-team-group-rbac.md`](../../wiki/architecture/org-team-group-rbac.md).

The clients are **42ctl** verbs, not direct callers:
`vault env-init | sync-keys | scope-status | set-env | get-env | rotate-scope`.

---

## Flag — OFF by default = byte-parity

`VAULT42_SCOPE_KEYS_ENABLED` (read in `config.rs`; default `false`). The seven RPCs below route
through `authn_scope` (`grpc.rs`), which gates BEFORE authentication or any store access:

```rust
/// Gate-then-authenticate a scope-key RPC: when the feature flag is OFF, return
/// UNIMPLEMENTED so the wire stays byte-parity; otherwise authenticate as usual.
fn authn_scope(&self, meta: &MetadataMap, method: &str) -> Result<Principal, Status> {
    if !self.scope_keys_enabled {
        return Err(Status::unimplemented("scope-key surface disabled"));
    }
    authn(meta, method, self.skew_secs, self.contract_pub.as_ref())
}
```

When OFF: every scope/env RPC returns `UNIMPLEMENTED`, no row is read or written, and the wire is
byte-identical to a build without the feature. The base secret surface (`Push`/`Get`/`Ls`/… in
`vault.proto`) is unaffected.

Server-side migrations: `082_vault42_scope_keys`, `083_env_scope_pubkey`, `084_vault42_env_secrets`.
Control-plane side: `077_environments`, `078_groups`, `079_project_grants_ext`, `080_invites`,
`081_user_pubkeys` (flags `ENVIRONMENTS_ENABLED`, `GROUPS_ENABLED`, `INVITES_ENABLED`,
`USER_PUBKEYS_ENABLED`, `RBAC_HIERARCHY_ENABLED`, `ORG_MODEL_ENABLED` — all default OFF).

---

## The crypto model (brief)

An **environment is the key-bearing scope**: its own X25519 keypair with an `epoch` for forward
secrecy (`generate_keyset` in `keyset.rs`).

- **Seal to the scope PUBLIC key.** Secrets are sealed client-side to the scope public key
  (`scope_recipients`); a member never appears as an envelope recipient.
- **Wrap the scope PRIVATE key per member.** `grant_scope_key` wraps the scope secret to a member's
  X25519 key as a `GrantedScopeKey`, signed by a granting admin. The granter signature binds
  `scope_id ‖ epoch ‖ member_id ‖ wrapped` with length-prefixed **injective framing** (a domain tag
  distinct from the envelope AAD — the AAD golden vector is unchanged).
- **Two-hop read.** A member calls `GetScopeKey` → `open_scope_key` (verify granter sig, unwrap with
  their X25519 secret → scope private key) → `open` the env secret. The scope private key never
  leaves a `Zeroizing` buffer.

The server **never decrypts**. It verifies signatures only: the **granter** signature on a wrap
(`verify_grant_signature`, no member secret needed) and the **author** signature on an env-secret
PUT (`verify_envelope_author`). Everything stored crosses the wire as raw bytes and persists as
base64 TEXT (a `bytea` column cannot bind from JSON).

**The env-secret row is NOT owner-scoped — the seal IS the access control.** `GetEnvSecret` and
`ListEnvSecrets` return the opaque envelope / path list to **any authenticated caller**; only a
holder of the scope private key (reachable only through a wrapped scope key) can decrypt.

---

## The 7 RPCs (`contracts/vault/v1/vault.proto`)

Scope-key surface — implemented in `ops_scope.rs` / `ops_rotate.rs`:

| RPC | Stores / returns | Server check (never decrypts) |
|---|---|---|
| `WrapScopeKey` | Deposits `granted_blob` (opaque `GrantedScopeKey`) under `member_id` — a foreign-owner write (like `Share`). Returns `stored`. | Verifies `granter_pubkey`'s signature over the blob; pins the blob's bound `scope_id`/`epoch` to the request (`bind_request_to_grant`) — mismatch ⇒ `permission_denied`. |
| `GetScopeKey` | Returns the caller's **own** wrap (`granted_blob` + `granter_pubkey`) for `(scope_id, epoch)`. | Owner-scoped to the caller — a member cannot read another's wrap. Absent ⇒ `not_found`. |
| `ListScopeMembers` | Returns `(member_id, wrapped_at)` the caller may see for `(scope_id, epoch)`. | Owner-scoped to the caller's own membership; never the cross-member set. |
| `RotateScope` | Persists one rewrap per remaining member under `new_epoch` (`rewraps: repeated WrapScopeKeyRequest`); returns `rewrapped` count. A removed member simply has no `new_epoch` wrap — forward secrecy by **absence**, not deletion. | Each rewrap is re-verified via `store_one_rewrap` with `pin_epoch = Some(new_epoch)` (`bind_rotation_epoch`), so a genuinely-signed OLD-epoch grant cannot be smuggled in. |

Shared env-secret store — implemented in `ops_env.rs`:

| RPC | Stores / returns | Server check (never decrypts) |
|---|---|---|
| `PutEnvSecret` | Appends the next version of an opaque `envelope` keyed by `(scope_id, epoch, path)`; returns `version`. `expected_prev_rev` is optimistic concurrency (0 = create; stale ⇒ `failed_precondition`). Row NOT owner-scoped. | Verifies the envelope's **author** signature against the caller's key (`verify_envelope_author`); forged/unsigned ⇒ `permission_denied`, malformed ⇒ `invalid_argument`. |
| `GetEnvSecret` | Returns the opaque `envelope` + `author_pubkey` for `(scope_id, epoch, path, version)` (0 = latest) to **any** authenticated caller. | None beyond authn — the seal gates decryption. Absent ⇒ `not_found`. `author_pubkey` lets the reader verify authorship. |
| `ListEnvSecrets` | Returns each `(path, version)` of `(scope_id, epoch)` at its latest version — **no envelope** — to any authenticated caller (so an admin's `rotate-scope` can re-seal every secret). | None beyond authn — the seal still gates decryption. |

---

## Proof

- **vault42 v14** — env-secret decryption round-trip (provisioned member reads + decrypts;
  `ops_env.rs::provisioned_member_reads_and_decrypts_env_secret`).
- **vault42 v15** — rotation forward-secrecy (removed member loses the new epoch).
- Core unit tests (`keyset.rs`): two-hop round-trip, wrong-member / forged-sig / mutated
  scope_id-epoch / wrong-granter rejects, grant byte round-trip.
- Server unit tests (`ops_scope.rs` / `ops_env.rs` / `ops_rotate.rs`): wrap-then-get,
  forged-granter / mislabeled-scope / cross-member-read / stale-rev / old-epoch-rewrap rejects.
- Control-plane gates: **m162** (RBAC hierarchy), **m166** (environments + groups + per-env grants +
  scope-pubkey publish), **m168** (invites), **m170** (standalone + 409 org-guard), **m172** (pubkey
  registry).
- Live cross-repo end-to-end: `scripts/test/e2e-rbac-scope-keys-live.sh` (grobase repo) — the
  authoritative CLI command sequence and expected outputs.
