/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   ops_scope.rs                                         :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/22 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/22 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Scope-key operations (wrap / get / list-members) — the KEK-hierarchy server layer.
//! A granting admin DEPOSITS a member's wrapped scope key into the MEMBER's namespace (a
//! foreign-owner write, exactly like share): the server verifies the granter signature
//! over the opaque `GrantedScopeKey` WITHOUT decrypting (it holds no member secret), pins
//! the blob's bound `scope_id`/`epoch` to the request so a row cannot be mislabeled, then
//! stores it. A member fetches only ITS OWN wrap (owner = caller), so no member can read
//! another's. The blob is stored base64 TEXT (a bytea column cannot bind from JSON) and
//! crosses the wire as raw bytes; zero-knowledge holds throughout.

use crate::ops_write::map_store;
use crate::principal::Principal;
use crate::scope_store::ScopeKeyPut;
use crate::svc::VaultSvc;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use tonic::Status;
use vault42_core::{verify_grant_signature, AuthorPublicKey, GrantedScopeKey};
use vault42_proto::vault::v1::{
    GetScopeKeyResponse, ScopeMember, WrapScopeKeyRequest, WrapScopeKeyResponse,
};

impl VaultSvc {
    /// Deposit a granter-signed scope-key wrap into `req.member_id`'s namespace. Verifies
    /// the granter signature without decrypting, binds the blob's scope/epoch to the
    /// request, then stores the opaque blob base64-encoded. A forged/unsigned grant or a
    /// scope/epoch mismatch is `permission_denied`; the caller need not own `member_id`.
    pub(crate) async fn op_wrap_scope_key(
        &self,
        caller: &Principal,
        req: WrapScopeKeyRequest,
    ) -> Result<WrapScopeKeyResponse, Status> {
        let grant = GrantedScopeKey::from_bytes(&req.granted_blob)
            .map_err(|_| Status::invalid_argument("malformed scope-key grant"))?;
        let granter = granter_key(&req.granter_pubkey)?;
        verify_grant_signature(&grant, &granter)
            .map_err(|_| Status::permission_denied("scope-key grant signature invalid"))?;
        bind_request_to_grant(&grant, &req)?;
        self.store
            .put_scope_key(ScopeKeyPut {
                owner: req.member_id.clone(),
                scope_id: req.scope_id.clone(),
                epoch: req.epoch as i64,
                granted_blob: STANDARD.encode(&req.granted_blob),
                granter_pubkey: STANDARD.encode(&req.granter_pubkey),
            })
            .await
            .map_err(map_store)?;
        self.emit_audit(caller, "wrap_scope_key", &scope_target(&req))
            .await;
        Ok(WrapScopeKeyResponse { stored: true })
    }

    /// Fetch the caller's OWN wrap for `(scope_id, epoch)`, returning the opaque blob and
    /// granter key as raw bytes. Owner-scoped to the caller — a member can never read
    /// another member's wrap. `not_found` when the caller has no grant for the scope.
    pub(crate) async fn op_get_scope_key(
        &self,
        caller: &Principal,
        scope_id: &str,
        epoch: u32,
    ) -> Result<GetScopeKeyResponse, Status> {
        let row = self
            .store
            .get_scope_key(&caller.id, scope_id, epoch as i64)
            .await
            .map_err(map_store)?
            .ok_or_else(|| Status::not_found("no scope-key grant for this scope"))?;
        Ok(GetScopeKeyResponse {
            granted_blob: decode_b64(&row.granted_blob)?,
            granter_pubkey: decode_b64(&row.granter_pubkey)?,
        })
    }

    /// List the scope members the caller may see for `(scope_id, epoch)`. Owner-scoped:
    /// it returns the caller's own membership entry, never the cross-member set (that is
    /// a control-plane concern and would breach per-member isolation here).
    pub(crate) async fn op_list_scope_members(
        &self,
        caller: &Principal,
        scope_id: &str,
        epoch: u32,
    ) -> Result<Vec<ScopeMember>, Status> {
        let rows = self
            .store
            .list_scope_members(&caller.id, scope_id, epoch as i64)
            .await
            .map_err(map_store)?;
        Ok(rows
            .into_iter()
            .map(|(member_id, wrapped_at)| ScopeMember {
                member_id,
                wrapped_at,
            })
            .collect())
    }
}

/// Parse the 32-byte granter Ed25519 public key from the request, or fail.
fn granter_key(bytes: &[u8]) -> Result<AuthorPublicKey, Status> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Status::invalid_argument("granter pubkey length"))?;
    AuthorPublicKey::from_bytes(&arr).map_err(|_| Status::invalid_argument("granter pubkey"))
}

/// Pin the request's claimed `(scope_id, epoch)` to what the blob's signature binds, so a
/// caller cannot file a genuinely-signed grant under a different scope/epoch row.
fn bind_request_to_grant(grant: &GrantedScopeKey, req: &WrapScopeKeyRequest) -> Result<(), Status> {
    if grant.epoch != req.epoch || hex::encode(grant.scope_id) != req.scope_id {
        return Err(Status::permission_denied(
            "scope-key grant does not match the request scope/epoch",
        ));
    }
    Ok(())
}

/// The audit target string for a wrap: `member/scope@epoch`.
fn scope_target(req: &WrapScopeKeyRequest) -> String {
    format!("{}/{}@{}", req.member_id, req.scope_id, req.epoch)
}

/// Decode a base64 TEXT column back to the raw bytes the wire carries.
fn decode_b64(text: &str) -> Result<Vec<u8>, Status> {
    STANDARD
        .decode(text)
        .map_err(|_| Status::internal("corrupt stored scope key"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use std::sync::Arc;
    use vault42_core::{generate_keyset, grant_scope_key, Identity};

    /// A fresh service over a throwaway SQLite store (no grobase, no contract gate).
    fn fresh_svc(tag: &str) -> VaultSvc {
        let path =
            std::env::temp_dir().join(format!("vault42-scope-{}-{tag}.db", std::process::id()));
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
        let store = Store::open(path.to_str().expect("path"), 0).expect("open");
        VaultSvc::new(Arc::new(store), 120, None, None)
    }

    /// Sign a genuine grant of `scope`/`epoch` to `member`'s X25519 key by `granter`.
    fn signed_grant(granter: &Identity, member: &Identity, scope: [u8; 16], epoch: u32) -> Vec<u8> {
        let (_keyset, scope_secret) = generate_keyset(scope, epoch);
        grant_scope_key(
            &scope_secret,
            &member.encryption_public(),
            granter.signing_key(),
            scope,
            epoch,
        )
        .expect("grant")
        .to_bytes()
        .expect("to_bytes")
    }

    /// Build a wrap request depositing `blob` for `member` under `scope`/`epoch`.
    fn wrap_req(
        member: &Principal,
        granter: &Identity,
        scope: [u8; 16],
        blob: Vec<u8>,
    ) -> WrapScopeKeyRequest {
        WrapScopeKeyRequest {
            member_id: member.id.clone(),
            scope_id: hex::encode(scope),
            epoch: 1,
            granted_blob: blob,
            granter_pubkey: granter.author_public().to_bytes().to_vec(),
        }
    }

    #[tokio::test]
    async fn wrap_then_get_returns_same_blob() {
        let svc = fresh_svc("roundtrip");
        let (granter, member) = (Identity::generate(), Identity::generate());
        let member_p = Principal::from_pubkey(member.author_public().to_bytes());
        let scope = [1u8; 16];
        let blob = signed_grant(&granter, &member, scope, 1);
        let admin = Principal::from_pubkey(granter.author_public().to_bytes());
        svc.op_wrap_scope_key(&admin, wrap_req(&member_p, &granter, scope, blob.clone()))
            .await
            .expect("wrap");
        let got = svc
            .op_get_scope_key(&member_p, &hex::encode(scope), 1)
            .await
            .expect("get");
        assert_eq!(got.granted_blob, blob);
        assert_eq!(got.granter_pubkey, granter.author_public().to_bytes());
    }

    #[tokio::test]
    async fn forged_granter_sig_is_rejected() {
        let svc = fresh_svc("forged");
        let (granter, attacker, member) = (
            Identity::generate(),
            Identity::generate(),
            Identity::generate(),
        );
        let member_p = Principal::from_pubkey(member.author_public().to_bytes());
        let scope = [2u8; 16];
        let blob = signed_grant(&granter, &member, scope, 1);
        let admin = Principal::from_pubkey(attacker.author_public().to_bytes());
        let err = svc
            .op_wrap_scope_key(&admin, wrap_req(&member_p, &attacker, scope, blob))
            .await
            .expect_err("must reject");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn mislabeled_scope_is_rejected() {
        let svc = fresh_svc("mislabel");
        let (granter, member) = (Identity::generate(), Identity::generate());
        let member_p = Principal::from_pubkey(member.author_public().to_bytes());
        let blob = signed_grant(&granter, &member, [4u8; 16], 1);
        let admin = Principal::from_pubkey(granter.author_public().to_bytes());
        let mut req = wrap_req(&member_p, &granter, [4u8; 16], blob);
        req.scope_id = hex::encode([5u8; 16]);
        let err = svc
            .op_wrap_scope_key(&admin, req)
            .await
            .expect_err("mislabel must reject");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn another_member_cannot_read_the_wrap() {
        let svc = fresh_svc("isolation");
        let (granter, member, intruder) = (
            Identity::generate(),
            Identity::generate(),
            Identity::generate(),
        );
        let member_p = Principal::from_pubkey(member.author_public().to_bytes());
        let intruder_p = Principal::from_pubkey(intruder.author_public().to_bytes());
        let scope = [3u8; 16];
        let blob = signed_grant(&granter, &member, scope, 1);
        let admin = Principal::from_pubkey(granter.author_public().to_bytes());
        svc.op_wrap_scope_key(&admin, wrap_req(&member_p, &granter, scope, blob))
            .await
            .expect("wrap");
        let err = svc
            .op_get_scope_key(&intruder_p, &hex::encode(scope), 1)
            .await
            .expect_err("intruder must not read");
        assert_eq!(err.code(), tonic::Code::NotFound);
    }
}
