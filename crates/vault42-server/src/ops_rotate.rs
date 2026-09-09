/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   ops_rotate.rs                                        :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/22 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/22 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Forward-secure scope rotation — the revocation half of the KEK hierarchy. The caller
//! has already re-sealed the scope's secrets to a FRESH scope keypair and re-wrapped the
//! new scope key to the REMAINING members client-side; this server step only persists the
//! new-epoch wraps. Each rewrap is verified WITHOUT decrypting (granter signature) AND
//! pinned to the rotation's new epoch, so a genuinely-signed old-epoch grant cannot be
//! smuggled into the new member set. A removed member simply has no new-epoch wrap, so it
//! can no longer reach the rotated secret — forward secrecy by absence, never by deletion.
//!
//! Absence is also why the caller's OWN wrap is a precondition rather than a courtesy: the
//! new scope key exists only in the rotating client's memory, so a rotation that omits the
//! caller leaves nobody able to open the secrets it just re-sealed.

use crate::principal::Principal;
use crate::svc::VaultSvc;
use tonic::Status;
use vault42_proto::vault::v1::{RotateScopeRequest, RotateScopeResponse, WrapScopeKeyRequest};

impl VaultSvc {
    /// Persist the new-epoch member wraps of a scope rotation. Refuses outright a rotation
    /// carrying no wrap for the caller, which would strand the scope. Then verifies and
    /// stores each rewrap (granter-signed, scope/epoch-bound, pinned to `new_epoch`); a
    /// malformed, forged, mislabeled, or wrong-epoch rewrap aborts the rotation before the
    /// audit event, leaving any rewrap already accepted in place for a reconcile to finish.
    /// Emits a single `scope_rotate` audit event keyed to `scope@new_epoch`.
    pub(crate) async fn op_rotate_scope(
        &self,
        caller: &Principal,
        req: RotateScopeRequest,
    ) -> Result<RotateScopeResponse, Status> {
        let RotateScopeRequest {
            scope_id,
            new_epoch,
            rewraps,
        } = req;
        require_caller_rewrap(caller, &rewraps)?;
        let mut rewrapped = 0u32;
        for rewrap in rewraps {
            self.store_one_rewrap(rewrap, Some(new_epoch)).await?;
            rewrapped += 1;
        }
        self.emit_audit(caller, "scope_rotate", &format!("{scope_id}@{new_epoch}"))
            .await;
        Ok(RotateScopeResponse { rewrapped })
    }
}

/// Refuse a rotation that does not re-wrap the new scope key to the rotating caller.
///
/// The new scope secret lives only in the rotating client's memory: it is generated there,
/// used to re-seal every secret, and gone when the process exits. A rotation carrying no
/// wrap for the caller therefore destroys the only copy of the key its own re-sealed
/// secrets now need, and because an epoch never regresses there is no way back. Requiring
/// the caller's own wrap costs nothing in privilege — re-sealing already obliges the caller
/// to decrypt every secret in the scope — and it is what keeps a rotation repairable.
///
/// Checked before the first rewrap is persisted, so a refused rotation stores nothing.
fn require_caller_rewrap(
    caller: &Principal,
    rewraps: &[WrapScopeKeyRequest],
) -> Result<(), Status> {
    if rewraps.iter().any(|r| r.member_id == caller.id) {
        return Ok(());
    }
    Err(Status::invalid_argument(
        "rotation must re-wrap the new scope key to the rotating caller, \
         otherwise the new key is unrecoverable and the scope is stranded",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::principal::Principal;
    use crate::store::Store;
    use std::sync::Arc;
    use vault42_core::{
        generate_keyset, grant_scope_key, open, open_scope_key, scope_recipients, seal, Identity,
        Kind, Metadata, ReadScope, RecipientPublicKey, RecipientSecretKey, ScopeKeyset,
        DEFAULT_MODE,
    };
    use vault42_proto::vault::v1::WrapScopeKeyRequest;
    use zeroize::Zeroizing;

    /// A fresh service over a throwaway SQLite store (no grobase, no contract gate).
    fn fresh_svc(tag: &str) -> VaultSvc {
        let path =
            std::env::temp_dir().join(format!("vault42-rotate-{}-{tag}.db", std::process::id()));
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
        let store = Store::open(path.to_str().expect("path"), 0).expect("open");
        VaultSvc::new(Arc::new(store), 120, None, None)
    }

    /// Fixed metadata for the scope secret at a given rev (the secret revs with the epoch).
    fn scope_meta(rev: u64) -> Metadata {
        Metadata {
            version: 2,
            secret_id: "scope-secret".into(),
            tenant: "self".into(),
            owner: "scope:env-prod".into(),
            rev,
            content_type: "env".into(),
            recovery_optin: false,
            project_id: "p-rot".into(),
            relative_path: String::new(),
            kind: Kind::Generic,
            mode: DEFAULT_MODE,
        }
    }

    /// Reconstruct a usable X25519 secret from an opened scope private buffer.
    fn as_secret(scope_priv: &Zeroizing<[u8; 32]>) -> RecipientSecretKey {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&scope_priv[..]);
        RecipientSecretKey::from(bytes)
    }

    /// Seal `plaintext` to a scope keyset's public key, authored by `author`; wire bytes.
    fn seal_to_scope(
        keyset: &ScopeKeyset,
        author: &Identity,
        rev: u64,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let recipients = scope_recipients(keyset, None);
        seal(
            plaintext,
            scope_meta(rev),
            &recipients,
            author.signing_key(),
        )
        .expect("seal")
        .to_bytes()
        .expect("encode")
    }

    /// Build a wrap request depositing `granter`'s grant of `scope_secret` to `member` for
    /// `(scope, epoch)` — exactly the bytes a granting admin sends to WrapScopeKey.
    fn wrap_req(
        member: &Principal,
        member_pub: &RecipientPublicKey,
        granter: &Identity,
        scope_secret: &Zeroizing<[u8; 32]>,
        scope: [u8; 16],
        epoch: u32,
    ) -> WrapScopeKeyRequest {
        let blob = grant_scope_key(
            scope_secret,
            member_pub,
            granter.signing_key(),
            scope,
            epoch,
        )
        .expect("grant")
        .to_bytes()
        .expect("to_bytes");
        WrapScopeKeyRequest {
            member_id: member.id.clone(),
            scope_id: hex::encode(scope),
            epoch,
            granted_blob: blob,
            granter_pubkey: granter.author_public().to_bytes().to_vec(),
        }
    }

    /// Fetch the caller's wrap, open the scope secret, then open the envelope with it.
    async fn decrypt_via_scope(
        svc: &VaultSvc,
        member: &(Principal, Identity),
        granter: &Identity,
        author: &Identity,
        scope: [u8; 16],
        epoch: u32,
        envelope: &[u8],
    ) -> vault42_core::Result<Zeroizing<Vec<u8>>> {
        let row = svc
            .op_get_scope_key(&member.0, &hex::encode(scope), epoch)
            .await
            .expect("get wrap");
        let grant = vault42_core::GrantedScopeKey::from_bytes(&row.granted_blob).expect("grant");
        let scope_secret = open_scope_key(
            &grant,
            member.1.encryption_secret(),
            &granter.author_public(),
        )?;
        let env = vault42_core::Envelope::from_bytes(envelope).expect("envelope");
        let read = ReadScope {
            secret_id: "scope-secret",
            min_rev: 0,
        };
        open(
            &env,
            &as_secret(&scope_secret),
            &author.author_public(),
            &read,
        )
    }

    /// v14 — full decryption round-trip through the server's scope-key surface, plus the
    /// non-member denial: a provisioned member two-hop-opens the scope secret and reads the
    /// plaintext; an identity with no wrap gets NotFound and cannot decrypt.
    #[tokio::test]
    async fn scope_key_e2e_roundtrip_and_non_member_denied() {
        let svc = fresh_svc("v14");
        let (granter, author) = (Identity::generate(), Identity::generate());
        let member = Identity::generate();
        let member_p = Principal::from_pubkey(member.author_public().to_bytes());
        let admin = Principal::from_pubkey(granter.author_public().to_bytes());
        let scope = [1u8; 16];
        let plaintext = b"DATABASE_URL=postgres://prod";
        let (keyset, scope_secret) = generate_keyset(scope, 1);
        let envelope = seal_to_scope(&keyset, &author, 1, plaintext);
        let member_pub = member.encryption_public();
        svc.op_wrap_scope_key(
            &admin,
            wrap_req(&member_p, &member_pub, &granter, &scope_secret, scope, 1),
        )
        .await
        .expect("wrap member");

        let opened = decrypt_via_scope(
            &svc,
            &(member_p, member),
            &granter,
            &author,
            scope,
            1,
            &envelope,
        )
        .await
        .expect("member decrypts");
        assert_eq!(&opened[..], plaintext);

        let outsider = Identity::generate();
        let outsider_p = Principal::from_pubkey(outsider.author_public().to_bytes());
        let err = svc
            .op_get_scope_key(&outsider_p, &hex::encode(scope), 1)
            .await
            .expect_err("non-member must not have a wrap");
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    /// v15 — rotation forward-secrecy: after a rotation to epoch 2 (secret re-sealed to a
    /// FRESH scope keypair, re-wrapped ONLY to the remaining member), the remaining member
    /// opens the new secret; the removed member has no epoch-2 wrap (NotFound) AND its old
    /// epoch-1 scope secret cannot open the epoch-2 envelope (sealed to the new scope key).
    #[tokio::test]
    async fn rotation_revokes_removed_member_forward_secrecy() {
        let svc = fresh_svc("v15");
        let (granter, author) = (Identity::generate(), Identity::generate());
        let (keep, drop_member) = (Identity::generate(), Identity::generate());
        let keep_p = Principal::from_pubkey(keep.author_public().to_bytes());
        let drop_p = Principal::from_pubkey(drop_member.author_public().to_bytes());
        let admin = Principal::from_pubkey(granter.author_public().to_bytes());
        let scope = [2u8; 16];
        let (_k1, s1) = generate_keyset(scope, 1);
        for member in [
            (&keep_p, keep.encryption_public()),
            (&drop_p, drop_member.encryption_public()),
        ] {
            svc.op_wrap_scope_key(
                &admin,
                wrap_req(member.0, &member.1, &granter, &s1, scope, 1),
            )
            .await
            .expect("wrap epoch1");
        }

        let (k2, s2) = generate_keyset(scope, 2);
        let new_plaintext = b"v2-secret-rotated";
        let env2 = seal_to_scope(&k2, &author, 2, new_plaintext);
        let keep_pub = keep.encryption_public();
        let admin_pub = granter.encryption_public();
        let req = RotateScopeRequest {
            scope_id: hex::encode(scope),
            new_epoch: 2,
            rewraps: vec![
                wrap_req(&keep_p, &keep_pub, &granter, &s2, scope, 2),
                wrap_req(&admin, &admin_pub, &granter, &s2, scope, 2),
            ],
        };
        assert_eq!(
            svc.op_rotate_scope(&admin, req)
                .await
                .expect("rotate")
                .rewrapped,
            2
        );

        let opened = decrypt_via_scope(&svc, &(keep_p, keep), &granter, &author, scope, 2, &env2)
            .await
            .expect("remaining member decrypts epoch2");
        assert_eq!(&opened[..], new_plaintext);

        let err = svc
            .op_get_scope_key(&drop_p, &hex::encode(scope), 2)
            .await
            .expect_err("removed member has no epoch2 wrap");
        assert_eq!(err.code(), tonic::Code::NotFound);

        let env2_dec = vault42_core::Envelope::from_bytes(&env2).expect("env2");
        let read = ReadScope {
            secret_id: "scope-secret",
            min_rev: 0,
        };
        let stale = open(&env2_dec, &as_secret(&s1), &author.author_public(), &read);
        assert!(
            stale.is_err(),
            "epoch1 scope secret must not open the epoch2 envelope"
        );
    }

    /// A genuinely-signed grant for the OLD epoch must NOT be acceptable as a new-epoch
    /// rewrap: `op_rotate_scope` pins each rewrap to `new_epoch`, so smuggling an epoch-1
    /// grant into a rotation to epoch 2 is `permission_denied` and persists nothing.
    #[tokio::test]
    async fn rotation_rejects_a_wrong_epoch_rewrap() {
        let svc = fresh_svc("v15-epoch");
        let granter = Identity::generate();
        let keep = Identity::generate();
        let keep_p = Principal::from_pubkey(keep.author_public().to_bytes());
        let admin = Principal::from_pubkey(granter.author_public().to_bytes());
        let scope = [6u8; 16];
        let (_k2, s2) = generate_keyset(scope, 2);
        let keep_pub = keep.encryption_public();
        let admin_pub = granter.encryption_public();
        let stale_rewrap = wrap_req(&keep_p, &keep_pub, &granter, &s2, scope, 1);
        let req = RotateScopeRequest {
            scope_id: hex::encode(scope),
            new_epoch: 2,
            rewraps: vec![
                stale_rewrap,
                wrap_req(&admin, &admin_pub, &granter, &s2, scope, 2),
            ],
        };
        let err = svc
            .op_rotate_scope(&admin, req)
            .await
            .expect_err("a wrong-epoch rewrap must be rejected");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        for who in [&keep_p, &admin] {
            let leaked = svc.op_get_scope_key(who, &hex::encode(scope), 2).await;
            assert!(
                matches!(leaked, Err(ref e) if e.code() == tonic::Code::NotFound),
                "a rejected rotation must persist no epoch-2 wrap"
            );
        }
    }

    /// A rotation that re-wraps the new scope key to everyone EXCEPT the caller is refused.
    ///
    /// This is the shape that silently destroyed a whole environment: the client computed its
    /// re-wrap set from the grant "missing" list, which is empty once every member is already
    /// provisioned, so a rotation re-sealed every secret to a new key and then wrapped that
    /// key to nobody. The server reported success. Refusing it here means no client bug can
    /// reach that outcome, regardless of how the re-wrap set was computed.
    #[tokio::test]
    async fn rotation_without_a_wrap_for_the_caller_is_refused() {
        let svc = fresh_svc("v15-caller");
        let granter = Identity::generate();
        let keep = Identity::generate();
        let keep_p = Principal::from_pubkey(keep.author_public().to_bytes());
        let admin = Principal::from_pubkey(granter.author_public().to_bytes());
        let scope = [9u8; 16];
        let (_k2, s2) = generate_keyset(scope, 2);
        let keep_pub = keep.encryption_public();
        for rewraps in [
            vec![wrap_req(&keep_p, &keep_pub, &granter, &s2, scope, 2)],
            Vec::new(),
        ] {
            let req = RotateScopeRequest {
                scope_id: hex::encode(scope),
                new_epoch: 2,
                rewraps,
            };
            let err = svc
                .op_rotate_scope(&admin, req)
                .await
                .expect_err("a rotation the caller cannot recover must be refused");
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }
        let stranded = svc.op_get_scope_key(&keep_p, &hex::encode(scope), 2).await;
        assert!(
            matches!(stranded, Err(ref e) if e.code() == tonic::Code::NotFound),
            "a refused rotation must persist nothing"
        );
    }
}
