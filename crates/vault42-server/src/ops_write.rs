/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   ops_write.rs                                         :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Write operations (push / share / rotate / rotate-keys / rm). The server verifies the
//! envelope's author signature against the caller's key WITHOUT decrypting — so it
//! stores only well-formed, caller-authored envelopes. For push/rotate the signed owner
//! MUST equal the caller (a principal cannot write into another's namespace); only
//! `share` may target a foreign owner, and then the write is an unconditional append
//! into that recipient's space — the friend later reads it with their own key.

use crate::principal::Principal;
use crate::secret_write::PutSecret;
use crate::store::StoreError;
use crate::svc::VaultSvc;
use tonic::Status;
use vault42_core::{verify_envelope_author, Envelope};
use vault42_proto::vault::v1::{PushResponse, ReKeyed, RmResponse};

/// One write request: who, where, the opaque envelope, the expected head version, and
/// the audit action label (push / share / rotate / rotate_keys).
pub struct WriteOp<'a> {
    pub caller: &'a Principal,
    pub path: &'a str,
    pub envelope: &'a [u8],
    pub expected_prev: i64,
    pub action: &'a str,
}

impl VaultSvc {
    /// Store a caller-authored envelope. push/rotate require the signed owner to equal
    /// the caller and use optimistic concurrency; share targets a foreign owner and
    /// appends unconditionally.
    pub(crate) async fn op_write(&self, op: WriteOp<'_>) -> Result<PushResponse, Status> {
        let env = Envelope::from_bytes(op.envelope)
            .map_err(|_| Status::invalid_argument("malformed envelope"))?;
        verify_envelope_author(&env, &op.caller.pubkey)
            .map_err(|_| Status::permission_denied("envelope not authored by caller"))?;
        let is_share = op.action == "share";
        if !is_share && env.metadata.owner != op.caller.id {
            return Err(Status::permission_denied(
                "envelope owner must be the caller",
            ));
        }
        let owner = env.metadata.owner.clone();
        let secret_id = env.metadata.secret_id.clone();
        let version = self
            .store
            .put_secret(PutSecret {
                owner: owner.clone(),
                path: op.path.to_string(),
                secret_id: secret_id.clone(),
                expected_prev: (!is_share).then_some(op.expected_prev),
                envelope: op.envelope.to_vec(),
                author_pubkey: op.caller.pubkey.to_vec(),
            })
            .await
            .map_err(map_store)?;
        self.emit_audit(op.caller, op.action, &format!("{owner}/{}", op.path))
            .await;
        Ok(PushResponse {
            secret_id,
            version: version as u64,
        })
    }

    /// Re-key a batch of secrets (each item is a freshly re-wrapped envelope).
    pub(crate) async fn op_rotate_keys(
        &self,
        caller: &Principal,
        items: Vec<ReKeyed>,
    ) -> Result<u32, Status> {
        let mut rewrapped = 0u32;
        for item in items {
            self.op_write(WriteOp {
                caller,
                path: &item.path,
                envelope: &item.envelope,
                expected_prev: item.expected_prev_rev as i64,
                action: "rotate_keys",
            })
            .await?;
            rewrapped += 1;
        }
        Ok(rewrapped)
    }

    /// Delete `path` for the caller: all versions when `version == 0`, else just one.
    pub(crate) async fn op_rm(
        &self,
        caller: &Principal,
        path: &str,
        version: u64,
    ) -> Result<RmResponse, Status> {
        let removed = self
            .store
            .remove_secret(&caller.id, path, version as i64)
            .await
            .map_err(map_store)?;
        self.emit_audit(caller, "rm", path).await;
        Ok(RmResponse {
            tombstoned: removed,
        })
    }
}

/// Map a storage error to the right gRPC status.
pub(crate) fn map_store(error: StoreError) -> Status {
    match error {
        StoreError::Conflict => Status::failed_precondition("version conflict"),
        StoreError::Quota => Status::resource_exhausted("per-owner secret quota exceeded"),
        StoreError::Sql => Status::internal("storage error"),
    }
}
