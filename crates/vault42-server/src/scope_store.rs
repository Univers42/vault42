/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   scope_store.rs                                       :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/22 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/22 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Owner-scoped storage of scope-key grants in the embedded SQLite store. A grant is
//! deposited under the MEMBER's owner (a foreign-owner write, like share) and read back
//! only by that same owner — strict per-member isolation by construction. The opaque
//! `GrantedScopeKey` blob and the granter public key are stored as base64 TEXT (mirroring
//! the `secrets` envelope discipline); the server holds no scope secret in the clear.

use crate::store::{now_unix, Store, StoreError};
use rusqlite::{params, OptionalExtension};

/// A deposited scope-key grant: who it is for, the scope/epoch it unlocks, the opaque
/// grant blob, the granter's public key, and when it was wrapped.
pub struct ScopeKeyPut {
    pub owner: String,
    pub scope_id: String,
    pub epoch: i64,
    pub granted_blob: String,
    pub granter_pubkey: String,
}

/// One member's wrap for a scope/epoch: the opaque grant blob and the granter key.
pub struct ScopeKeyRow {
    pub granted_blob: String,
    pub granter_pubkey: String,
}

impl Store {
    /// Upsert `put`'s grant for `(owner, scope_id, epoch)`. A re-deposit (same key)
    /// replaces the blob — re-granting after a rotation is idempotent for one epoch.
    pub async fn put_scope_key(&self, put: ScopeKeyPut) -> Result<(), StoreError> {
        self.run(move |c| {
            c.execute(
                "INSERT INTO scope_keys(owner,scope_id,epoch,granted_blob,granter_pubkey,wrapped_at) \
                 VALUES(?1,?2,?3,?4,?5,?6) \
                 ON CONFLICT(owner,scope_id,epoch) DO UPDATE SET \
                 granted_blob=excluded.granted_blob, granter_pubkey=excluded.granter_pubkey, \
                 wrapped_at=excluded.wrapped_at",
                params![
                    put.owner,
                    put.scope_id,
                    put.epoch,
                    put.granted_blob,
                    put.granter_pubkey,
                    now_unix()
                ],
            )
            .map_err(|_| StoreError::Sql)?;
            Ok(())
        })
        .await
    }

    /// Fetch `owner`'s own grant for `(scope_id, epoch)`, or `None`. Owner-scoped: a
    /// member can only ever read its own wrap, never another member's.
    pub async fn get_scope_key(
        &self,
        owner: &str,
        scope_id: &str,
        epoch: i64,
    ) -> Result<Option<ScopeKeyRow>, StoreError> {
        let (owner, scope_id) = (owner.to_string(), scope_id.to_string());
        self.run(move |c| {
            c.query_row(
                "SELECT granted_blob, granter_pubkey FROM scope_keys \
                 WHERE owner=?1 AND scope_id=?2 AND epoch=?3",
                params![owner, scope_id, epoch],
                |r| {
                    Ok(ScopeKeyRow {
                        granted_blob: r.get(0)?,
                        granter_pubkey: r.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(|_| StoreError::Sql)
        })
        .await
    }

    /// List `(member_id, wrapped_at)` for `owner`'s grants on `(scope_id, epoch)`.
    /// Owner-scoped, so it returns only the caller's own membership entry — never the
    /// cross-member set (that would breach isolation and is a control-plane concern).
    pub async fn list_scope_members(
        &self,
        owner: &str,
        scope_id: &str,
        epoch: i64,
    ) -> Result<Vec<(String, i64)>, StoreError> {
        let (owner, scope_id) = (owner.to_string(), scope_id.to_string());
        self.run(move |c| {
            let mut stmt = c
                .prepare(
                    "SELECT owner, wrapped_at FROM scope_keys \
                     WHERE owner=?1 AND scope_id=?2 AND epoch=?3 ORDER BY owner",
                )
                .map_err(|_| StoreError::Sql)?;
            let rows = stmt
                .query_map(params![owner, scope_id, epoch], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .map_err(|_| StoreError::Sql)?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(|_| StoreError::Sql)?);
            }
            Ok(out)
        })
        .await
    }
}
