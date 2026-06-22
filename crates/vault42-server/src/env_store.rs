/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   env_store.rs                                         :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/22 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/22 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Shared env-secret storage in the embedded SQLite store. An env secret is sealed
//! CLIENT-SIDE to the scope's X25519 PUBLIC key, so it is stored ONCE keyed by
//! `(scope_id, epoch, path, version)` — NOT owner-scoped — and readable by ANY caller:
//! the seal IS the access control (only a holder of the scope private key can decrypt).
//! Versioning mirrors `secret_write`: an append bumps the head with optimistic
//! concurrency, so a stale writer is rejected rather than silently overwriting. The
//! opaque envelope is stored as base64 TEXT (mirroring the scope-key discipline); the
//! server never sees plaintext.

use crate::store::{now_unix, Store, StoreError};
use rusqlite::{params, OptionalExtension};

/// A versioned env-secret write: the scope/epoch/path it keys, the expected previous
/// head version (`None` ⇒ unconditional append), the base64 envelope, and the base64
/// author public key recipients verify authorship against.
pub struct EnvSecretPut {
    pub scope_id: String,
    pub epoch: i64,
    pub path: String,
    pub expected_prev: Option<i64>,
    pub envelope_b64: String,
    pub author_pubkey_b64: String,
}

/// One stored env-secret row: its version, the base64 envelope, and the base64 author
/// public key. Both blobs are returned opaque (the caller decodes to raw wire bytes).
pub struct EnvSecretRow {
    pub version: i64,
    pub envelope_b64: String,
    pub author_pubkey_b64: String,
}

impl Store {
    /// Append the next version for `(scope_id, epoch, path)`. With `Some(expected_prev)`
    /// the stored head must match (else `Conflict`); with `None` it appends
    /// unconditionally. The single-connection pool serializes the read-then-insert.
    pub async fn put_env_secret(&self, put: EnvSecretPut) -> Result<i64, StoreError> {
        self.run(move |c| {
            let current: i64 = c
                .query_row(
                    "SELECT COALESCE(MAX(version),0) FROM env_secrets \
                     WHERE scope_id=?1 AND epoch=?2 AND path=?3",
                    params![put.scope_id, put.epoch, put.path],
                    |r| r.get(0),
                )
                .map_err(|_| StoreError::Sql)?;
            if matches!(put.expected_prev, Some(expected) if expected != current) {
                return Err(StoreError::Conflict);
            }
            let next = current + 1;
            c.execute(
                "INSERT INTO env_secrets(scope_id,epoch,path,version,envelope,author_pubkey,updated_at) \
                 VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![
                    put.scope_id,
                    put.epoch,
                    put.path,
                    next,
                    put.envelope_b64,
                    put.author_pubkey_b64,
                    now_unix()
                ],
            )
            .map_err(|_| StoreError::Sql)?;
            Ok(next)
        })
        .await
    }

    /// Fetch one env-secret version for `(scope_id, epoch, path)` (`version == 0` ⇒
    /// latest), or `None`. NOT owner-scoped — any caller may read the opaque blob; the
    /// seal to the scope public key is the access control.
    pub async fn get_env_secret(
        &self,
        scope_id: &str,
        epoch: i64,
        path: &str,
        version: i64,
    ) -> Result<Option<EnvSecretRow>, StoreError> {
        let (scope_id, path) = (scope_id.to_string(), path.to_string());
        self.run(move |c| {
            c.query_row(
                "SELECT version, envelope, author_pubkey FROM env_secrets \
                 WHERE scope_id=?1 AND epoch=?2 AND path=?3 AND (?4=0 OR version=?4) \
                 ORDER BY version DESC LIMIT 1",
                params![scope_id, epoch, path, version],
                |r| {
                    Ok(EnvSecretRow {
                        version: r.get(0)?,
                        envelope_b64: r.get(1)?,
                        author_pubkey_b64: r.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(|_| StoreError::Sql)
        })
        .await
    }

    /// List `(path, latest_version)` for every env secret of `(scope_id, epoch)`,
    /// path-sorted. NOT owner-scoped — the seal to the scope public key gates decryption;
    /// enumerating paths is open to any caller (the basis for an admin's rotate re-seal).
    pub async fn list_env_secrets(
        &self,
        scope_id: &str,
        epoch: i64,
    ) -> Result<Vec<(String, i64)>, StoreError> {
        let scope_id = scope_id.to_string();
        self.run(move |c| {
            let mut stmt = c
                .prepare(
                    "SELECT path, MAX(version) FROM env_secrets \
                     WHERE scope_id=?1 AND epoch=?2 GROUP BY path ORDER BY path",
                )
                .map_err(|_| StoreError::Sql)?;
            let rows = stmt
                .query_map(params![scope_id, epoch], |r| Ok((r.get(0)?, r.get(1)?)))
                .map_err(|_| StoreError::Sql)?;
            rows.collect::<Result<Vec<(String, i64)>, _>>()
                .map_err(|_| StoreError::Sql)
        })
        .await
    }
}
