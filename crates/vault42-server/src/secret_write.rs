/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   secret_write.rs                                      :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Owner-scoped writes. A push appends a new monotonic version only if the caller's
//! `expected_prev` matches the stored head (optimistic concurrency — a stale writer is
//! rejected, not silently overwritten). A share has no head the sharer can observe in
//! the recipient's space, so it passes `expected_prev = None` to append unconditionally.
//! The envelope is opaque bytes; the server never inspects plaintext. Writes are
//! serialized by the single-connection pool, so the read-then-insert is atomic.

use crate::store::{now_unix, Store, StoreError};
use rusqlite::params;

/// A versioned write: the opaque envelope, its owner/path/secret-id, the expected
/// previous version (`None` ⇒ unconditional append, for share), and the author key.
pub struct PutSecret {
    pub owner: String,
    pub path: String,
    pub secret_id: String,
    pub expected_prev: Option<i64>,
    pub envelope: Vec<u8>,
    pub author_pubkey: Vec<u8>,
}

impl Store {
    /// Append the next version for `(owner, path)`. With `Some(expected_prev)` the head
    /// must match (else `Conflict`); with `None` it appends unconditionally.
    pub async fn put_secret(&self, p: PutSecret) -> Result<i64, StoreError> {
        let max = self.max_secrets;
        self.run(move |c| {
            let current: i64 = c
                .query_row(
                    "SELECT COALESCE(MAX(version),0) FROM secrets WHERE owner=?1 AND path=?2",
                    params![p.owner, p.path],
                    |r| r.get(0),
                )
                .map_err(|_| StoreError::Sql)?;
            if matches!(p.expected_prev, Some(expected) if expected != current) {
                return Err(StoreError::Conflict);
            }
            if current == 0 && max > 0 {
                let owned: i64 = c
                    .query_row(
                        "SELECT COUNT(DISTINCT path) FROM secrets WHERE owner=?1",
                        params![p.owner],
                        |r| r.get(0),
                    )
                    .map_err(|_| StoreError::Sql)?;
                if owned >= max {
                    return Err(StoreError::Quota);
                }
            }
            let next = current + 1;
            c.execute(
                "INSERT INTO secrets(owner,path,secret_id,version,envelope,author_pubkey,updated_at) \
                 VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![p.owner, p.path, p.secret_id, next, p.envelope, p.author_pubkey, now_unix()],
            )
            .map_err(|_| StoreError::Sql)?;
            Ok(next)
        })
        .await
    }

    /// Delete `(owner, path)`: every version when `version == 0`, else just that one.
    /// Returns whether any row was removed.
    pub async fn remove_secret(
        &self,
        owner: &str,
        path: &str,
        version: i64,
    ) -> Result<bool, StoreError> {
        let (owner, path) = (owner.to_string(), path.to_string());
        self.run(move |c| {
            let removed = c
                .execute(
                    "DELETE FROM secrets WHERE owner=?1 AND path=?2 AND (?3=0 OR version=?3)",
                    params![owner, path, version],
                )
                .map_err(|_| StoreError::Sql)?;
            Ok(removed > 0)
        })
        .await
    }
}
