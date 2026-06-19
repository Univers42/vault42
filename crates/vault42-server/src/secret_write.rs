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
//! rejected, not silently overwritten). The envelope is opaque bytes; the server never
//! inspects plaintext.

use crate::store::{now_unix, Store, StoreError};
use rusqlite::params;

/// A versioned write: the opaque envelope, its owner/path/secret-id, the expected
/// previous version, and the author public-key sidecar.
pub struct PutSecret {
    pub owner: String,
    pub path: String,
    pub secret_id: String,
    pub expected_prev: i64,
    pub envelope: Vec<u8>,
    pub author_pubkey: Vec<u8>,
}

impl Store {
    /// Append the next version for `(owner, path)` iff the head equals
    /// `expected_prev`; returns the new version or `Conflict`.
    pub async fn put_secret(&self, p: PutSecret) -> Result<i64, StoreError> {
        self.run(move |c| {
            let current: i64 = c
                .query_row(
                    "SELECT COALESCE(MAX(version),0) FROM secrets WHERE owner=?1 AND path=?2",
                    params![p.owner, p.path],
                    |r| r.get(0),
                )
                .map_err(|_| StoreError::Sql)?;
            if current != p.expected_prev {
                return Err(StoreError::Conflict);
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

    /// Delete every version of `(owner, path)`; returns whether any row was removed.
    pub async fn remove_secret(&self, owner: &str, path: &str) -> Result<bool, StoreError> {
        let (owner, path) = (owner.to_string(), path.to_string());
        self.run(move |c| {
            let removed = c
                .execute(
                    "DELETE FROM secrets WHERE owner=?1 AND path=?2",
                    params![owner, path],
                )
                .map_err(|_| StoreError::Sql)?;
            Ok(removed > 0)
        })
        .await
    }
}
