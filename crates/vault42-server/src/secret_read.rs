/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   secret_read.rs                                       :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Owner-scoped reads of stored envelopes. Every query is filtered by `owner`, so a
//! principal can only ever see its own rows — cross-tenant isolation by construction,
//! independent of any pool state.

use crate::store::{Store, StoreError};
use rusqlite::{params, OptionalExtension};

/// A stored secret row: the opaque envelope plus the author public key sidecar a
/// recipient needs to verify a shared secret's authorship.
pub struct SecretRow {
    pub version: i64,
    pub envelope: Vec<u8>,
    pub author_pubkey: Vec<u8>,
}

impl Store {
    /// Fetch one secret version for `owner`/`path` (`version == 0` ⇒ latest), or
    /// `None` if absent.
    pub async fn get_secret(
        &self,
        owner: &str,
        path: &str,
        version: i64,
    ) -> Result<Option<SecretRow>, StoreError> {
        let (owner, path) = (owner.to_string(), path.to_string());
        self.run(move |c| {
            c.query_row(
                "SELECT version, envelope, author_pubkey FROM secrets \
                 WHERE owner=?1 AND path=?2 AND (?3=0 OR version=?3) ORDER BY version DESC LIMIT 1",
                params![owner, path, version],
                |r| {
                    Ok(SecretRow {
                        version: r.get(0)?,
                        envelope: r.get(1)?,
                        author_pubkey: r.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(|_| StoreError::Sql)
        })
        .await
    }

    /// List the latest version of each secret under `prefix` for `owner`.
    pub async fn list_secrets(
        &self,
        owner: &str,
        prefix: &str,
    ) -> Result<Vec<(String, i64, i64)>, StoreError> {
        let (owner, like) = (owner.to_string(), format!("{prefix}%"));
        self.run(move |c| {
            let mut stmt = c
                .prepare(
                    "SELECT path, MAX(version), MAX(updated_at) FROM secrets \
                     WHERE owner=?1 AND path LIKE ?2 GROUP BY path ORDER BY path",
                )
                .map_err(|_| StoreError::Sql)?;
            let rows = stmt
                .query_map(params![owner, like], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
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
