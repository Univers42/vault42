/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   tenants.rs                                           :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The tenant registry backing contract issuance.
//!
//! A tenant name ends up inside a signed contract, so the claim must be settled before
//! anything is signed. A repeat claim by the same author fingerprint is idempotent, which
//! is what lets a client re-register to refresh an expiring contract; a claim by a
//! different fingerprint is refused so a name cannot be stolen.

use super::Store;
use crate::error::{Error, Result};
use rusqlite::params;

impl Store {
    /// Claim `tenant` for `author_fp`. False means the name is held by someone else.
    ///
    /// The read and the insert share one serialized connection, so two concurrent claims
    /// cannot both succeed.
    pub async fn claim_tenant(
        &self,
        tenant: String,
        author_fp: String,
        account_id: Option<String>,
        now: i64,
    ) -> Result<bool> {
        self.call(move |conn| {
            let held: Option<String> = conn
                .query_row(
                    "SELECT author_fp FROM tenants WHERE tenant=?1",
                    params![tenant],
                    |row| row.get(0),
                )
                .ok();
            match held {
                Some(existing) => Ok(existing == author_fp),
                None => {
                    insert(conn, &tenant, &author_fp, account_id.as_deref(), now).map(|()| true)
                }
            }
        })
        .await
    }
}

/// Insert a fresh tenant claim.
fn insert(
    conn: &rusqlite::Connection,
    tenant: &str,
    author_fp: &str,
    account_id: Option<&str>,
    now: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO tenants(tenant, author_fp, account_id, created_at) VALUES(?1,?2,?3,?4)",
        params![tenant, author_fp, account_id, now],
    )
    .map_err(|e| Error::Internal(e.into()))?;
    Ok(())
}
