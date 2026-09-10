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
//! anything is signed. A claim is OWNED BY AN ACCOUNT, not merely by a key: the account is
//! the durable identity, the key is a device credential that can be lost or rotated. That
//! ownership is what makes three things possible that a key-only registry cannot express —
//! an owner rebinding their own name to a fresh key, a quota that bounds squatting, and
//! releasing the name when the account goes away.

use super::Store;
use crate::error::{Error, Result};
use rusqlite::params;

/// The outcome of a claim attempt. Three states, because "false" conflated a name held by
/// somebody else with a quota refusal, and the caller must answer them with different
/// statuses (409 versus 403) for the operator to know which wall they hit.
#[derive(Debug, PartialEq, Eq)]
pub enum Claim {
    /// The name is now bound to this account and key.
    Granted,
    /// Another account holds the name.
    Taken,
    /// This account already holds as many names as it may.
    QuotaExceeded,
}

impl Store {
    /// Claim `tenant` for `account_id` at `author_fp`, bounded by `max_tenants`.
    ///
    /// The read, the quota count and the write share one serialized connection, so two
    /// concurrent claims cannot both succeed and cannot both pass the quota check.
    ///
    /// Re-claiming a name the account already owns REBINDS it to the presented key. Without
    /// that, losing a keystore stranded the name forever: the old fingerprint could never be
    /// presented again and no path anywhere released it.
    pub async fn claim_tenant(
        &self,
        tenant: String,
        author_fp: String,
        account_id: String,
        limits: (usize, i64),
    ) -> Result<Claim> {
        let (max_tenants, now) = limits;
        self.call(move |conn| {
            let held: Option<(String, Option<String>)> = conn
                .query_row(
                    "SELECT author_fp, account_id FROM tenants WHERE tenant=?1",
                    params![tenant],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .ok();
            match held {
                Some(existing) => rebind(conn, &tenant, (&author_fp, &account_id), existing),
                None => grant(conn, &tenant, (&author_fp, &account_id), (max_tenants, now)),
            }
        })
        .await
    }
}

/// Settle a claim on a name that already exists.
///
/// The same key refreshing its own contract is idempotent. The owning ACCOUNT presenting a
/// different key rebinds the name to it. Anyone else is refused, so a name still cannot be
/// stolen — the widening is strictly "the owner may re-key", never "a stranger may take".
fn rebind(
    conn: &rusqlite::Connection,
    tenant: &str,
    claimant: (&str, &str),
    held: (String, Option<String>),
) -> Result<Claim> {
    let (author_fp, account_id) = claimant;
    let (held_fp, held_account) = held;
    if held_fp == author_fp {
        return Ok(Claim::Granted);
    }
    if held_account.as_deref() != Some(account_id) {
        return Ok(Claim::Taken);
    }
    conn.execute(
        "UPDATE tenants SET author_fp=?2 WHERE tenant=?1",
        params![tenant, author_fp],
    )
    .map_err(|e| Error::Internal(e.into()))?;
    Ok(Claim::Granted)
}

/// Insert a fresh claim once the account's quota allows another name.
fn grant(
    conn: &rusqlite::Connection,
    tenant: &str,
    claimant: (&str, &str),
    limits: (usize, i64),
) -> Result<Claim> {
    let (author_fp, account_id) = claimant;
    let (max_tenants, now) = limits;
    let held: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM tenants WHERE account_id=?1",
            params![account_id],
            |row| row.get(0),
        )
        .map_err(|e| Error::Internal(e.into()))?;
    if held as usize >= max_tenants {
        return Ok(Claim::QuotaExceeded);
    }
    conn.execute(
        "INSERT INTO tenants(tenant, author_fp, account_id, created_at) VALUES(?1,?2,?3,?4)",
        params![tenant, author_fp, account_id, now],
    )
    .map_err(|e| Error::Internal(e.into()))?;
    Ok(Claim::Granted)
}
