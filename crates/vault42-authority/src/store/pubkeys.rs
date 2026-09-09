/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   pubkeys.rs                                           :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Member public keys, with their proof of possession stored verbatim.
//!
//! `pubkey_sig` is stored exactly as presented and echoed exactly as stored. It is a
//! signature over a canonically framed message that includes the account id, so any
//! re-encoding or normalization would invalidate it for every later verifier.

use super::{is_constraint_violation, Store};
use crate::error::{Error, Result};
use rusqlite::params;

/// A member's public keys as registered.
pub struct MemberPubkey {
    pub user_id: String,
    pub x25519_pub: String,
    pub ed25519_pub: String,
    pub v42_address: String,
    pub pubkey_sig: String,
}

impl Store {
    /// Register or replace the caller's own public keys for an organization.
    ///
    /// Replacing is allowed because a member may rotate their identity; the proof of
    /// possession is re-verified on every write, so a replacement cannot install a key the
    /// caller does not hold.
    pub async fn put_member_pubkey(&self, org_id: String, keys: MemberPubkey) -> Result<()> {
        let now = vault42_contract::signing::now_unix();
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO member_pubkeys(org_id, account_id, x25519_pub, ed25519_pub,
                                            v42_address, pubkey_sig, created_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7)
                 ON CONFLICT(org_id, account_id) DO UPDATE SET
                   x25519_pub=excluded.x25519_pub,
                   ed25519_pub=excluded.ed25519_pub,
                   v42_address=excluded.v42_address,
                   pubkey_sig=excluded.pubkey_sig",
                params![
                    org_id,
                    keys.user_id,
                    keys.x25519_pub,
                    keys.ed25519_pub,
                    keys.v42_address,
                    keys.pubkey_sig,
                    now
                ],
            )
            .map_err(|error| {
                if is_constraint_violation(&error) {
                    Error::BadRequest("not a member of this organization".into())
                } else {
                    Error::Internal(error.into())
                }
            })?;
            Ok(())
        })
        .await
    }

    /// Read a member's registered public keys.
    pub async fn member_pubkey(
        &self,
        org_id: String,
        account_id: String,
    ) -> Result<Option<MemberPubkey>> {
        self.call(move |conn| {
            let found = conn.query_row(
                "SELECT account_id, x25519_pub, ed25519_pub, v42_address, pubkey_sig
                   FROM member_pubkeys WHERE org_id=?1 AND account_id=?2",
                params![org_id, account_id],
                |row| {
                    Ok(MemberPubkey {
                        user_id: row.get(0)?,
                        x25519_pub: row.get(1)?,
                        ed25519_pub: row.get(2)?,
                        v42_address: row.get(3)?,
                        pubkey_sig: row.get(4)?,
                    })
                },
            );
            match found {
                Ok(keys) => Ok(Some(keys)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(error) => Err(Error::Internal(error.into())),
            }
        })
        .await
    }
}
