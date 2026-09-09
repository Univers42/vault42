/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   sessions.rs                                          :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Session rows.
//!
//! Only a BLAKE3 hash of the bearer token is stored, so a database leak yields nothing
//! replayable as a login. Every lookup re-checks expiry, revocation, and account status
//! in the same statement, so a disabled account cannot keep using a live token.

use super::Store;
use crate::auth::Principal;
use crate::error::{Error, Result};
use rusqlite::params;

impl Store {
    /// Record a freshly minted session.
    pub async fn insert_session(
        &self,
        token_hash: String,
        account_id: String,
        issued_at: i64,
        expires_at: i64,
    ) -> Result<()> {
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO sessions(token_hash, account_id, issued_at, expires_at)
                 VALUES(?1,?2,?3,?4)",
                params![token_hash, account_id, issued_at, expires_at],
            )
            .map_err(|e| Error::Internal(e.into()))?;
            Ok(())
        })
        .await
    }

    /// Resolve a token hash to its principal, or `None` if it is not usable now.
    ///
    /// "Not usable" covers unknown, expired, revoked, and belonging to a disabled
    /// account. The caller cannot distinguish these, which is intentional.
    pub async fn session_principal(
        &self,
        token_hash: String,
        now: i64,
    ) -> Result<Option<Principal>> {
        self.call(move |conn| {
            let found = conn.query_row(
                "SELECT a.id, a.email, a.mfa_required
                   FROM sessions s JOIN accounts a ON a.id = s.account_id
                  WHERE s.token_hash = ?1
                    AND s.revoked_at IS NULL
                    AND s.expires_at > ?2
                    AND a.status = 'active'",
                params![&token_hash, now],
                |row| {
                    Ok(Principal {
                        account_id: row.get(0)?,
                        email: row.get(1)?,
                        mfa_required: row.get::<_, i64>(2)? != 0,
                        token_hash: token_hash.clone(),
                    })
                },
            );
            match found {
                Ok(principal) => Ok(Some(principal)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(error) => Err(Error::Internal(error.into())),
            }
        })
        .await
    }

    /// Revoke one session. Idempotent: revoking an already-revoked token is not an error.
    pub async fn revoke_session(&self, token_hash: String, now: i64) -> Result<()> {
        self.call(move |conn| {
            conn.execute(
                "UPDATE sessions SET revoked_at=?2 WHERE token_hash=?1 AND revoked_at IS NULL",
                params![token_hash, now],
            )
            .map_err(|e| Error::Internal(e.into()))?;
            Ok(())
        })
        .await
    }

    /// Revoke every live session for an account, used when its password changes.
    pub async fn revoke_account_sessions(&self, account_id: String, now: i64) -> Result<()> {
        self.call(move |conn| {
            // ponytail: expired rows are left in place — add a periodic prune if the
            // sessions table ever grows enough to matter.
            conn.execute(
                "UPDATE sessions SET revoked_at=?2 WHERE account_id=?1 AND revoked_at IS NULL",
                params![account_id, now],
            )
            .map_err(|e| Error::Internal(e.into()))?;
            Ok(())
        })
        .await
    }
}
