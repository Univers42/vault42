/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   secondfactor.rs                                      :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Storage for one-time codes and escrowed keystores.
//!
//! Every rule that makes a six-digit code safe is enforced in one statement here rather than
//! spread across a handler: a code is consumed as it is verified, its attempt count rises even
//! on a wrong guess, and expiry is compared in the same query. Reading then writing would let
//! two concurrent submissions each see an unconsumed code and both succeed.

use super::Store;
use crate::error::{Error, Result};
use rusqlite::params;

/// A code to store, replacing whatever that address had before.
pub struct NewCode {
    pub email: String,
    pub code_hash: String,
    pub expires_at: i64,
}

/// Why a submitted code was not accepted. All of these are one message to the caller — the
/// difference matters for the log and the test, never for the response.
#[derive(Debug, PartialEq, Eq)]
pub enum CodeRejection {
    NoCode,
    Expired,
    AlreadyUsed,
    TooManyAttempts,
    Wrong,
}

impl Store {
    /// Store a fresh code for an address, replacing any code it already had.
    ///
    /// Replacing rather than appending is what keeps the guessing bound meaningful: a hundred
    /// requests must not become a hundred simultaneous chances.
    pub async fn put_code(&self, new: NewCode) -> Result<()> {
        let now = vault42_contract::signing::now_unix();
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO otp_codes(email, code_hash, created_at, expires_at, consumed_at,
                                       attempts)
                 VALUES(?1,?2,?3,?4,NULL,0)
                 ON CONFLICT(email) DO UPDATE SET
                   code_hash=excluded.code_hash, created_at=excluded.created_at,
                   expires_at=excluded.expires_at, consumed_at=NULL, attempts=0",
                params![new.email, new.code_hash, now, new.expires_at],
            )
            .map_err(|e| Error::Internal(e.into()))?;
            Ok(())
        })
        .await
    }

    /// Spend one attempt against the live code for `email`, consuming it if `verify` accepts.
    ///
    /// One transaction, and the attempt is recorded before the answer is known, so a wrong guess
    /// costs the guesser whether or not they see the result. `verify` receives the stored digest
    /// and decides — the comparison stays in `otp.rs` where it can be constant-time, and the
    /// database work stays here where it can be atomic.
    pub async fn spend_attempt<F>(
        &self,
        email: String,
        verify: F,
    ) -> Result<std::result::Result<(), CodeRejection>>
    where
        F: FnOnce(&str) -> bool + Send + 'static,
    {
        let now = vault42_contract::signing::now_unix();
        self.call(move |conn| {
            let tx = conn.transaction().map_err(|e| Error::Internal(e.into()))?;
            let outcome = judge(&tx, &email, now, verify)?;
            tx.commit().map_err(|e| Error::Internal(e.into()))?;
            Ok(outcome)
        })
        .await
    }

    /// Store or replace an escrowed keystore blob for an address.
    pub async fn put_escrow(&self, email: String, blob: String) -> Result<()> {
        let now = vault42_contract::signing::now_unix();
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO escrow(email, blob, updated_at) VALUES(?1,?2,?3)
                 ON CONFLICT(email) DO UPDATE SET blob=excluded.blob,
                                                  updated_at=excluded.updated_at",
                params![email, blob, now],
            )
            .map_err(|e| Error::Internal(e.into()))?;
            Ok(())
        })
        .await
    }

    /// Fetch an escrowed keystore blob, or `None` when that address has none.
    pub async fn escrow_blob(&self, email: String) -> Result<Option<String>> {
        self.call(move |conn| {
            let found = conn.query_row(
                "SELECT blob FROM escrow WHERE email=?1",
                params![email],
                |row| row.get::<_, String>(0),
            );
            match found {
                Ok(blob) => Ok(Some(blob)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(error) => Err(Error::Internal(error.into())),
            }
        })
        .await
    }
}

/// Decide one submission inside an open transaction: load the row, charge the attempt, and
/// consume the code only on a correct guess.
fn judge<F>(
    conn: &rusqlite::Connection,
    email: &str,
    now: i64,
    verify: F,
) -> Result<std::result::Result<(), CodeRejection>>
where
    F: FnOnce(&str) -> bool,
{
    let row = conn.query_row(
        "SELECT code_hash, expires_at, consumed_at, attempts FROM otp_codes WHERE email=?1",
        params![email],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        },
    );
    let (hash, expires_at, consumed_at, attempts) = match row {
        Ok(found) => found,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(Err(CodeRejection::NoCode)),
        Err(error) => return Err(Error::Internal(error.into())),
    };
    if let Some(refusal) = unusable(expires_at, consumed_at, attempts, now) {
        return Ok(Err(refusal));
    }
    charge_attempt(conn, email)?;
    if !verify(&hash) {
        return Ok(Err(CodeRejection::Wrong));
    }
    consume(conn, email, now)?;
    Ok(Ok(()))
}

/// Why this code cannot be tried at all, if so.
fn unusable(
    expires_at: i64,
    consumed_at: Option<i64>,
    attempts: i64,
    now: i64,
) -> Option<CodeRejection> {
    if consumed_at.is_some() {
        return Some(CodeRejection::AlreadyUsed);
    }
    if expires_at <= now {
        return Some(CodeRejection::Expired);
    }
    if attempts >= crate::otp::MAX_ATTEMPTS {
        return Some(CodeRejection::TooManyAttempts);
    }
    None
}

/// Record that an attempt was spent, before the guess is judged.
fn charge_attempt(conn: &rusqlite::Connection, email: &str) -> Result<()> {
    conn.execute(
        "UPDATE otp_codes SET attempts = attempts + 1 WHERE email=?1",
        params![email],
    )
    .map_err(|e| Error::Internal(e.into()))?;
    Ok(())
}

/// Mark the code used, so a correct code works exactly once.
fn consume(conn: &rusqlite::Connection, email: &str, now: i64) -> Result<()> {
    conn.execute(
        "UPDATE otp_codes SET consumed_at=?2 WHERE email=?1",
        params![email, now],
    )
    .map_err(|e| Error::Internal(e.into()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A used code is refused before anything else is considered, so a correct code cannot be
    /// replayed even inside its validity window.
    #[test]
    fn a_consumed_code_is_refused_first() {
        assert_eq!(
            unusable(i64::MAX, Some(1), 0, 100),
            Some(CodeRejection::AlreadyUsed)
        );
    }

    /// Expiry is checked before the attempt count, so an expired code does not report the
    /// misleading "too many attempts".
    #[test]
    fn expiry_is_reported_as_expiry() {
        assert_eq!(unusable(100, None, 99, 100), Some(CodeRejection::Expired));
        assert_eq!(unusable(99, None, 0, 100), Some(CodeRejection::Expired));
    }

    /// The attempt bound is what makes six digits survivable, and it is inclusive.
    #[test]
    fn the_attempt_bound_closes_the_code() {
        let bound = crate::otp::MAX_ATTEMPTS;
        assert_eq!(
            unusable(i64::MAX, None, bound, 1),
            Some(CodeRejection::TooManyAttempts)
        );
        assert_eq!(unusable(i64::MAX, None, bound - 1, 1), None);
    }

    /// A live, unused, unexhausted code is usable.
    #[test]
    fn a_live_code_is_usable() {
        assert_eq!(unusable(i64::MAX, None, 0, 100), None);
    }
}
