/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   accounts.rs                                          :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Account rows: create, look up, and change a password hash.
//!
//! The stored value is an Argon2id PHC string, never a password. Lookup is by the
//! normalized (lowercased) email so one address cannot be registered twice in different
//! cases, which the `UNIQUE` constraint also enforces.

use super::{is_constraint_violation, Store};
use crate::error::{Error, Result};
use rusqlite::params;

/// The columns a caller reads back for an account.
///
/// Still a projection — `created_at` has no reader — but `email` and `mfa_required` now do:
/// the second-factor check needs the address a proof must bind and the flag that decides
/// whether one is demanded.
#[derive(Clone)]
pub struct Account {
    pub id: String,
    pub email: String,
    pub password_hash: String,
    pub status: String,
    pub mfa_required: bool,
}

impl Store {
    /// Insert a new account. Returns `Conflict` when the email is already registered.
    pub async fn create_account(
        &self,
        id: String,
        email: String,
        password_hash: String,
        now: i64,
    ) -> Result<()> {
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO accounts(id, email, password_hash, created_at)
                 VALUES(?1,?2,?3,?4)",
                params![id, email, password_hash, now],
            )
            .map_err(|error| {
                if is_constraint_violation(&error) {
                    Error::Conflict("email already registered".into())
                } else {
                    Error::Internal(error.into())
                }
            })?;
            Ok(())
        })
        .await
    }

    /// Fetch an account by its normalized email.
    pub async fn account_by_email(&self, email: String) -> Result<Option<Account>> {
        self.call(move |conn| one(conn, "email", &email)).await
    }

    /// Fetch an account by id.
    pub async fn account_by_id(&self, id: String) -> Result<Option<Account>> {
        self.call(move |conn| one(conn, "id", &id)).await
    }

    /// Turn the second-factor requirement on or off for an account.
    pub async fn set_mfa_required(&self, id: String, required: bool) -> Result<()> {
        self.call(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE accounts SET mfa_required=?2 WHERE id=?1",
                    params![id, i64::from(required)],
                )
                .map_err(|e| Error::Internal(e.into()))?;
            if changed == 0 {
                return Err(Error::NotFound);
            }
            Ok(())
        })
        .await
    }

    /// Replace an account's password hash.
    pub async fn set_password_hash(&self, id: String, password_hash: String) -> Result<()> {
        self.call(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE accounts SET password_hash=?2 WHERE id=?1",
                    params![id, password_hash],
                )
                .map_err(|e| Error::Internal(e.into()))?;
            if changed == 0 {
                return Err(Error::NotFound);
            }
            Ok(())
        })
        .await
    }
}

/// Fetch one account by an indexed column (`id` or `email`).
///
/// The column name is supplied by this module only, never by a request, so it is
/// interpolated; the value is always bound.
fn one(conn: &rusqlite::Connection, column: &str, value: &str) -> Result<Option<Account>> {
    let sql = format!(
        "SELECT id, email, password_hash, status, mfa_required FROM accounts WHERE {column}=?1"
    );
    let found = conn.query_row(&sql, params![value], |row| {
        Ok(Account {
            id: row.get(0)?,
            email: row.get(1)?,
            password_hash: row.get(2)?,
            status: row.get(3)?,
            mfa_required: row.get::<_, i64>(4)? == 1,
        })
    });
    match found {
        Ok(account) => Ok(Some(account)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(error) => Err(Error::Internal(error.into())),
    }
}
