/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   mod.rs                                               :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The authority's SQLite store.
//!
//! `max_size(1)` is deliberate, not a placeholder: it serializes every statement through
//! one connection, which is what makes read-then-write sequences atomic without explicit
//! locking. The audit chain and the "already a member" checks depend on that, and it is
//! the same discipline `vault42-server` uses. Foreign keys are ON so the referential
//! rules in the schema are enforced by the database rather than by handlers.

mod accounts;
mod authz;
mod environments;
mod grants;
mod groups;
mod invites;
mod migrate;
mod orgs;
mod projects;
mod pubkeys;
mod sessions;
mod teams;
mod tenants;
mod variables;

pub use environments::{Environment, NewEnvironment};
pub use grants::{NewGrant, WrapScope};
pub use groups::NewGroup;
pub use invites::{Acceptance, NewInvite};
pub use orgs::NewOrg;
pub use projects::NewProject;
pub use pubkeys::MemberPubkey;
pub use teams::{NewTeam, NewTeamMember};
pub use variables::{ResolveScopes, UpsertVariable, Variable};

use crate::error::{Error, Result};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

/// A clonable handle to the authority database.
#[derive(Clone)]
pub struct Store {
    pool: Pool<SqliteConnectionManager>,
}

impl Store {
    /// Open (creating if needed) the database at `path` and bring the schema up to date.
    pub fn open(path: &str, now: i64) -> anyhow::Result<Self> {
        let manager = SqliteConnectionManager::file(path).with_init(|conn| {
            conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA foreign_keys=ON;
                 PRAGMA busy_timeout=5000;",
            )
        });
        let pool = Pool::builder().max_size(1).build(manager)?;
        let mut conn = pool.get()?;
        migrate::run(&mut conn, now)?;
        Ok(Self { pool })
    }

    /// Run blocking database work off the async runtime, on the pooled connection.
    ///
    /// Every store method funnels through here so the `spawn_blocking` and pool-checkout
    /// handling exist once rather than in each query.
    pub(crate) async fn call<T, F>(&self, work: F) -> Result<T>
    where
        F: FnOnce(&mut rusqlite::Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let pool = self.pool.clone();
        let joined = tokio::task::spawn_blocking(move || {
            let mut conn = pool.get().map_err(|e| Error::Internal(e.into()))?;
            work(&mut conn)
        })
        .await;
        joined.map_err(|e| Error::Internal(e.into()))?
    }
}

/// True when a rusqlite error is a uniqueness or foreign-key violation.
///
/// Used to turn a race on a unique column into a 409 instead of a 500: two concurrent
/// signups for one email both pass the pre-check, and the database settles it.
pub(crate) fn is_constraint_violation(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(inner, _)
            if inner.code == rusqlite::ErrorCode::ConstraintViolation
    )
}
