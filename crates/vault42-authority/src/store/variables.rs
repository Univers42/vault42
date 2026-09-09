/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   variables.rs                                         :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Configuration variables at three levels of scope.
//!
//! `value` is opaque here and stays opaque. The authority never parses it, never validates its
//! shape, and holds no key that could open it: a secret's value is a blob the client sealed
//! against the environment's scope key. That is the zero-knowledge boundary as a storage rule,
//! and it is why `is_secret` is only a hint to the client rather than something acted on here.
//!
//! Resolution folds environment over project over organization in one query, so precedence is
//! a property of the data rather than of whichever caller happens to assemble it.

use super::Store;
use crate::error::{Error, Result};
use rusqlite::params;

/// A variable to write.
pub struct UpsertVariable {
    pub scope_kind: String,
    pub scope_id: String,
    pub key: String,
    pub value: String,
    pub is_secret: bool,
    pub updated_by: String,
}

/// A variable as the API reports it. `scope_kind` says which level supplied it.
pub struct Variable {
    pub key: String,
    pub value: String,
    pub is_secret: bool,
    pub scope_kind: String,
    pub updated_at: i64,
}

/// The three scopes a resolution folds together.
pub struct ResolveScopes {
    pub org_id: String,
    pub project_id: String,
    pub env_id: String,
}

impl Store {
    /// Create or replace a variable at one scope.
    pub async fn put_variable(&self, new: UpsertVariable) -> Result<()> {
        let now = vault42_contract::signing::now_unix();
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO variables(scope_kind, scope_id, key, value, is_secret,
                                       updated_at, updated_by)
                 VALUES(?1,?2,?3,?4,?5,?6,?7)
                 ON CONFLICT(scope_kind, scope_id, key) DO UPDATE SET
                   value=excluded.value,
                   is_secret=excluded.is_secret,
                   updated_at=excluded.updated_at,
                   updated_by=excluded.updated_by",
                params![
                    new.scope_kind,
                    new.scope_id,
                    new.key,
                    new.value,
                    new.is_secret as i64,
                    now,
                    new.updated_by
                ],
            )
            .map_err(|e| Error::Internal(e.into()))?;
            Ok(())
        })
        .await
    }

    /// Every variable set directly at one scope, without folding.
    pub async fn list_variables(
        &self,
        scope_kind: String,
        scope_id: String,
    ) -> Result<Vec<Variable>> {
        self.call(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT key, value, is_secret, scope_kind, updated_at FROM variables
                      WHERE scope_kind=?1 AND scope_id=?2 ORDER BY key",
                )
                .map_err(|e| Error::Internal(e.into()))?;
            let rows = stmt
                .query_map(params![scope_kind, scope_id], read_variable)
                .map_err(|e| Error::Internal(e.into()))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|e| Error::Internal(e.into()))
        })
        .await
    }

    /// Remove a variable from one scope. Absent is not an error.
    pub async fn delete_variable(
        &self,
        scope_kind: String,
        scope_id: String,
        key: String,
    ) -> Result<()> {
        self.call(move |conn| {
            conn.execute(
                "DELETE FROM variables WHERE scope_kind=?1 AND scope_id=?2 AND key=?3",
                params![scope_kind, scope_id, key],
            )
            .map_err(|e| Error::Internal(e.into()))?;
            Ok(())
        })
        .await
    }

    /// The effective variable set for an environment: environment over project over org.
    ///
    /// A single window-function query, so a key set at two levels resolves deterministically
    /// and the answer names which level won.
    pub async fn resolve_variables(&self, scopes: ResolveScopes) -> Result<Vec<Variable>> {
        self.call(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT key, value, is_secret, scope_kind, updated_at FROM (
                       SELECT key, value, is_secret, scope_kind, updated_at,
                              ROW_NUMBER() OVER (PARTITION BY key ORDER BY rank) AS rn
                         FROM (
                           SELECT key, value, is_secret, scope_kind, updated_at, 1 AS rank
                             FROM variables WHERE scope_kind='env' AND scope_id=?3
                           UNION ALL
                           SELECT key, value, is_secret, scope_kind, updated_at, 2 AS rank
                             FROM variables WHERE scope_kind='project' AND scope_id=?2
                           UNION ALL
                           SELECT key, value, is_secret, scope_kind, updated_at, 3 AS rank
                             FROM variables WHERE scope_kind='org' AND scope_id=?1
                         )
                     ) WHERE rn = 1 ORDER BY key",
                )
                .map_err(|e| Error::Internal(e.into()))?;
            let rows = stmt
                .query_map(
                    params![scopes.org_id, scopes.project_id, scopes.env_id],
                    read_variable,
                )
                .map_err(|e| Error::Internal(e.into()))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|e| Error::Internal(e.into()))
        })
        .await
    }
}

/// Map a row onto a `Variable`.
fn read_variable(row: &rusqlite::Row<'_>) -> rusqlite::Result<Variable> {
    Ok(Variable {
        key: row.get(0)?,
        value: row.get(1)?,
        is_secret: row.get::<_, i64>(2)? != 0,
        scope_kind: row.get(3)?,
        updated_at: row.get(4)?,
    })
}
