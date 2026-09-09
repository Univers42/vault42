/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   environments.rs                                      :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Environment rows and their published scope keys.
//!
//! `scope_pubkey` and `scope_epoch` are the bridge to the crypto: an administrator generates
//! a scope keyset client-side and publishes only its public half here, so the authority can
//! tell members which key to seal to without ever holding the secret. Rotation is an epoch
//! bump, and a member who receives no wrap at the new epoch loses access by absence.

use super::{is_constraint_violation, Store};
use crate::error::{Error, Result};
use rusqlite::params;

/// A new environment.
pub struct NewEnvironment {
    pub id: String,
    pub project_id: String,
    pub name: String,
}

/// An environment as the API reports it.
pub struct Environment {
    pub id: String,
    pub name: String,
    pub scope_pubkey: Option<String>,
    pub scope_epoch: i64,
}

impl Store {
    /// Create an environment in a project.
    pub async fn create_environment(&self, new: NewEnvironment) -> Result<()> {
        let now = vault42_contract::signing::now_unix();
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO environments(id, project_id, name, created_at) VALUES(?1,?2,?3,?4)",
                params![new.id, new.project_id, new.name, now],
            )
            .map_err(|error| {
                if is_constraint_violation(&error) {
                    Error::Conflict("environment name already used in this project".into())
                } else {
                    Error::Internal(error.into())
                }
            })?;
            Ok(())
        })
        .await
    }

    /// Every environment in a project, oldest first.
    pub async fn list_environments(&self, project_id: String) -> Result<Vec<Environment>> {
        self.call(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, name, scope_pubkey, scope_epoch FROM environments
                      WHERE project_id=?1 ORDER BY created_at, name",
                )
                .map_err(|e| Error::Internal(e.into()))?;
            let rows = stmt
                .query_map(params![project_id], read_environment)
                .map_err(|e| Error::Internal(e.into()))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|e| Error::Internal(e.into()))
        })
        .await
    }

    /// Resolve an environment reference (id or name) within a project to its id.
    pub async fn resolve_environment(
        &self,
        project_id: String,
        reference: String,
    ) -> Result<Option<String>> {
        self.call(move |conn| {
            let found = conn.query_row(
                "SELECT id FROM environments WHERE project_id=?1 AND (id=?2 OR name=?2)",
                params![project_id, reference],
                |row| row.get::<_, String>(0),
            );
            match found {
                Ok(id) => Ok(Some(id)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(error) => Err(Error::Internal(error.into())),
            }
        })
        .await
    }

    /// Publish or rotate an environment's scope public key, returning the updated row.
    ///
    /// Refuses an epoch that does not advance: accepting a lower epoch would let a stale
    /// client roll the environment back to a key that removed members still hold.
    pub async fn set_scope_key(
        &self,
        env_id: String,
        scope_pubkey: String,
        scope_epoch: i64,
    ) -> Result<Environment> {
        self.call(move |conn| {
            let current: i64 = conn
                .query_row(
                    "SELECT scope_epoch FROM environments WHERE id=?1",
                    params![env_id],
                    |row| row.get(0),
                )
                .map_err(|_| Error::NotFound)?;
            if scope_epoch <= current {
                return Err(Error::Conflict(format!(
                    "scope_epoch must advance; environment is at {current}"
                )));
            }
            conn.execute(
                "UPDATE environments SET scope_pubkey=?2, scope_epoch=?3 WHERE id=?1",
                params![env_id, scope_pubkey, scope_epoch],
            )
            .map_err(|e| Error::Internal(e.into()))?;
            conn.query_row(
                "SELECT id, name, scope_pubkey, scope_epoch FROM environments WHERE id=?1",
                params![env_id],
                read_environment,
            )
            .map_err(|e| Error::Internal(e.into()))
        })
        .await
    }
}

/// Map a row onto an `Environment`.
fn read_environment(row: &rusqlite::Row<'_>) -> rusqlite::Result<Environment> {
    Ok(Environment {
        id: row.get(0)?,
        name: row.get(1)?,
        scope_pubkey: row.get(2)?,
        scope_epoch: row.get(3)?,
    })
}
