/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   grants.rs                                            :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */
//! Project grants: who may act on a project, and at what level.
//!
//! `env_id` NULL means the grant is project-wide and by contract applies to every environment
//! in the project; the client already relies on that, so it is not a shortcut. The wrap
//! bookkeeping that fulfils a grant lives in `wraps.rs`.

use super::{is_constraint_violation, Store};
use crate::error::{Error, Result};
use rusqlite::params;

/// A grant to create.
pub struct NewGrant {
    pub id: String,
    pub project_id: String,
    pub grantee_kind: String,
    pub grantee_id: String,
    pub project_role: String,
    pub env_id: Option<String>,
    pub granted_by: String,
}

/// A grant as the API reports it.
///
/// `project_role` is here because a client cannot mint a scope-key wrap without it: the wrap
/// carries the role that decides whether its holder may write, and the only place the role is
/// recorded is this grant. Omitting it from the listing made every wrap a Reader — a team granted
/// write could not write, and no error said so anywhere.
pub struct GrantRow {
    pub id: String,
    pub env_id: Option<String>,
    pub project_role: String,
}

impl Store {
    /// Create a grant, refusing a grantee or environment that does not fit the project.
    pub async fn create_grant(&self, new: NewGrant) -> Result<()> {
        let now = vault42_contract::signing::now_unix();
        self.call(move |conn| {
            check_grantee(conn, &new)?;
            check_env(conn, &new)?;
            conn.execute(
                "INSERT INTO grants(id, project_id, grantee_kind, grantee_id, project_role,
                                    env_id, granted_by, created_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    new.id,
                    new.project_id,
                    new.grantee_kind,
                    new.grantee_id,
                    new.project_role,
                    new.env_id,
                    new.granted_by,
                    now
                ],
            )
            .map_err(|error| {
                if is_constraint_violation(&error) {
                    Error::BadRequest("grant references something that does not exist".into())
                } else {
                    Error::Internal(error.into())
                }
            })?;
            Ok(())
        })
        .await
    }

    /// Every live grant on a project.
    pub async fn list_grants(&self, project_id: String) -> Result<Vec<GrantRow>> {
        self.call(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, env_id, project_role FROM grants
                      WHERE project_id=?1 AND revoked_at IS NULL ORDER BY created_at, id",
                )
                .map_err(|e| Error::Internal(e.into()))?;
            let rows = stmt
                .query_map(params![project_id], |row| {
                    Ok(GrantRow {
                        id: row.get(0)?,
                        env_id: row.get(1)?,
                        project_role: row.get(2)?,
                    })
                })
                .map_err(|e| Error::Internal(e.into()))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|e| Error::Internal(e.into()))
        })
        .await
    }

    /// The grant's project, so a caller can authorize against the owning organization.
    pub async fn grant_project(&self, grant_id: String) -> Result<Option<String>> {
        self.call(move |conn| {
            let found = conn.query_row(
                "SELECT project_id FROM grants WHERE id=?1 AND revoked_at IS NULL",
                params![grant_id],
                |row| row.get::<_, String>(0),
            );
            match found {
                Ok(project) => Ok(Some(project)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(error) => Err(Error::Internal(error.into())),
            }
        })
        .await
    }
}

/// Refuse a grantee that does not belong to the project's organization.
fn check_grantee(conn: &rusqlite::Connection, new: &NewGrant) -> Result<()> {
    let org_id: String = conn
        .query_row(
            "SELECT org_id FROM projects WHERE id=?1",
            params![new.project_id],
            |row| row.get(0),
        )
        .map_err(|_| Error::NotFound)?;
    let sql = if new.grantee_kind == "user" {
        "SELECT COUNT(*) FROM org_members WHERE org_id=?1 AND account_id=?2"
    } else {
        "SELECT COUNT(*) FROM teams WHERE org_id=?1 AND id=?2"
    };
    let count: i64 = conn
        .query_row(sql, params![org_id, new.grantee_id], |row| row.get(0))
        .map_err(|e| Error::Internal(e.into()))?;
    if count == 0 {
        return Err(Error::BadRequest(format!(
            "{} {:?} does not belong to this project's organization",
            new.grantee_kind, new.grantee_id
        )));
    }
    Ok(())
}

/// Refuse an environment that belongs to a different project.
fn check_env(conn: &rusqlite::Connection, new: &NewGrant) -> Result<()> {
    let Some(env_id) = &new.env_id else {
        return Ok(());
    };
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM environments WHERE id=?1 AND project_id=?2",
            params![env_id, new.project_id],
            |row| row.get(0),
        )
        .map_err(|e| Error::Internal(e.into()))?;
    if count == 0 {
        return Err(Error::BadRequest(
            "env_id does not belong to this project".into(),
        ));
    }
    Ok(())
}
