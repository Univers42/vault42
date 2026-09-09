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

//! Project grants and the scope-key wraps that fulfil them.
//!
//! A grant says who may act on a project, and at what level. `env_id` NULL means the grant
//! is project-wide and by contract applies to every environment in the project; the client
//! already relies on that, so it is not a shortcut.
//!
//! `missing` is the operational half: the authorized member set minus those who already hold
//! a scope-key wrap for the environment and epoch being asked about. A wrap is meaningful
//! only against that pair, because the scope key it wraps belongs to one environment and is
//! replaced at every rotation. Answering `missing` without both would report a member as
//! provisioned in an environment they cannot read, or at an epoch that no longer exists.
//!
//! `missing` is a provisioning worklist and nothing more. It is deliberately NOT the
//! authorized-member set: the two coincide only until the first member is provisioned, and a
//! caller that needs everyone the grant authorizes — rotation does — must read `members`.

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
pub struct GrantRow {
    pub id: String,
    pub env_id: Option<String>,
}

/// The environment scope a wrap is bound to. A scope key belongs to one environment and is
/// replaced at each rotation, so a wrap without both coordinates describes nothing.
pub struct WrapScope {
    pub env_id: String,
    pub epoch: i64,
}

/// Who a grant authorizes, and which of them still need a wrap for one `WrapScope`.
pub struct GrantFulfilment {
    pub members: Vec<String>,
    pub missing: Vec<String>,
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
                    "SELECT id, env_id FROM grants
                      WHERE project_id=?1 AND revoked_at IS NULL ORDER BY created_at, id",
                )
                .map_err(|e| Error::Internal(e.into()))?;
            let rows = stmt
                .query_map(params![project_id], |row| {
                    Ok(GrantRow {
                        id: row.get(0)?,
                        env_id: row.get(1)?,
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

    /// Everyone a grant authorizes, plus those of them still lacking a wrap for `scope`.
    ///
    /// Both halves come from one connection so they describe the same instant: a caller that
    /// read them separately could re-wrap against a member list that changed in between.
    pub async fn grant_fulfilment(
        &self,
        grant_id: String,
        scope: WrapScope,
    ) -> Result<GrantFulfilment> {
        self.call(move |conn| {
            check_wrap_env(conn, &grant_id, &scope.env_id)?;
            let members = authorized_members(conn, &grant_id)?;
            let mut missing = Vec::new();
            for account_id in &members {
                if !has_wrap(conn, &grant_id, account_id, &scope)? {
                    missing.push(account_id.clone());
                }
            }
            Ok(GrantFulfilment { members, missing })
        })
        .await
    }

    /// Record that a scope-key wrap now exists for an authorized member at one `WrapScope`.
    ///
    /// Refuses an account the grant does not authorize: `missing` is computed against the
    /// same set, so admitting an outsider here would make the bookkeeping describe access
    /// nobody granted. Refuses likewise an environment the grant does not cover.
    pub async fn add_grant_wrap(
        &self,
        grant_id: String,
        account_id: String,
        scope: WrapScope,
    ) -> Result<()> {
        let now = vault42_contract::signing::now_unix();
        self.call(move |conn| {
            check_wrap_env(conn, &grant_id, &scope.env_id)?;
            let authorized = authorized_members(conn, &grant_id)?;
            if !authorized.iter().any(|member| member == &account_id) {
                return Err(Error::BadRequest(
                    "account is not authorized by this grant".into(),
                ));
            }
            conn.execute(
                "INSERT OR IGNORE INTO
                   grant_wraps(grant_id, account_id, env_id, epoch, created_at)
                 VALUES(?1,?2,?3,?4,?5)",
                params![grant_id, account_id, scope.env_id, scope.epoch, now],
            )
            .map_err(|e| Error::Internal(e.into()))?;
            Ok(())
        })
        .await
    }
}

/// Refuse an environment the grant does not cover.
///
/// The environment must belong to the grant's project, and an env-scoped grant covers only
/// its own environment. Without this a wrap recorded against an unrelated environment would
/// make that environment's `missing` list omit a member who was never provisioned there.
fn check_wrap_env(conn: &rusqlite::Connection, grant_id: &str, env_id: &str) -> Result<()> {
    let scoped_to: Option<String> = conn
        .query_row(
            "SELECT g.env_id FROM grants g
               JOIN environments e ON e.project_id = g.project_id
              WHERE g.id=?1 AND g.revoked_at IS NULL AND e.id=?2",
            params![grant_id, env_id],
            |row| row.get(0),
        )
        .map_err(|_| Error::NotFound)?;
    match scoped_to {
        Some(only) if only != env_id => Err(Error::NotFound),
        _ => Ok(()),
    }
}

/// Every account the grant authorizes: the user itself, or the team's current membership.
fn authorized_members(conn: &rusqlite::Connection, grant_id: &str) -> Result<Vec<String>> {
    let (kind, grantee): (String, String) = conn
        .query_row(
            "SELECT grantee_kind, grantee_id FROM grants WHERE id=?1 AND revoked_at IS NULL",
            params![grant_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| Error::NotFound)?;
    if kind == "user" {
        return Ok(vec![grantee]);
    }
    let mut stmt = conn
        .prepare("SELECT account_id FROM team_members WHERE team_id=?1 ORDER BY account_id")
        .map_err(|e| Error::Internal(e.into()))?;
    let rows = stmt
        .query_map(params![grantee], |row| row.get::<_, String>(0))
        .map_err(|e| Error::Internal(e.into()))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| Error::Internal(e.into()))
}

/// True when a wrap already exists for this grant and account at `scope`.
fn has_wrap(
    conn: &rusqlite::Connection,
    grant_id: &str,
    account_id: &str,
    scope: &WrapScope,
) -> Result<bool> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM grant_wraps
              WHERE grant_id=?1 AND account_id=?2 AND env_id=?3 AND epoch=?4",
            params![grant_id, account_id, scope.env_id, scope.epoch],
            |row| row.get(0),
        )
        .map_err(|e| Error::Internal(e.into()))?;
    Ok(count > 0)
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
