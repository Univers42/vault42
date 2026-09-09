/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   authz.rs                                             :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The effective-permission query.
//!
//! An organization role says who administers the organization. A grant says who may act on a
//! project, and this is where the two meet: the strongest role a caller holds on a given
//! project scope, whether granted directly or through a team.
//!
//! It is one query rather than a fetch-then-filter loop because the answer must reflect team
//! membership as it is right now. Caching it, or resolving it in two round trips, would let a
//! member removed from a team keep acting until something refreshed.

use super::Store;
use crate::error::{Error, Result};
use crate::rbac::ProjectRole;
use rusqlite::params;

impl Store {
    /// The strongest project role `account_id` holds over `env_id` within `project_id`.
    ///
    /// `env_id` of `None` asks about the project itself, which only a project-wide grant
    /// covers. A project-wide grant (`grants.env_id IS NULL`) also covers every environment,
    /// which is the contract the client already relies on.
    pub async fn effective_project_role(
        &self,
        project_id: String,
        account_id: String,
        env_id: Option<String>,
    ) -> Result<Option<ProjectRole>> {
        self.call(move |conn| {
            let mut best: Option<ProjectRole> = None;
            for role in granted_roles(conn, &project_id, &account_id, env_id.as_deref())? {
                let parsed = ProjectRole::parse(&role)?;
                if strength(parsed) > best.map_or(0, strength) {
                    best = Some(parsed);
                }
            }
            Ok(best)
        })
        .await
    }
}

/// Every project role granted to the account over this scope, directly or via a team.
fn granted_roles(
    conn: &rusqlite::Connection,
    project_id: &str,
    account_id: &str,
    env_id: Option<&str>,
) -> Result<Vec<String>> {
    let mut stmt = conn
        .prepare(
            "SELECT g.project_role FROM grants g
              WHERE g.project_id = ?1
                AND g.revoked_at IS NULL
                AND (g.env_id IS NULL OR g.env_id = ?3)
                AND (
                      (g.grantee_kind = 'user' AND g.grantee_id = ?2)
                   OR (g.grantee_kind = 'team' AND EXISTS (
                         SELECT 1 FROM team_members tm
                          WHERE tm.team_id = g.grantee_id AND tm.account_id = ?2))
                )",
        )
        .map_err(|e| Error::Internal(e.into()))?;
    let rows = stmt
        .query_map(params![project_id, account_id, env_id], |row| {
            row.get::<_, String>(0)
        })
        .map_err(|e| Error::Internal(e.into()))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| Error::Internal(e.into()))
}

/// Order the roles so the strongest wins when several grants apply.
fn strength(role: ProjectRole) -> u8 {
    match role {
        ProjectRole::Admin => 3,
        ProjectRole::Write => 2,
        ProjectRole::Read => 1,
    }
}
