/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   teams.rs                                             :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Team rows and team membership.
//!
//! The rule that a team member must already belong to the organization is enforced twice
//! on purpose: as a composite foreign key in the schema, and as an explicit check here so
//! the caller gets an error that says what to do. The foreign key is the guarantee; the
//! check is the message.

use super::{is_constraint_violation, Store};
use crate::error::{Error, Result};
use crate::rbac::TeamRole;
use rusqlite::params;

/// A new team.
pub struct NewTeam {
    pub id: String,
    pub org_id: String,
    pub slug: String,
    pub name: String,
}

/// A team as the API reports it.
pub struct Team {
    pub id: String,
    pub slug: String,
    pub name: String,
}

/// An account being placed in a team.
pub struct NewTeamMember {
    pub team_id: String,
    pub org_id: String,
    pub account_id: String,
    pub role: TeamRole,
}

impl Store {
    /// Create a team within an organization.
    pub async fn create_team(&self, new: NewTeam) -> Result<()> {
        let now = vault42_contract::signing::now_unix();
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO teams(id, org_id, slug, name, created_at) VALUES(?1,?2,?3,?4,?5)",
                params![new.id, new.org_id, new.slug, new.name, now],
            )
            .map_err(|error| {
                if is_constraint_violation(&error) {
                    Error::Conflict("team slug already taken in this organization".into())
                } else {
                    Error::Internal(error.into())
                }
            })?;
            Ok(())
        })
        .await
    }

    /// Resolve a team reference (id or slug) within an organization to its id.
    pub async fn resolve_team(&self, org_id: String, reference: String) -> Result<Option<String>> {
        self.call(move |conn| {
            let found = conn.query_row(
                "SELECT id FROM teams WHERE org_id=?1 AND (id=?2 OR slug=?2)",
                params![org_id, reference],
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

    /// Every team in an organization, oldest first.
    pub async fn list_teams(&self, org_id: String) -> Result<Vec<Team>> {
        self.call(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, slug, name FROM teams WHERE org_id=?1
                      ORDER BY created_at, slug",
                )
                .map_err(|e| Error::Internal(e.into()))?;
            let rows = stmt
                .query_map(params![org_id], |row| {
                    Ok(Team {
                        id: row.get(0)?,
                        slug: row.get(1)?,
                        name: row.get(2)?,
                    })
                })
                .map_err(|e| Error::Internal(e.into()))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|e| Error::Internal(e.into()))
        })
        .await
    }

    /// Place an account in a team, updating its role if already present.
    ///
    /// Refuses with a message when the account does not belong to the organization; the
    /// composite foreign key would refuse it anyway, but with no explanation.
    pub async fn add_team_member(&self, add: NewTeamMember) -> Result<()> {
        let now = vault42_contract::signing::now_unix();
        self.call(move |conn| {
            super::require_org_membership(conn, &add.org_id, &add.account_id)?;
            conn.execute(
                "INSERT INTO team_members(team_id, org_id, account_id, team_role, created_at)
                 VALUES(?1,?2,?3,?4,?5)
                 ON CONFLICT(team_id, account_id) DO UPDATE SET team_role=excluded.team_role",
                params![
                    add.team_id,
                    add.org_id,
                    add.account_id,
                    add.role.as_str(),
                    now
                ],
            )
            .map_err(|e| Error::Internal(e.into()))?;
            Ok(())
        })
        .await
    }
}
