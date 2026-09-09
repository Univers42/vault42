/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   groups.rs                                            :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Project groups.
//!
//! A group is a project-scoped bag of accounts, used to hand a grant to several people at
//! once. Membership requires belonging to the project's organization, and since M6 the table
//! carries `org_id` so a composite foreign key onto `org_members` enforces that rule in both
//! directions: an outsider cannot be added, and a member removed from the organization has
//! their group memberships cascaded away rather than left behind for a grant to reach.

use super::{is_constraint_violation, Store};
use crate::error::{Error, Result};
use rusqlite::params;

/// A new group.
pub struct NewGroup {
    pub id: String,
    pub project_id: String,
    pub name: String,
}

impl Store {
    /// Create a group in a project.
    pub async fn create_group(&self, new: NewGroup) -> Result<()> {
        let now = vault42_contract::signing::now_unix();
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO groups(id, project_id, name, created_at) VALUES(?1,?2,?3,?4)",
                params![new.id, new.project_id, new.name, now],
            )
            .map_err(|e| Error::Internal(e.into()))?;
            Ok(())
        })
        .await
    }

    /// Resolve a group id and return the project and organization it belongs to.
    pub async fn resolve_group(&self, group_id: String) -> Result<Option<(String, String)>> {
        self.call(move |conn| {
            let found = conn.query_row(
                "SELECT g.project_id, p.org_id FROM groups g
                   JOIN projects p ON p.id = g.project_id
                  WHERE g.id=?1",
                params![group_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            );
            match found {
                Ok(pair) => Ok(Some(pair)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(error) => Err(Error::Internal(error.into())),
            }
        })
        .await
    }

    /// Add an organization member to a group.
    pub async fn add_group_member(
        &self,
        group_id: String,
        org_id: String,
        account_id: String,
    ) -> Result<()> {
        let now = vault42_contract::signing::now_unix();
        self.call(move |conn| {
            super::require_org_membership(conn, &org_id, &account_id)?;
            conn.execute(
                "INSERT OR IGNORE INTO group_members(group_id, org_id, account_id, created_at)
                 VALUES(?1,?2,?3,?4)",
                params![group_id, org_id, account_id, now],
            )
            .map_err(|error| {
                if is_constraint_violation(&error) {
                    Error::NotFound
                } else {
                    Error::Internal(error.into())
                }
            })?;
            Ok(())
        })
        .await
    }
}
