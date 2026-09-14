/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   projects.rs                                          :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Project rows.
//!
//! A project id is a v4 UUID because 42ctl derives an environment's scope id as
//! `blake3(project_uuid_bytes ‖ env_name)[..16]`. A non-UUID project id therefore has no
//! derivable scope, which would break every env-secret operation silently.

use super::{is_constraint_violation, Store};
use crate::error::{Error, Result};
use rusqlite::params;

/// A new project.
pub struct NewProject {
    pub id: String,
    pub org_id: String,
    pub slug: String,
    pub name: String,
}

/// A project as the API reports it.
pub struct Project {
    pub id: String,
    pub slug: String,
    pub name: String,
}

impl Store {
    /// Create a project in an organization.
    pub async fn create_project(&self, new: NewProject) -> Result<()> {
        let now = vault42_contract::signing::now_unix();
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO projects(id, org_id, slug, name, created_at) VALUES(?1,?2,?3,?4,?5)",
                params![new.id, new.org_id, new.slug, new.name, now],
            )
            .map_err(|error| {
                if is_constraint_violation(&error) {
                    Error::Conflict("project slug already taken in this organization".into())
                } else {
                    Error::Internal(error.into())
                }
            })?;
            Ok(())
        })
        .await
    }

    /// Resolve a project reference (id or slug) within one organization to its id.
    ///
    /// A slug is unique only inside its organization (`UNIQUE (org_id, slug)`), so a lookup
    /// that is not scoped to one picks whichever organization's project comes first. That is
    /// what made every grant route answer 404 the moment a second organization created a
    /// project with the same slug — `api`, `web`, the names everybody chooses.
    pub async fn resolve_project_in_org(
        &self,
        org_id: String,
        reference: String,
    ) -> Result<Option<String>> {
        self.call(move |conn| {
            let found = conn.query_row(
                "SELECT id FROM projects WHERE org_id=?1 AND (id=?2 OR slug=?2)",
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

    /// Resolve a project reference (id or slug) among the organizations `account_id` belongs
    /// to, to `(project_id, org_id)`, for routes whose path names no organization.
    ///
    /// Looking only where the caller is a member keeps another organization's projects out of
    /// the answer, and out of the error too. A slug the caller holds in two organizations is
    /// refused rather than resolved to either: acting on the wrong organization's project is
    /// worse than asking for its id, which is unique.
    pub async fn resolve_member_project(
        &self,
        account_id: String,
        reference: String,
    ) -> Result<Option<(String, String)>> {
        self.call(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT p.id, p.org_id FROM projects p
                       JOIN org_members m ON m.org_id = p.org_id
                      WHERE m.account_id = ?1 AND (p.id = ?2 OR p.slug = ?2)
                      LIMIT 2",
                )
                .map_err(|e| Error::Internal(e.into()))?;
            let found = stmt
                .query_map(params![account_id, reference], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|e| Error::Internal(e.into()))?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|e| Error::Internal(e.into()))?;
            match found.as_slice() {
                [] => Ok(None),
                [one] => Ok(Some(one.clone())),
                _ => Err(Error::BadRequest(format!(
                    "project {reference:?} names a project in more than one of your \
                     organizations; use its id"
                ))),
            }
        })
        .await
    }

    /// Every project in an organization, oldest first.
    pub async fn list_projects(&self, org_id: String) -> Result<Vec<Project>> {
        self.call(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, slug, name FROM projects WHERE org_id=?1 ORDER BY created_at, slug",
                )
                .map_err(|e| Error::Internal(e.into()))?;
            let rows = stmt
                .query_map(params![org_id], |row| {
                    Ok(Project {
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
}
