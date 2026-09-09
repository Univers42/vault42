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

    /// Resolve a project reference (id or slug) to `(project_id, org_id)`.
    ///
    /// Returns the owning organization too, because most project routes do not carry the
    /// organization in their path and still have to authorize against it.
    pub async fn resolve_project(&self, reference: String) -> Result<Option<(String, String)>> {
        self.call(move |conn| {
            let found = conn.query_row(
                "SELECT id, org_id FROM projects WHERE id=?1 OR slug=?1",
                params![reference],
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
