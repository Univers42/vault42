/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   orgs.rs                                              :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Organization rows and membership.
//!
//! An organization reference on the wire may be either its id or its slug, because the
//! client sends whichever the user typed. Both are unique, so `resolve_org` accepts either
//! and everything downstream works in ids.

use super::{is_constraint_violation, Store};
use crate::error::{Error, Result};
use crate::rbac::OrgRole;
use rusqlite::params;

/// A new organization, grouped so the call stays within the parameter limit.
pub struct NewOrg {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub created_by: String,
    pub created_at: i64,
}

/// An organization as the API reports it.
pub struct Org {
    pub id: String,
    pub slug: String,
    pub name: String,
}

/// One membership row as the API reports it.
pub struct Member {
    pub user_id: String,
    pub role: String,
    pub created_at: i64,
}

impl Store {
    /// Create an organization and enrol its creator as owner, atomically.
    ///
    /// The two writes share one transaction because an organization with no owner would
    /// be unadministrable: nobody could invite, and nobody could delete it.
    pub async fn create_org(&self, new: NewOrg) -> Result<()> {
        self.call(move |conn| {
            let tx = conn.transaction().map_err(|e| Error::Internal(e.into()))?;
            tx.execute(
                "INSERT INTO orgs(id, slug, name, created_by, created_at) VALUES(?1,?2,?3,?4,?5)",
                params![new.id, new.slug, new.name, new.created_by, new.created_at],
            )
            .map_err(|error| {
                if is_constraint_violation(&error) {
                    Error::Conflict("organization slug already taken".into())
                } else {
                    Error::Internal(error.into())
                }
            })?;
            tx.execute(
                "INSERT INTO org_members(org_id, account_id, role, created_at)
                 VALUES(?1,?2,'owner',?3)",
                params![new.id, new.created_by, new.created_at],
            )
            .map_err(|e| Error::Internal(e.into()))?;
            tx.commit().map_err(|e| Error::Internal(e.into()))?;
            Ok(())
        })
        .await
    }

    /// Resolve an org reference (id or slug) to its id.
    pub async fn resolve_org(&self, reference: String) -> Result<Option<String>> {
        self.call(move |conn| {
            let found = conn.query_row(
                "SELECT id FROM orgs WHERE id=?1 OR slug=?1",
                params![reference],
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

    /// Read one organization by id.
    pub async fn org_by_id(&self, org_id: String) -> Result<Option<Org>> {
        self.call(move |conn| {
            let found = conn.query_row(
                "SELECT id, slug, name FROM orgs WHERE id=?1",
                params![org_id],
                |row| {
                    Ok(Org {
                        id: row.get(0)?,
                        slug: row.get(1)?,
                        name: row.get(2)?,
                    })
                },
            );
            match found {
                Ok(org) => Ok(Some(org)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(error) => Err(Error::Internal(error.into())),
            }
        })
        .await
    }

    /// The caller's role in an organization, or `None` if they are not a member.
    pub async fn org_role(&self, org_id: String, account_id: String) -> Result<Option<OrgRole>> {
        self.call(move |conn| {
            let found = conn.query_row(
                "SELECT role FROM org_members WHERE org_id=?1 AND account_id=?2",
                params![org_id, account_id],
                |row| row.get::<_, String>(0),
            );
            match found {
                Ok(role) => OrgRole::parse(&role).map(Some),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(error) => Err(Error::Internal(error.into())),
            }
        })
        .await
    }

    /// Every member of an organization, oldest first.
    pub async fn list_org_members(&self, org_id: String) -> Result<Vec<Member>> {
        self.call(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT account_id, role, created_at FROM org_members
                      WHERE org_id=?1 ORDER BY created_at, account_id",
                )
                .map_err(|e| Error::Internal(e.into()))?;
            let rows = stmt
                .query_map(params![org_id], |row| {
                    Ok(Member {
                        user_id: row.get(0)?,
                        role: row.get(1)?,
                        created_at: row.get(2)?,
                    })
                })
                .map_err(|e| Error::Internal(e.into()))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|e| Error::Internal(e.into()))
        })
        .await
    }
}
