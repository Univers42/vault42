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

//! Project routes.
//!
//! The optional `id` on create exists to reconcile two meanings of "project" that never met
//! in the client. 42ctl's `push`/`pull` derive a local project id as a UUIDv5 over the
//! canonical root path and store data under it, while its scope and grant verbs take
//! `--project` as a caller-supplied string. Nothing linked them, so a user could push and
//! then configure environments for two different objects that happened to share a name.
//!
//! Accepting the client's existing id makes them one object: a project already pushed can be
//! registered here under the same identifier, and everything already stored stays reachable.
//! Omit `id` and the authority mints a fresh v4 UUID.

use super::{admin_context, check_slug, check_uuid, org_context};
use crate::app::App;
use crate::auth::Principal;
use crate::error::{Error, Result};
use crate::store::NewProject;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Create-project body.
#[derive(Deserialize)]
pub struct CreateProjectReq {
    slug: String,
    name: String,
    #[serde(default)]
    id: Option<String>,
}

/// A project as the client expects it.
#[derive(Serialize)]
pub struct ProjectResp {
    id: String,
    slug: String,
    name: String,
}

/// Create a project in an organization. Administrators only.
pub async fn create(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path(org): Path<String>,
    Json(body): Json<CreateProjectReq>,
) -> Result<(StatusCode, Json<ProjectResp>)> {
    let org_id = admin_context(&app, org, &caller).await?;
    check_slug(&body.slug, "slug")?;
    if body.name.trim().is_empty() || body.name.len() > 200 {
        return Err(Error::BadRequest("name must be 1..=200 characters".into()));
    }
    let id = match body.id {
        Some(existing) => {
            check_uuid(&existing, "id")?;
            existing
        }
        None => uuid::Uuid::new_v4().to_string(),
    };
    app.store
        .create_project(NewProject {
            id: id.clone(),
            org_id,
            slug: body.slug.clone(),
            name: body.name.clone(),
        })
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(ProjectResp {
            id,
            slug: body.slug,
            name: body.name,
        }),
    ))
}

/// List an organization's projects. Any member may read them.
pub async fn list(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path(org): Path<String>,
) -> Result<Json<Vec<ProjectResp>>> {
    let (org_id, _) = org_context(&app, org, &caller).await?;
    let rows = app.store.list_projects(org_id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| ProjectResp {
                id: row.id,
                slug: row.slug,
                name: row.name,
            })
            .collect(),
    ))
}
