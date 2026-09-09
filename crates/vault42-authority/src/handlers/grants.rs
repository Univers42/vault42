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

//! Project grant routes, and the wrap bookkeeping that fulfils them.
//!
//! A grant with `env_id` null is project-wide and applies to every environment in the
//! project. The client already depends on that, so it is contract rather than convenience.
//!
//! `missing` is the client's provisioning loop and doubles as the authorized-member set for
//! rotation, so exactness matters in both directions: a name absent from it silently loses
//! access, and a name that should not be there silently keeps it.

use super::org_project;
use crate::app::App;
use crate::auth::Principal;
use crate::error::{Error, Result};
use crate::rbac::ProjectRole;
use crate::store::NewGrant;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Create-grant body.
#[derive(Deserialize)]
pub struct GrantReq {
    grantee_kind: String,
    grantee_id: String,
    project_role: String,
    #[serde(default)]
    env_id: Option<String>,
}

/// Add-wrap body.
#[derive(Deserialize)]
pub struct WrapReq {
    user_id: String,
}

/// A created grant.
#[derive(Serialize)]
pub struct GrantResp {
    id: String,
}

/// A grant as listed. `env_id` null means project-wide.
#[derive(Serialize)]
pub struct ProjectGrantResp {
    id: String,
    env_id: Option<String>,
}

/// Which authorized members still need a scope-key wrap.
#[derive(Serialize)]
pub struct FulfilledResp {
    missing: Vec<String>,
}

/// Grant a role on a project to a user or a team. Administrators only.
pub async fn create(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path((org, project)): Path<(String, String)>,
    Json(body): Json<GrantReq>,
) -> Result<(StatusCode, Json<GrantResp>)> {
    let (project_id, _, role) = org_project(&app, (org, project), &caller).await?;
    role.require_admin()?;
    if body.grantee_kind != "user" && body.grantee_kind != "team" {
        return Err(Error::BadRequest(
            "grantee_kind must be user or team".into(),
        ));
    }
    let project_role = ProjectRole::parse(&body.project_role)?;
    let id = uuid::Uuid::new_v4().to_string();
    app.store
        .create_grant(NewGrant {
            id: id.clone(),
            project_id,
            grantee_kind: body.grantee_kind,
            grantee_id: body.grantee_id,
            project_role: project_role.as_str().to_string(),
            env_id: body.env_id,
            granted_by: caller.account_id,
        })
        .await?;
    Ok((StatusCode::CREATED, Json(GrantResp { id })))
}

/// List a project's live grants. Any organization member may read them.
pub async fn list(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path((org, project)): Path<(String, String)>,
) -> Result<Json<Vec<ProjectGrantResp>>> {
    let (project_id, _, _) = org_project(&app, (org, project), &caller).await?;
    let rows = app.store.list_grants(project_id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| ProjectGrantResp {
                id: row.id,
                env_id: row.env_id,
            })
            .collect(),
    ))
}

/// Report which authorized members still lack a scope-key wrap.
pub async fn fulfilled(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path((org, project, grant)): Path<(String, String, String)>,
) -> Result<Json<FulfilledResp>> {
    let (project_id, _, _) = org_project(&app, (org, project), &caller).await?;
    require_grant_in_project(&app, &grant, &project_id).await?;
    let missing = app.store.grant_missing_wraps(grant).await?;
    Ok(Json(FulfilledResp { missing }))
}

/// Record that a scope-key wrap now exists for a member. Administrators only.
pub async fn add_wrap(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path((org, project, grant)): Path<(String, String, String)>,
    Json(body): Json<WrapReq>,
) -> Result<StatusCode> {
    let (project_id, _, role) = org_project(&app, (org, project), &caller).await?;
    role.require_admin()?;
    require_grant_in_project(&app, &grant, &project_id).await?;
    app.store.add_grant_wrap(grant, body.user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Refuse a grant id that belongs to a different project than the path names.
async fn require_grant_in_project(app: &App, grant_id: &str, project_id: &str) -> Result<()> {
    let owner = app
        .store
        .grant_project(grant_id.to_string())
        .await?
        .ok_or(Error::NotFound)?;
    if owner != project_id {
        return Err(Error::NotFound);
    }
    Ok(())
}
