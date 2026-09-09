/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   environments.rs                                      :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Environment routes, including the published scope key.
//!
//! Publishing a scope key is how an administrator tells members which key to seal secrets
//! to. Only the public half is ever sent here. The epoch must advance on every publish, so a
//! stale client cannot roll an environment back to a key that removed members still hold.

use super::{project_admin, project_context};
use crate::app::App;
use crate::auth::Principal;
use crate::error::{Error, Result};
use crate::store::NewEnvironment;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Create-environment body.
#[derive(Deserialize)]
pub struct CreateEnvReq {
    name: String,
}

/// Publish-scope-key body.
#[derive(Deserialize)]
pub struct ScopeKeyReq {
    scope_pubkey: String,
    scope_epoch: i64,
}

/// An environment as the client expects it.
#[derive(Serialize)]
pub struct EnvResp {
    id: String,
    name: String,
    scope_pubkey: Option<String>,
    scope_epoch: i64,
}

/// Create an environment in a project. Administrators only.
pub async fn create(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path(project): Path<String>,
    Json(body): Json<CreateEnvReq>,
) -> Result<(StatusCode, Json<EnvResp>)> {
    let (project_id, _) = project_admin(&app, project, &caller).await?;
    let name = body.name.trim();
    if name.is_empty() || name.len() > 64 {
        return Err(Error::BadRequest("name must be 1..=64 characters".into()));
    }
    let id = uuid::Uuid::new_v4().to_string();
    app.store
        .create_environment(NewEnvironment {
            id: id.clone(),
            project_id,
            name: name.to_string(),
        })
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(EnvResp {
            id,
            name: name.to_string(),
            scope_pubkey: None,
            scope_epoch: 0,
        }),
    ))
}

/// List a project's environments. Any organization member may read them.
pub async fn list(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path(project): Path<String>,
) -> Result<Json<Vec<EnvResp>>> {
    let (project_id, _, _) = project_context(&app, project, &caller).await?;
    let rows = app.store.list_environments(project_id).await?;
    Ok(Json(rows.into_iter().map(into_resp).collect()))
}

/// Publish or rotate an environment's scope public key. Administrators only.
pub async fn set_scope_key(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path((project, env)): Path<(String, String)>,
    Json(body): Json<ScopeKeyReq>,
) -> Result<Json<EnvResp>> {
    let (project_id, _) = project_admin(&app, project, &caller).await?;
    if body.scope_pubkey.trim().is_empty() {
        return Err(Error::BadRequest("scope_pubkey must not be empty".into()));
    }
    if body.scope_epoch < 1 {
        return Err(Error::BadRequest("scope_epoch must be at least 1".into()));
    }
    let env_id = app
        .store
        .resolve_environment(project_id, env)
        .await?
        .ok_or(Error::NotFound)?;
    let updated = app
        .store
        .set_scope_key(env_id, body.scope_pubkey, body.scope_epoch)
        .await?;
    Ok(Json(into_resp(updated)))
}

/// Project a stored environment onto its wire shape.
fn into_resp(row: crate::store::Environment) -> EnvResp {
    EnvResp {
        id: row.id,
        name: row.name,
        scope_pubkey: row.scope_pubkey,
        scope_epoch: row.scope_epoch,
    }
}
