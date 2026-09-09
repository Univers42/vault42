/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   variables.rs                                         :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Variable routes at three levels of scope, and the resolved view over them.
//!
//! Reads need organization membership. Writes need either organization administration or a
//! live project grant of `write` or `admin` covering the scope being written — that is where
//! grants stop being bookkeeping and start deciding something.
//!
//! Values are opaque. The authority never parses one, so a secret is a blob the client sealed
//! against the environment's scope key and the authority cannot read it even in principle.

use super::{org_context, project_context};
use crate::app::App;
use crate::auth::Principal;
use crate::error::{Error, Result};
use crate::rbac::{OrgRole, ProjectRole};
use crate::store::{ResolveScopes, UpsertVariable};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// The longest key accepted.
const MAX_KEY_LEN: usize = 128;

/// The longest value accepted.
///
/// A variable is configuration, not a file. Files go through the vault data plane, which is
/// built to stream them; a megabyte here is generous for a sealed secret and keeps a single
/// request from pinning a large buffer on a 256 MB machine.
const MAX_VALUE_LEN: usize = 1 << 20;

/// Write-variable body.
#[derive(Deserialize)]
pub struct PutVariableReq {
    value: String,
    #[serde(default)]
    is_secret: bool,
}

/// A variable as the API reports it.
#[derive(Serialize)]
pub struct VariableResp {
    key: String,
    value: String,
    is_secret: bool,
    scope_kind: String,
    updated_at: i64,
}

/// List the variables set directly on an organization.
pub async fn org_list(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path(org): Path<String>,
) -> Result<Json<Vec<VariableResp>>> {
    let (org_id, _) = org_context(&app, org, &caller).await?;
    list(&app, "org", org_id).await
}

/// Set a variable on an organization. Administrators only.
pub async fn org_put(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path((org, key)): Path<(String, String)>,
    Json(body): Json<PutVariableReq>,
) -> Result<StatusCode> {
    let (org_id, role) = org_context(&app, org, &caller).await?;
    role.require_admin()?;
    write(&app, ("org", org_id), (key, body), &caller).await
}

/// Remove a variable from an organization. Administrators only.
pub async fn org_delete(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path((org, key)): Path<(String, String)>,
) -> Result<StatusCode> {
    let (org_id, role) = org_context(&app, org, &caller).await?;
    role.require_admin()?;
    remove(&app, "org", org_id, key).await
}

/// List the variables set directly on a project.
pub async fn project_list(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path(project): Path<String>,
) -> Result<Json<Vec<VariableResp>>> {
    let (project_id, _, _) = project_context(&app, project, &caller).await?;
    list(&app, "project", project_id).await
}

/// Set a variable on a project.
pub async fn project_put(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path((project, key)): Path<(String, String)>,
    Json(body): Json<PutVariableReq>,
) -> Result<StatusCode> {
    let (project_id, _, role) = project_context(&app, project, &caller).await?;
    require_write(&app, &project_id, role, &caller, None).await?;
    write(&app, ("project", project_id), (key, body), &caller).await
}

/// Remove a variable from a project.
pub async fn project_delete(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path((project, key)): Path<(String, String)>,
) -> Result<StatusCode> {
    let (project_id, _, role) = project_context(&app, project, &caller).await?;
    require_write(&app, &project_id, role, &caller, None).await?;
    remove(&app, "project", project_id, key).await
}

/// List the variables set directly on an environment.
pub async fn env_list(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path((project, env)): Path<(String, String)>,
) -> Result<Json<Vec<VariableResp>>> {
    let (_, env_id) = env_scope(&app, (project, env), &caller).await?;
    list(&app, "env", env_id).await
}

/// Set a variable on an environment.
pub async fn env_put(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path((project, env, key)): Path<(String, String, String)>,
    Json(body): Json<PutVariableReq>,
) -> Result<StatusCode> {
    let (project_id, env_id) = env_scope(&app, (project, env), &caller).await?;
    let role = caller_org_role(&app, &project_id, &caller).await?;
    require_write(&app, &project_id, role, &caller, Some(env_id.clone())).await?;
    write(&app, ("env", env_id), (key, body), &caller).await
}

/// Remove a variable from an environment.
pub async fn env_delete(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path((project, env, key)): Path<(String, String, String)>,
) -> Result<StatusCode> {
    let (project_id, env_id) = env_scope(&app, (project, env), &caller).await?;
    let role = caller_org_role(&app, &project_id, &caller).await?;
    require_write(&app, &project_id, role, &caller, Some(env_id.clone())).await?;
    remove(&app, "env", env_id, key).await
}

/// The effective variables for an environment: environment over project over organization.
pub async fn resolve(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path((project, env)): Path<(String, String)>,
) -> Result<Json<Vec<VariableResp>>> {
    let (project_id, org_id, _) = project_context(&app, project, &caller).await?;
    let env_id = app
        .store
        .resolve_environment(project_id.clone(), env)
        .await?
        .ok_or(Error::NotFound)?;
    let rows = app
        .store
        .resolve_variables(ResolveScopes {
            org_id,
            project_id,
            env_id,
        })
        .await?;
    Ok(Json(rows.into_iter().map(into_resp).collect()))
}

/// Resolve a project and environment pair, requiring organization membership.
async fn env_scope(
    app: &App,
    refs: (String, String),
    caller: &Principal,
) -> Result<(String, String)> {
    let (project, env) = refs;
    let (project_id, _, _) = project_context(app, project, caller).await?;
    let env_id = app
        .store
        .resolve_environment(project_id.clone(), env)
        .await?
        .ok_or(Error::NotFound)?;
    Ok((project_id, env_id))
}

/// The caller's organization role, via the project's organization.
async fn caller_org_role(app: &App, project_id: &str, caller: &Principal) -> Result<OrgRole> {
    let (_, _, role) = project_context(app, project_id.to_string(), caller).await?;
    Ok(role)
}

/// Refuse unless the caller may write this scope.
///
/// Organization administrators always may. Otherwise a live grant of `write` or `admin` must
/// cover the scope, which for an environment includes any project-wide grant.
async fn require_write(
    app: &App,
    project_id: &str,
    org_role: OrgRole,
    caller: &Principal,
    env_id: Option<String>,
) -> Result<()> {
    if org_role.can_administer() {
        return Ok(());
    }
    let granted = app
        .store
        .effective_project_role(project_id.to_string(), caller.account_id.clone(), env_id)
        .await?;
    match granted {
        Some(ProjectRole::Admin | ProjectRole::Write) => Ok(()),
        _ => Err(Error::Forbidden),
    }
}

/// List one scope's variables.
async fn list(app: &App, kind: &str, scope_id: String) -> Result<Json<Vec<VariableResp>>> {
    let rows = app.store.list_variables(kind.to_string(), scope_id).await?;
    Ok(Json(rows.into_iter().map(into_resp).collect()))
}

/// Validate and upsert one variable.
async fn write(
    app: &App,
    scope: (&str, String),
    body: (String, PutVariableReq),
    caller: &Principal,
) -> Result<StatusCode> {
    let (kind, scope_id) = scope;
    let (key, value) = body;
    check_key(&key)?;
    if value.value.len() > MAX_VALUE_LEN {
        return Err(Error::BadRequest(format!(
            "value must be at most {MAX_VALUE_LEN} bytes"
        )));
    }
    if value.is_secret {
        crate::validate::check_sealed(&value.value).map_err(Error::BadRequest)?;
    }
    app.store
        .put_variable(UpsertVariable {
            scope_kind: kind.to_string(),
            scope_id,
            key,
            value: value.value,
            is_secret: value.is_secret,
            updated_by: caller.account_id.clone(),
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Delete one variable.
async fn remove(app: &App, kind: &str, scope_id: String, key: String) -> Result<StatusCode> {
    check_key(&key)?;
    app.store
        .delete_variable(kind.to_string(), scope_id, key)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Refuse a key that would not be a usable environment-variable name.
fn check_key(key: &str) -> Result<()> {
    let ok = !key.is_empty()
        && key.len() <= MAX_KEY_LEN
        && !key.starts_with(|c: char| c.is_ascii_digit())
        && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if ok {
        return Ok(());
    }
    Err(Error::BadRequest(format!(
        "key must be 1..={MAX_KEY_LEN} of [A-Za-z0-9_] and must not start with a digit"
    )))
}

/// Project a stored variable onto its wire shape.
fn into_resp(row: crate::store::Variable) -> VariableResp {
    VariableResp {
        key: row.key,
        value: row.value,
        is_secret: row.is_secret,
        scope_kind: row.scope_kind,
        updated_at: row.updated_at,
    }
}
