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

//! Project group routes.

use super::{project_admin, INVITE_TTL_SECS};
use crate::app::App;
use crate::auth::{session, Principal};
use crate::error::{Error, Result};
use crate::handlers::orgs::{InviteReq, IssuedInviteResp};
use crate::store::{NewGroup, NewInvite};
use crate::validate;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use vault42_contract::signing::now_unix;

/// Create-group body. The client sends an empty object, so `name` is optional.
#[derive(Deserialize)]
pub struct CreateGroupReq {
    #[serde(default)]
    name: Option<String>,
}

/// Add-group-member body.
#[derive(Deserialize)]
pub struct AddMemberReq {
    user_id: String,
}

/// A group as the client expects it.
#[derive(Serialize)]
pub struct GroupResp {
    id: String,
    name: String,
}

/// Create a group in a project. Administrators only.
pub async fn create(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path(project): Path<String>,
    Json(body): Json<CreateGroupReq>,
) -> Result<(StatusCode, Json<GroupResp>)> {
    let (project_id, _) = project_admin(&app, project, &caller).await?;
    let id = uuid::Uuid::new_v4().to_string();
    let name = match body.name.as_deref().map(str::trim) {
        Some(given) if !given.is_empty() => given.to_string(),
        _ => format!("group-{}", &id[..8]),
    };
    app.store
        .create_group(NewGroup {
            id: id.clone(),
            project_id,
            name: name.clone(),
        })
        .await?;
    Ok((StatusCode::CREATED, Json(GroupResp { id, name })))
}

/// Add an organization member to a group. Administrators only.
pub async fn add_member(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path(group): Path<String>,
    Json(body): Json<AddMemberReq>,
) -> Result<StatusCode> {
    let org_id = admin_of_group(&app, &group, &caller).await?;
    app.store
        .add_group_member(group, org_id, body.user_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Invite someone to a group. Administrators only.
pub async fn invite(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path(group): Path<String>,
    Json(body): Json<InviteReq>,
) -> Result<(StatusCode, Json<IssuedInviteResp>)> {
    admin_of_group(&app, &group, &caller).await?;
    let email = validate::normalize_email(&body.email).map_err(Error::BadRequest)?;
    let issued = session::mint(now_unix(), INVITE_TTL_SECS);
    let id = uuid::Uuid::new_v4().to_string();
    app.store
        .issue_invite(NewInvite {
            id: id.clone(),
            token_hash: issued.token_hash,
            scope_kind: "group".into(),
            scope_id: group,
            email,
            role: "member".into(),
            invited_by: caller.account_id,
            expires_at: issued.expires_at,
        })
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(IssuedInviteResp {
            id,
            token: issued.token,
        }),
    ))
}

/// Resolve a group to its organization, refusing unless the caller may administer it.
///
/// A group's path carries neither project nor organization, so the group row is what
/// establishes which organization to authorize against.
async fn admin_of_group(app: &App, group_id: &str, caller: &Principal) -> Result<String> {
    let (project_id, _) = app
        .store
        .resolve_group(group_id.to_string())
        .await?
        .ok_or(Error::NotFound)?;
    let (_, org_id) = project_admin(app, project_id, caller).await?;
    Ok(org_id)
}
