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

//! Team routes: create, list, add a member, invite.
//!
//! Adding someone to a team requires that they already belong to the organization. That is
//! the rule the schema enforces with a composite foreign key; these handlers surface it as
//! a message rather than a bare constraint failure.

use super::{admin_context, check_slug, org_context, INVITE_TTL_SECS};
use crate::app::App;
use crate::auth::{session, Principal};
use crate::error::{Error, Result};
use crate::handlers::orgs::{InviteReq, IssuedInviteResp};
use crate::rbac::TeamRole;
use crate::store::{NewInvite, NewTeam, NewTeamMember};
use crate::validate;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use vault42_contract::signing::now_unix;

/// Create-team body.
#[derive(Deserialize)]
pub struct CreateTeamReq {
    slug: String,
    name: String,
}

/// Add-team-member body.
#[derive(Deserialize)]
pub struct AddMemberReq {
    user_id: String,
    #[serde(default)]
    team_role: Option<String>,
}

/// A team as the client expects it.
#[derive(Serialize)]
pub struct TeamResp {
    id: String,
    slug: String,
    name: String,
}

/// Create a team in an organization. Administrators only.
pub async fn create(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path(org): Path<String>,
    Json(body): Json<CreateTeamReq>,
) -> Result<(StatusCode, Json<TeamResp>)> {
    let org_id = admin_context(&app, org, &caller).await?;
    check_slug(&body.slug, "slug")?;
    let id = uuid::Uuid::new_v4().to_string();
    app.store
        .create_team(NewTeam {
            id: id.clone(),
            org_id,
            slug: body.slug.clone(),
            name: body.name.clone(),
        })
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(TeamResp {
            id,
            slug: body.slug,
            name: body.name,
        }),
    ))
}

/// List an organization's teams. Any member may read them.
pub async fn list(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path(org): Path<String>,
) -> Result<Json<Vec<TeamResp>>> {
    let (org_id, _) = org_context(&app, org, &caller).await?;
    let rows = app.store.list_teams(org_id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| TeamResp {
                id: row.id,
                slug: row.slug,
                name: row.name,
            })
            .collect(),
    ))
}

/// Place an existing organization member in a team. Administrators only.
pub async fn add_member(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path((org, team)): Path<(String, String)>,
    Json(body): Json<AddMemberReq>,
) -> Result<StatusCode> {
    let org_id = admin_context(&app, org, &caller).await?;
    let team_id = resolve(&app, &org_id, team).await?;
    let role = TeamRole::parse(body.team_role.as_deref().unwrap_or("member"))?;
    let account_id = resolve_member(&app, &org_id, body.user_id).await?;
    app.store
        .add_team_member(NewTeamMember {
            team_id,
            org_id,
            account_id,
            role,
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Invite someone to a team. Administrators only.
pub async fn invite(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path((org, team)): Path<(String, String)>,
    Json(body): Json<InviteReq>,
) -> Result<(StatusCode, Json<IssuedInviteResp>)> {
    let org_id = admin_context(&app, org, &caller).await?;
    let team_id = resolve(&app, &org_id, team).await?;
    let email = validate::normalize_email(&body.email).map_err(Error::BadRequest)?;
    let role = TeamRole::parse(body.role.as_deref().unwrap_or("member"))?;
    let issued = session::mint(now_unix(), INVITE_TTL_SECS);
    let id = uuid::Uuid::new_v4().to_string();
    app.store
        .issue_invite(NewInvite {
            id: id.clone(),
            token_hash: issued.token_hash,
            scope_kind: "team".into(),
            scope_id: team_id,
            email,
            role: role.as_str().to_string(),
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

/// Resolve a team reference within an organization, or 404.
async fn resolve(app: &App, org_id: &str, reference: String) -> Result<String> {
    app.store
        .resolve_team(org_id.to_string(), reference)
        .await?
        .ok_or(Error::NotFound)
}

/// Resolve a member reference (account id or email) within the organization.
///
/// The client documents this field as "user id or email" and sent whichever the operator
/// typed; it was stored verbatim, so an address became a team member row matching no account
/// and the team silently authorized nobody. Resolving within the organization keeps the
/// address from being a lookup oracle for non-members.
async fn resolve_member(app: &App, org_id: &str, reference: String) -> Result<String> {
    let normalized =
        crate::validate::normalize_email(&reference).unwrap_or_else(|_| reference.clone());
    app.store
        .resolve_org_member(org_id.to_string(), normalized)
        .await?
        .ok_or_else(|| Error::BadRequest(format!("no member {reference:?} in this organization")))
}
