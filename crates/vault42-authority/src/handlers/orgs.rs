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

//! Organization routes: create, list members, invite.

use super::{admin_context, check_slug, org_context, INVITE_TTL_SECS};
use crate::app::App;
use crate::auth::{session, Principal};
use crate::error::{Error, Result};
use crate::rbac::OrgRole;
use crate::store::{NewInvite, NewOrg};
use crate::validate;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use vault42_contract::signing::now_unix;

/// Create-organization body.
#[derive(Deserialize)]
pub struct CreateOrgReq {
    slug: String,
    name: String,
}

/// Invite body, shared by the organization and team routes.
#[derive(Deserialize)]
pub struct InviteReq {
    pub email: String,
    #[serde(default)]
    pub role: Option<String>,
}

/// An organization as the client expects it.
#[derive(Serialize)]
pub struct OrgResp {
    id: String,
    slug: String,
    name: String,
}

/// One membership row.
#[derive(Serialize)]
pub struct MemberResp {
    user_id: String,
    role: String,
    created_at: i64,
}

/// A freshly issued invite. The token is returned exactly once, here.
#[derive(Serialize)]
pub struct IssuedInviteResp {
    pub id: String,
    pub token: String,
}

/// Create an organization; the caller becomes its owner.
pub async fn create(
    State(app): State<Arc<App>>,
    caller: Principal,
    Json(body): Json<CreateOrgReq>,
) -> Result<(StatusCode, Json<OrgResp>)> {
    check_slug(&body.slug, "slug")?;
    if body.name.trim().is_empty() || body.name.len() > 200 {
        return Err(Error::BadRequest("name must be 1..=200 characters".into()));
    }
    let id = uuid::Uuid::new_v4().to_string();
    app.store
        .create_org(NewOrg {
            id: id.clone(),
            slug: body.slug.clone(),
            name: body.name.clone(),
            created_by: caller.account_id,
            created_at: now_unix(),
        })
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(OrgResp {
            id,
            slug: body.slug,
            name: body.name,
        }),
    ))
}

/// Read one organization. Any member may resolve a slug to its canonical id.
///
/// This exists because a proof of possession must be signed over the organization's ID, not
/// over whichever alias the user typed. Without a way to resolve slug to id, a client would
/// sign over the slug and the server would verify over the id, so no proof would ever
/// verify.
pub async fn show(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path(org): Path<String>,
) -> Result<Json<OrgResp>> {
    let (org_id, _) = org_context(&app, org, &caller).await?;
    let found = app.store.org_by_id(org_id).await?.ok_or(Error::NotFound)?;
    Ok(Json(OrgResp {
        id: found.id,
        slug: found.slug,
        name: found.name,
    }))
}

/// List an organization's members. Any member may read the roster.
pub async fn members(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path(org): Path<String>,
) -> Result<Json<Vec<MemberResp>>> {
    let (org_id, _) = org_context(&app, org, &caller).await?;
    let rows = app.store.list_org_members(org_id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| MemberResp {
                user_id: row.user_id,
                role: row.role,
                created_at: row.created_at,
            })
            .collect(),
    ))
}

/// Invite someone to an organization. Administrators only.
pub async fn invite(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path(org): Path<String>,
    Json(body): Json<InviteReq>,
) -> Result<(StatusCode, Json<IssuedInviteResp>)> {
    let org_id = admin_context(&app, org, &caller).await?;
    let email = validate::normalize_email(&body.email).map_err(Error::BadRequest)?;
    let role = OrgRole::parse(body.role.as_deref().unwrap_or("member"))?;
    let issued = session::mint(now_unix(), INVITE_TTL_SECS);
    let id = uuid::Uuid::new_v4().to_string();
    app.store
        .issue_invite(NewInvite {
            id: id.clone(),
            token_hash: issued.token_hash,
            scope_kind: "org".into(),
            scope_id: org_id,
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
