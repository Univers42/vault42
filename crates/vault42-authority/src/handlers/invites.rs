/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   invites.rs                                           :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Invite routes: redeem one, and read one back.
//!
//! Redemption is authenticated because an invite grants membership to an account, so there
//! must be an account to grant it to. It is also bound to the invited address: the caller's
//! own email must match the one invited, so an intercepted token is useless to anyone else.

use crate::app::App;
use crate::auth::{session, Principal};
use crate::error::{Error, Result};
use crate::store::Acceptance;
use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use vault42_contract::signing::now_unix;

/// Redeem body.
#[derive(Deserialize)]
pub struct AcceptReq {
    token: String,
}

/// What an accepted invite granted.
#[derive(Serialize)]
pub struct AcceptedResp {
    scope_kind: String,
    scope_id: String,
    role: String,
}

/// An invite as the client expects it. Never carries the token.
#[derive(Serialize)]
pub struct InviteResp {
    id: String,
    scope_kind: String,
    scope_id: String,
    email: String,
    role: String,
    status: String,
    expires_at: i64,
}

/// Redeem an invite for the calling account.
pub async fn accept(
    State(app): State<Arc<App>>,
    caller: Principal,
    Json(body): Json<AcceptReq>,
) -> Result<Json<AcceptedResp>> {
    if body.token.trim().is_empty() {
        return Err(Error::BadRequest("token must not be empty".into()));
    }
    let granted = app
        .store
        .accept_invite(Acceptance {
            token_hash: session::hash_token(body.token.trim()),
            account_id: caller.account_id,
            email: caller.email,
            now: now_unix(),
        })
        .await?;
    Ok(Json(AcceptedResp {
        scope_kind: granted.scope_kind,
        scope_id: granted.scope_id,
        role: granted.role,
    }))
}

/// Read an invite back by id.
///
/// Restricted to the invited address: the row names who was invited and to what, which is
/// not something an unrelated account should be able to enumerate.
pub async fn show(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path(id): Path<String>,
) -> Result<Json<InviteResp>> {
    let invite = app.store.invite_by_id(id).await?.ok_or(Error::NotFound)?;
    if invite.email != caller.email {
        return Err(Error::NotFound);
    }
    Ok(Json(InviteResp {
        id: invite.id,
        scope_kind: invite.scope_kind,
        scope_id: invite.scope_id,
        email: invite.email,
        role: invite.role,
        status: invite.status,
        expires_at: invite.expires_at,
    }))
}
