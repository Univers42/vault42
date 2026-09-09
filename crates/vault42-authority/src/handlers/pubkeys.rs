/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   pubkeys.rs                                           :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Member public-key routes.
//!
//! Registration verifies a proof of possession, so a member cannot register somebody else's
//! public key and receive scope-key wraps meant for them. `user_id` always comes from the
//! session, never the body: taking it from the body would let a caller register keys under
//! another account's id and the proof would verify against whatever id they chose.

use super::org_context;
use crate::app::App;
use crate::auth::Principal;
use crate::error::{Error, Result};
use crate::pop;
use crate::store::MemberPubkey;
use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Register-keys body. Note the absence of a user id.
#[derive(Deserialize)]
pub struct PutPubkeyReq {
    x25519_pub: String,
    ed25519_pub: String,
    v42_address: String,
    pubkey_sig: String,
}

/// A member's keys as the client expects them.
#[derive(Serialize)]
pub struct PubkeyResp {
    user_id: String,
    x25519_pub: String,
    ed25519_pub: String,
    v42_address: String,
    pubkey_sig: String,
}

/// Register or replace the caller's own public keys for an organization.
pub async fn put_self(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path(org): Path<String>,
    Json(body): Json<PutPubkeyReq>,
) -> Result<Json<PubkeyResp>> {
    let (org_id, _) = org_context(&app, org, &caller).await?;
    let claim = pop::Claim {
        account_id: &caller.account_id,
        org_id: &org_id,
        x25519_pub: &body.x25519_pub,
        ed25519_pub: &body.ed25519_pub,
        pubkey_sig: &body.pubkey_sig,
    };
    if !pop::verify(&claim) {
        return Err(Error::BadRequest(
            "pubkey_sig is not a valid proof of possession for this account and organization"
                .into(),
        ));
    }
    let keys = MemberPubkey {
        user_id: caller.account_id.clone(),
        x25519_pub: body.x25519_pub,
        ed25519_pub: body.ed25519_pub,
        v42_address: body.v42_address,
        pubkey_sig: body.pubkey_sig,
    };
    app.store.put_member_pubkey(org_id.clone(), keys).await?;
    read_back(&app, org_id, caller.account_id).await
}

/// Read a member's registered public keys. Any organization member may read them.
pub async fn get_member(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path((org, user)): Path<(String, String)>,
) -> Result<Json<PubkeyResp>> {
    let (org_id, _) = org_context(&app, org, &caller).await?;
    read_back(&app, org_id, user).await
}

/// Fetch and project a member's keys, or 404.
async fn read_back(app: &App, org_id: String, account_id: String) -> Result<Json<PubkeyResp>> {
    let keys = app
        .store
        .member_pubkey(org_id, account_id)
        .await?
        .ok_or(Error::NotFound)?;
    Ok(Json(PubkeyResp {
        user_id: keys.user_id,
        x25519_pub: keys.x25519_pub,
        ed25519_pub: keys.ed25519_pub,
        v42_address: keys.v42_address,
        pubkey_sig: keys.pubkey_sig,
    }))
}
