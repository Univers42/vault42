/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   contract.rs                                          :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Contract issuance, re-served by the authority.
//!
//! This is the one route vault42's data plane depends on: it hands back an Ed25519-signed
//! contract binding a tenant to an author fingerprint, which vault42 then verifies
//! offline forever after. The signing key and the validation rules come from
//! `vault42-contract` rather than being reimplemented, so the two services cannot drift.

use crate::app::App;
use crate::error::{Error, Result};
use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use vault42_contract::signing::now_unix;
use vault42_contract::validate::{parse_fp, valid_tenant};

/// Registration request. `token` is required only when the authority configures one.
#[derive(Deserialize)]
pub struct RegisterReq {
    tenant: String,
    author_pubkey: String,
    #[serde(default)]
    token: Option<String>,
}

/// The issued contract.
#[derive(Serialize)]
pub struct RegisterResp {
    contract: String,
    tenant: String,
    expires_at: i64,
}

/// The authority public key, for vault42's `VAULT42_CONTRACT_PUBKEY`.
#[derive(Serialize)]
pub struct KeyResp {
    public_key: String,
}

/// Publish the authority public key. Public by design: it holds no secret.
pub async fn contract_key(State(app): State<Arc<App>>) -> Json<KeyResp> {
    Json(KeyResp {
        public_key: app.authority.public_hex(),
    })
}

/// Claim a tenant and issue a signed contract for the presented author key.
pub async fn register(
    State(app): State<Arc<App>>,
    Json(body): Json<RegisterReq>,
) -> Result<Json<RegisterResp>> {
    check_invite(&app, body.token.as_deref())?;
    if !valid_tenant(&body.tenant) {
        return Err(Error::BadRequest(
            "tenant must be 1..=64 of [A-Za-z0-9_-]".into(),
        ));
    }
    let author_fp = parse_fp(&body.author_pubkey).map_err(Error::BadRequest)?;
    let claimed = app
        .store
        .claim_tenant(
            body.tenant.clone(),
            hex::encode(author_fp),
            None,
            now_unix(),
        )
        .await?;
    if !claimed {
        return Err(Error::Conflict("tenant name is taken".into()));
    }
    let (contract, expires_at) = app.authority.issue(&body.tenant, author_fp)?;
    Ok(Json(RegisterResp {
        contract,
        tenant: body.tenant,
        expires_at,
    }))
}

/// Check the shared invite token in constant time, when one is configured.
///
/// Both sides are hashed before comparison so neither the token's length nor the position
/// of its first wrong byte is observable through timing. The previous implementation in
/// `vault42-contract` compared with `!=`, which leaks a prefix match and lets a guess be
/// refined byte by byte.
fn check_invite(app: &App, presented: Option<&str>) -> Result<()> {
    let Some(expected) = &app.register_token else {
        return Ok(());
    };
    let presented = blake3::hash(presented.unwrap_or_default().as_bytes());
    let expected = blake3::hash(expected.as_bytes());
    if presented.as_bytes().ct_eq(expected.as_bytes()).into() {
        return Ok(());
    }
    Err(Error::Unauthorized)
}
