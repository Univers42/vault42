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
use crate::auth::Principal;
use crate::error::{Error, Result};
use crate::store::tenants::Claim;
use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use vault42_contract::signing::now_unix;
use vault42_contract::validate::{parse_fp, valid_tenant};

/// Registration request. Authenticated by the caller's session, so it carries no token of
/// its own: `token` is accepted and ignored, purely so an older client's body still parses.
#[derive(Deserialize)]
pub struct RegisterReq {
    tenant: String,
    author_pubkey: String,
    #[serde(default)]
    #[allow(dead_code)]
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
///
/// Taking `Principal` is the whole security model of this route, not a convenience: it makes
/// registration authenticated BY CONSTRUCTION, exactly like every other non-public route
/// here, so the contract is issued to a known account rather than to whoever holds a shared
/// string. That replaces the old `VAULT42_REGISTER_TOKEN` gate, which had no identity, no
/// revocation, no expiry and no audit trail, and which guarded the most powerful capability
/// the authority has while the far weaker account layer sat unused beside it. Admission
/// control now lives at `signup`, which is where the anonymous caller actually is.
pub async fn register(
    State(app): State<Arc<App>>,
    caller: Principal,
    Json(body): Json<RegisterReq>,
) -> Result<Json<RegisterResp>> {
    if !valid_tenant(&body.tenant) {
        return Err(Error::BadRequest(
            "tenant must be 1..=64 of [A-Za-z0-9_-]".into(),
        ));
    }
    let author_fp = parse_fp(&body.author_pubkey).map_err(Error::BadRequest)?;
    let claim = app
        .store
        .claim_tenant(
            body.tenant.clone(),
            hex::encode(author_fp),
            caller.account_id,
            (app.max_tenants_per_account, now_unix()),
        )
        .await?;
    match claim {
        Claim::Taken => return Err(Error::Conflict("tenant name is taken".into())),
        Claim::QuotaExceeded => {
            return Err(Error::Forbidden);
        }
        Claim::Granted => {}
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
///
/// This now guards `signup` rather than `register`. The gate exists to bound who may enter
/// the system at all, and `signup` is the only route an unauthenticated stranger can reach;
/// putting it on `register` left account creation wide open while making the authenticated
/// step the hard one, which is backwards.
pub(crate) fn check_invite(app: &App, presented: Option<&str>) -> Result<()> {
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
