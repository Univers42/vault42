/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   routes.rs                                            :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The authority's HTTP/JSON surface. `POST /v1/register {tenant, author_pubkey}` claims
//! a tenant name for an Ed25519 author key and returns a signed contract; the consuming
//! client saves it and presents it to vault42. `GET /v1/contract-key` exposes the public
//! key vault42 verifies against. HTTPS is terminated at the fly edge.

use crate::authority::Authority;
use crate::signing::now_unix;
use crate::store::Store;
use crate::validate::{parse_fp, valid_tenant};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Shared application state. `register_token`, when set, gates registration (an invite
/// code shared with friends) so the public authority can't be squatted or flooded.
pub struct App {
    pub authority: Authority,
    pub store: Store,
    pub register_token: Option<String>,
    pub require_otp: bool,
    pub otp_jwt_secret: Option<Vec<u8>>,
}

#[derive(Deserialize)]
pub struct RegisterReq {
    tenant: String,
    author_pubkey: String,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    otp_proof: Option<String>,
}

#[derive(Serialize)]
struct RegisterResp {
    contract: String,
    tenant: String,
    expires_at: i64,
}

#[derive(Serialize)]
struct KeyResp {
    public_key: String,
}

/// Build the authority's router over shared state.
pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/contract-key", get(contract_key))
        .route("/v1/register", post(register))
        .with_state(app)
}

/// Liveness probe.
async fn healthz() -> &'static str {
    "ok"
}

/// Expose the authority public key (vault42's `VAULT42_CONTRACT_PUBKEY`).
async fn contract_key(State(app): State<Arc<App>>) -> Json<KeyResp> {
    Json(KeyResp {
        public_key: app.authority.public_hex(),
    })
}

/// Claim a tenant for an author key and return a signed contract.
async fn register(
    State(app): State<Arc<App>>,
    Json(req): Json<RegisterReq>,
) -> Result<Json<RegisterResp>, (StatusCode, String)> {
    if let Some(expected) = &app.register_token {
        if req.token.as_deref() != Some(expected.as_str()) {
            return Err((
                StatusCode::UNAUTHORIZED,
                "registration token required".into(),
            ));
        }
    }
    if app.require_otp {
        require_otp_proof(&app, &req)?;
    }
    if !valid_tenant(&req.tenant) {
        return Err((StatusCode::BAD_REQUEST, "invalid tenant name".into()));
    }
    let author_fp = parse_fp(&req.author_pubkey).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let claimed = app
        .store
        .claim_tenant(&req.tenant, &hex::encode(author_fp), now_unix())
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "registry error".into()))?;
    if !claimed {
        return Err((StatusCode::CONFLICT, "tenant name already claimed".into()));
    }
    let (contract, expires_at) = app
        .authority
        .issue(&req.tenant, author_fp)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "issue failed".into()))?;
    Ok(Json(RegisterResp {
        contract,
        tenant: req.tenant,
        expires_at,
    }))
}

/// Require + verify the email-OTP proof (when `VAULT42_CONTRACT_REQUIRE_OTP` is on):
/// both `email` and `otp_proof` must be present and the proof must verify against the
/// shared secret for that email — else 401. This makes the OTP a server-enforced gate.
fn require_otp_proof(app: &App, req: &RegisterReq) -> Result<(), (StatusCode, String)> {
    let secret = app.otp_jwt_secret.as_deref().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "otp required but GOTRUE_JWT_SECRET not configured".into(),
    ))?;
    let email = req.email.as_deref().filter(|e| !e.is_empty());
    let (Some(email), Some(proof)) = (email, req.otp_proof.as_deref()) else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "email + otp_proof required".into(),
        ));
    };
    crate::otp::verify_otp_proof(proof, email, secret)
        .map_err(|reason| (StatusCode::UNAUTHORIZED, format!("otp: {reason}")))
}
