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
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use vault42_core::fingerprint;

/// Shared application state.
pub struct App {
    pub authority: Authority,
    pub store: Store,
}

#[derive(Deserialize)]
pub struct RegisterReq {
    tenant: String,
    author_pubkey: String,
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

/// Decode a hex Ed25519 public key into its 16-byte author fingerprint.
fn parse_fp(pubkey_hex: &str) -> Result<[u8; 16], String> {
    let bytes =
        hex::decode(pubkey_hex.trim()).map_err(|_| "author_pubkey must be hex".to_string())?;
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "author_pubkey must be 32 bytes".to_string())?;
    Ok(fingerprint(&key))
}
