/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   secondfactor.rs                                      :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! One-time codes, keystore escrow, and turning the second factor on.
//!
//! Requesting a code always answers 200, whether or not the address has an account. That is not
//! politeness, it is the removal of an oracle: a different answer for an unknown address turns
//! this route into a way to enumerate who has an account here. The client already relies on it.
//!
//! Delivery is spawned rather than awaited, for the same reason. Sending over SMTP takes
//! hundreds of milliseconds and doing it inline would restore the oracle as a timing difference
//! after removing it from the status code. Both transports behave identically in this respect, so
//! a test never exercises a path production does not. A test that reads the outbox therefore polls
//! briefly for the file, as it already polls for readiness.
//!
//! Verifying a code returns a proof and never a session. The proof says only that somebody
//! holding this address entered the right code recently; it is what `login` and `/v1/register`
//! demand, and what authorizes escrow.

use crate::app::App;
use crate::auth::Principal;
use crate::error::{Error, Result};
use crate::store::NewCode;
use crate::{mail, otp, validate};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use vault42_contract::signing::now_unix;

/// The longest escrow blob accepted: a passphrase-wrapped keystore, not a file store.
const MAX_ESCROW_LEN: usize = 64 * 1024;

/// Request a code for an address.
#[derive(Deserialize)]
pub struct RequestReq {
    email: String,
}

/// Submit a code for an address.
#[derive(Deserialize)]
pub struct VerifyReq {
    email: String,
    code: String,
}

/// The proof a correct code earns.
#[derive(Serialize)]
pub struct VerifyResp {
    proof: String,
}

/// Upload an escrowed keystore.
#[derive(Deserialize)]
pub struct EscrowPutReq {
    email: String,
    proof: String,
    blob: String,
}

/// Fetch an escrowed keystore.
#[derive(Deserialize)]
pub struct EscrowFetchReq {
    email: String,
    proof: String,
}

/// The stored ciphertext, exactly as uploaded.
#[derive(Serialize)]
pub struct EscrowFetchResp {
    blob: String,
}

/// Turn the second factor on or off for the caller's own account.
#[derive(Deserialize)]
pub struct MfaReq {
    required: bool,
    proof: String,
}

/// Mail a fresh code to `email`, if an account holds it. Always 200.
pub async fn request(
    State(app): State<Arc<App>>,
    Json(body): Json<RequestReq>,
) -> Result<StatusCode> {
    app.proof_secret()?;
    let email = validate::normalize_email(&body.email).map_err(Error::BadRequest)?;
    if app.store.account_by_email(email.clone()).await?.is_some() {
        issue_code(&app, email).await?;
    }
    Ok(StatusCode::OK)
}

/// Generate, store and dispatch one code.
///
/// The code exists in a `Zeroizing` buffer and reaches the database only as a digest bound to the
/// address. Delivery is handed to a spawned task so the response time does not reveal whether an
/// account exists.
async fn issue_code(app: &Arc<App>, email: String) -> Result<()> {
    let code = otp::generate_code();
    app.store
        .put_code(NewCode {
            email: email.clone(),
            code_hash: otp::hash_code(&email, &code),
            expires_at: now_unix() + app.otp.ttl_secs,
        })
        .await?;
    let message = mail::code_message(&email, &code, app.otp.ttl_secs);
    let app = Arc::clone(app);
    tokio::spawn(async move {
        if mail::deliver(&app.mail, &message).is_err() {
            tracing::warn!("could not deliver a one-time code");
        }
    });
    Ok(())
}

/// Check a code and mint a proof. One answer for every kind of failure.
///
/// The rejection reason is deliberately not reported. "Expired", "already used" and "wrong" told
/// apart would let somebody probe whether an address currently has a live code, and how many
/// guesses remain.
pub async fn verify(
    State(app): State<Arc<App>>,
    Json(body): Json<VerifyReq>,
) -> Result<Json<VerifyResp>> {
    let secret = app.proof_secret()?.to_vec();
    let email = validate::normalize_email(&body.email).map_err(Error::BadRequest)?;
    otp::check_shape(&body.code)?;
    let submitted = body.code.clone();
    let bound = email.clone();
    let outcome = app
        .store
        .spend_attempt(email.clone(), move |stored| {
            otp::code_matches(&bound, &submitted, stored)
        })
        .await?;
    if let Err(reason) = outcome {
        tracing::info!(?reason, "one-time code refused");
        return Err(Error::Unauthorized);
    }
    let proof =
        vault42_contract::otp::mint_otp_proof(&email, &secret, now_unix() + app.otp.proof_ttl_secs)
            .map_err(|why| Error::Internal(anyhow::anyhow!(why)))?;
    Ok(Json(VerifyResp { proof }))
}

/// Store a passphrase-wrapped keystore, authorized by a proof bound to the same address.
///
/// The blob is ciphertext the authority cannot open, so this is storage rather than custody. The
/// proof is what stops somebody overwriting another person's escrow with a blob of their own.
pub async fn escrow_put(
    State(app): State<Arc<App>>,
    Json(body): Json<EscrowPutReq>,
) -> Result<StatusCode> {
    let email = authorized_address(&app, &body.email, &body.proof)?;
    if body.blob.is_empty() || body.blob.len() > MAX_ESCROW_LEN {
        return Err(Error::BadRequest(format!(
            "blob must be 1..={MAX_ESCROW_LEN} bytes"
        )));
    }
    app.store.put_escrow(email, body.blob).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Return a stored keystore blob to a holder of a proof for the same address.
pub async fn escrow_fetch(
    State(app): State<Arc<App>>,
    Json(body): Json<EscrowFetchReq>,
) -> Result<Json<EscrowFetchResp>> {
    let email = authorized_address(&app, &body.email, &body.proof)?;
    let blob = app.store.escrow_blob(email).await?.ok_or(Error::NotFound)?;
    Ok(Json(EscrowFetchResp { blob }))
}

/// Turn the second factor on or off for the caller, both directions gated on a fresh proof.
///
/// Enabling without proving the address can receive a code is how somebody locks themselves out
/// of their own account, so the proof is required to turn it on. It is required to turn it off for
/// the opposite reason: a stolen session must not be able to strip the factor that would have
/// stopped it.
pub async fn set_mfa(
    State(app): State<Arc<App>>,
    caller: Principal,
    Json(body): Json<MfaReq>,
) -> Result<StatusCode> {
    authorized_address(&app, &caller.email, &body.proof)?;
    app.store
        .set_mfa_required(caller.account_id, body.required)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Normalize `email` and refuse unless `proof` is a live proof bound to it.
fn authorized_address(app: &App, email: &str, proof: &str) -> Result<String> {
    let secret = app.proof_secret()?;
    let email = validate::normalize_email(email).map_err(Error::BadRequest)?;
    vault42_contract::otp::verify_otp_proof(proof, &email, secret)
        .map_err(|_| Error::Unauthorized)?;
    Ok(email)
}

/// Whether a login may mint a session for this account, given the proof it presented.
///
/// This is the second-factor gate, and it lives here rather than in each sign-in route so that
/// every path minting a session asks the same question. An account that requires a factor and an
/// authority with no secret to verify one is a misconfiguration, and it refuses: enabling the
/// requirement and then losing the secret must not silently disable the requirement.
pub fn check_second_factor(app: &App, account: (&str, bool), proof: Option<&str>) -> Result<()> {
    let (email, required) = account;
    if !required {
        return Ok(());
    }
    let Some(secret) = app.otp.proof_secret.as_deref() else {
        tracing::error!("an account requires a second factor but no proof secret is configured");
        return Err(Error::Internal(anyhow::anyhow!(
            "second factor required but unverifiable"
        )));
    };
    let proof = proof.ok_or(Error::Unauthorized)?;
    vault42_contract::otp::verify_otp_proof(proof, email, secret).map_err(|_| Error::Unauthorized)
}
