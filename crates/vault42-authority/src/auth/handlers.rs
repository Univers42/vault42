/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   handlers.rs                                          :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Account routes: signup, login, logout, me, and password change.
//!
//! Two rules run through all of them. A password is never logged, echoed, or returned,
//! and it lives in a `Zeroizing` buffer for as long as it is held. And no response ever
//! reveals whether an email is registered: a bad login is 401 whether the account is
//! absent, disabled, or the password is simply wrong.

use crate::app::App;
use crate::auth::{password, session, Principal};
use crate::error::{Error, Result};
use crate::handlers::secondfactor;
use crate::store::Account;
use crate::throttle;
use crate::validate;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use vault42_contract::signing::now_unix;
use zeroize::Zeroizing;

/// Signup and login request body.
///
/// `otp_proof` is absent on signup and on a login for an account with no second factor. When the
/// account requires one it is mandatory, and it is the proof minted by `/v1/auth/otp/verify`.
#[derive(Deserialize)]
pub struct Credentials {
    email: String,
    password: String,
    #[serde(default)]
    otp_proof: Option<String>,
}

/// Password-change request body.
#[derive(Deserialize)]
pub struct PasswdReq {
    current_password: String,
    new_password: String,
}

/// The account identity returned by signup.
#[derive(Serialize)]
pub struct AccountResp {
    account_id: String,
}

/// A minted session.
#[derive(Serialize)]
pub struct LoginResp {
    pub token: String,
    pub account_id: String,
    pub expires_at: i64,
}

/// The caller's own account.
#[derive(Serialize)]
pub struct MeResp {
    account_id: String,
    email: String,
    mfa_required: bool,
}

/// Create an account. 409 when the email is already registered.
pub async fn signup(
    State(app): State<Arc<App>>,
    Json(body): Json<Credentials>,
) -> Result<(StatusCode, Json<AccountResp>)> {
    let email = validate::normalize_email(&body.email).map_err(Error::BadRequest)?;
    let secret = Zeroizing::new(body.password);
    validate::check_password(&secret).map_err(Error::BadRequest)?;
    let hash = password::hash(&secret).map_err(Error::Internal)?;
    let account_id = uuid::Uuid::new_v4().to_string();
    app.store
        .create_account(account_id.clone(), email, hash, now_unix())
        .await?;
    Ok((StatusCode::CREATED, Json(AccountResp { account_id })))
}

/// Exchange credentials for a bearer token.
pub async fn login(
    State(app): State<Arc<App>>,
    Json(body): Json<Credentials>,
) -> Result<Json<LoginResp>> {
    let email = validate::normalize_email(&body.email).map_err(Error::BadRequest)?;
    throttle::guard(&app, throttle::LOGIN, &email).await?;
    let secret = Zeroizing::new(body.password);
    let Some(account) = app.store.account_by_email(email.clone()).await? else {
        password::verify_absent(&secret);
        return Err(Error::Unauthorized);
    };
    if account.status != "active" || !password::verify(&secret, &account.password_hash) {
        return Err(Error::Unauthorized);
    }
    app.store.clear_attempts(throttle::LOGIN, email).await?;
    mint_session(&app, &account, body.otp_proof.as_deref()).await
}

/// The one place a sign-in mints a session.
///
/// Every route that hands out a bearer token goes through here, and the second-factor check is
/// inside it. That is the whole design: a new sign-in route cannot forget the check, because it
/// cannot mint a session without asking this function, and this function has no way to skip it.
/// The GitHub device flow arrives the same way, which matters most there — an external service's
/// answer is the input, and that is where a forgotten check usually lives.
pub(crate) async fn mint_session(
    app: &App,
    account: &Account,
    otp_proof: Option<&str>,
) -> Result<Json<LoginResp>> {
    secondfactor::check_second_factor(app, (&account.email, account.mfa_required), otp_proof)?;
    let now = now_unix();
    let issued = session::mint(now, app.session_ttl_secs);
    app.store
        .insert_session(
            issued.token_hash,
            account.id.clone(),
            now,
            issued.expires_at,
        )
        .await?;
    Ok(Json(LoginResp {
        token: issued.token,
        account_id: account.id.clone(),
        expires_at: issued.expires_at,
    }))
}

/// Revoke the presenting session.
pub async fn logout(State(app): State<Arc<App>>, caller: Principal) -> Result<StatusCode> {
    app.store
        .revoke_session(caller.token_hash, now_unix())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Report the caller's own account.
pub async fn me(caller: Principal) -> Json<MeResp> {
    Json(MeResp {
        account_id: caller.account_id,
        email: caller.email,
        mfa_required: caller.mfa_required,
    })
}

/// Change the caller's password, revoking every session including this one.
///
/// Revoking all sessions is the point: a password change is what a user does after
/// suspecting compromise, so leaving other sessions live would defeat it.
pub async fn passwd(
    State(app): State<Arc<App>>,
    caller: Principal,
    Json(body): Json<PasswdReq>,
) -> Result<StatusCode> {
    let current = Zeroizing::new(body.current_password);
    let fresh = Zeroizing::new(body.new_password);
    validate::check_password(&fresh).map_err(Error::BadRequest)?;
    let account = app
        .store
        .account_by_id(caller.account_id.clone())
        .await?
        .ok_or(Error::Unauthorized)?;
    if !password::verify(&current, &account.password_hash) {
        return Err(Error::Unauthorized);
    }
    let hash = password::hash(&fresh).map_err(Error::Internal)?;
    app.store
        .set_password_hash(account.id.clone(), hash)
        .await?;
    app.store
        .revoke_account_sessions(account.id, now_unix())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
