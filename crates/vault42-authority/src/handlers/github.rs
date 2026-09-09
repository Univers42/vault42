/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   github.rs                                            :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! GitHub device-flow sign-in.
//!
//! No browser callback and no client secret on the operator's machine: the CLI asks for a device
//! code, shows the person a URL and a short code, and polls until GitHub says they approved it.
//! The authority does the token exchange, reads the account's verified address, and mints a
//! session. The GitHub access token is used once, in that exchange, and never stored or returned.
//!
//! Three rules carry the security of this route, and each is a way people lose accounts.
//!
//! The address must be one GitHub says is verified. An unverified address is one anybody can
//! claim, so trusting it would mean typing somebody else's address into a GitHub profile and
//! being handed their vault. Only `verified` addresses are considered, and the primary one is
//! preferred over the rest.
//!
//! A session comes from `mint_session` and from nowhere else, so an account requiring a second
//! factor still requires it here. This is the path where a forgotten check usually lives, because
//! an external service's answer is the input and it is tempting to treat "GitHub said yes" as the
//! whole decision.
//!
//! Signing in this way never creates an account. The person must already have one with that
//! address, so a GitHub identity cannot mint a vault account nobody invited.

use crate::app::App;
use crate::auth::handlers::mint_session;
use crate::error::{Error, Result};
use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

/// How long the authority waits on GitHub before giving up on one call.
const GITHUB_TIMEOUT: Duration = Duration::from_secs(10);

/// The scope needed to read the signer's addresses, and nothing more.
const SCOPE: &str = "read:user user:email";

/// Poll request body.
#[derive(Deserialize)]
pub struct PollReq {
    device_code: String,
}

/// The device grant, passed through to the caller as GitHub issued it.
#[derive(Serialize, Deserialize)]
pub struct DeviceStart {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: i64,
    pub interval: i64,
}

/// A poll answer. `access_token` is null while the person has not approved yet.
///
/// The name is the client's, and it is a session token for this authority rather than a GitHub
/// token: the GitHub one never leaves the exchange.
#[derive(Serialize)]
pub struct PollResp {
    access_token: Option<String>,
}

/// What GitHub returns from the token exchange: either a token or a reason it is not ready.
#[derive(Deserialize)]
struct TokenResp {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// One address on a GitHub account.
#[derive(Deserialize)]
struct GithubEmail {
    email: String,
    verified: bool,
    #[serde(default)]
    primary: bool,
}

/// Begin the device flow.
pub async fn start(State(app): State<Arc<App>>) -> Result<Json<DeviceStart>> {
    let client_id = configured(&app)?;
    let grant: DeviceStart = github_form(
        &format!("{}/login/device/code", app.github.oauth_base),
        &[("client_id", client_id), ("scope", SCOPE)],
    )
    .await?;
    Ok(Json(grant))
}

/// Poll once. `null` while pending; a session token once the person has approved.
pub async fn poll(
    State(app): State<Arc<App>>,
    Json(body): Json<PollReq>,
) -> Result<Json<PollResp>> {
    let client_id = configured(&app)?;
    let exchanged: TokenResp = github_form(
        &format!("{}/login/oauth/access_token", app.github.oauth_base),
        &[
            ("client_id", client_id),
            ("device_code", &body.device_code),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ],
    )
    .await?;
    let Some(token) = exchanged.access_token else {
        return pending_or_refused(exchanged.error.as_deref());
    };
    let email = verified_address(&app, &token).await?;
    let account = app
        .store
        .account_by_email(email)
        .await?
        .ok_or(Error::Unauthorized)?;
    if account.status != "active" {
        return Err(Error::Unauthorized);
    }
    let session = mint_session(&app, &account, None).await?;
    Ok(Json(PollResp {
        access_token: Some(session.0.token.clone()),
    }))
}

/// Report a still-pending grant as pending, and anything else as a refusal.
///
/// `authorization_pending` and `slow_down` mean "keep polling" and are the normal case. Every
/// other error — an expired grant, a denied request, an unknown device code — ends the flow, and
/// answering "pending" to those would leave the CLI polling a grant that will never come.
fn pending_or_refused(error: Option<&str>) -> Result<Json<PollResp>> {
    match error {
        Some("authorization_pending") | Some("slow_down") => {
            Ok(Json(PollResp { access_token: None }))
        }
        _ => Err(Error::Unauthorized),
    }
}

/// The address GitHub confirms belongs to the signer, preferring their primary one.
///
/// Unverified addresses are ignored entirely. An unverified address is one anybody can type into
/// a profile, so honouring it would let somebody claim an address they do not control and be
/// handed the account that holds it here.
async fn verified_address(app: &App, token: &str) -> Result<String> {
    let addresses: Vec<GithubEmail> =
        github_get(&format!("{}/user/emails", app.github.api_base), token).await?;
    let usable: Vec<&GithubEmail> = addresses.iter().filter(|entry| entry.verified).collect();
    let chosen = usable
        .iter()
        .find(|entry| entry.primary)
        .or_else(|| usable.first())
        .ok_or_else(|| Error::BadRequest("no verified address on this GitHub account".into()))?;
    crate::validate::normalize_email(&chosen.email).map_err(Error::BadRequest)
}

/// The configured client id, or a named refusal.
///
/// A deployment with no GitHub app should say so rather than 404, because the route existing and
/// the feature being configured are different questions and the client cannot tell them apart.
fn configured(app: &App) -> Result<&str> {
    app.github
        .client_id
        .as_deref()
        .filter(|id| !id.is_empty())
        .ok_or_else(|| Error::BadRequest("GitHub sign-in is not configured here".into()))
}

/// POST a form to GitHub and decode its JSON answer.
fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(GITHUB_TIMEOUT)
        .build()
        .map_err(|e| Error::Internal(e.into()))
}

/// POST an OAuth form, asking for JSON rather than GitHub's default form encoding.
async fn github_form<T: serde::de::DeserializeOwned>(
    url: &str,
    form: &[(&str, &str)],
) -> Result<T> {
    let response = client()?
        .post(url)
        .header("accept", "application/json")
        .form(form)
        .send()
        .await
        .map_err(|_| Error::BadRequest("GitHub could not be reached".into()))?;
    response
        .json::<T>()
        .await
        .map_err(|_| Error::BadRequest("GitHub returned something unexpected".into()))
}

/// GET a GitHub API resource with a bearer token.
async fn github_get<T: serde::de::DeserializeOwned>(url: &str, token: &str) -> Result<T> {
    let response = client()?
        .get(url)
        .header("accept", "application/vnd.github+json")
        .header("user-agent", "vault42-authority")
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| Error::BadRequest("GitHub could not be reached".into()))?;
    response
        .json::<T>()
        .await
        .map_err(|_| Error::BadRequest("GitHub returned something unexpected".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only a still-pending grant keeps the client polling; everything else ends the flow.
    #[test]
    fn only_a_pending_grant_keeps_the_client_polling() {
        for waiting in ["authorization_pending", "slow_down"] {
            let answer = pending_or_refused(Some(waiting)).expect("pending is not an error");
            assert!(answer.0.access_token.is_none());
        }
        for over in [
            Some("expired_token"),
            Some("access_denied"),
            Some("incorrect_device_code"),
            None,
        ] {
            assert!(
                pending_or_refused(over).is_err(),
                "{over:?} must end the flow rather than poll forever"
            );
        }
    }
}
