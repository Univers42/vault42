/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   e2e_github.rs                                        :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The GitHub device-flow battery, driven against a stub standing in for github.com.
//!
//! This is the route where a forgotten check usually lives, because an external service's answer
//! is the input and it is tempting to treat "GitHub said yes" as the whole decision. So the stub
//! is deliberately hostile: it can approve a sign-in for an address the signer never proved they
//! own, for an address with no account here, and for an account that requires a second factor.
//! Each of those must be refused, and none of them is refused by anything GitHub does.
//!
//! The two base URLs exist for exactly this. They default to the real hosts, so an unset variable
//! can never point sign-in somewhere unexpected, and an override is what lets the battery attack
//! the route at all.

use crate::app::App;
use crate::config::GithubConfig;
use crate::e2e::{fresh_app, post, send, signed_up};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post as post_route};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::sync::Arc;

/// What the stub GitHub should answer with.
#[derive(Clone)]
struct Stub {
    token_answer: Value,
    emails: Value,
}

/// Start a stub GitHub on a loopback port and return its base URL and a shutdown handle.
///
/// A real socket rather than an in-process seam, because the thing under test is an outbound HTTP
/// call: replacing it with a function call would test a different program.
async fn stub_github(stub: Stub) -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route(
            "/login/device/code",
            post_route(|| async {
                Json(json!({
                    "device_code": "dev-code-1",
                    "user_code": "WXYZ-1234",
                    "verification_uri": "https://github.com/login/device",
                    "expires_in": 900,
                    "interval": 5
                }))
            }),
        )
        .route(
            "/login/oauth/access_token",
            post_route(|State(s): State<Stub>| async move { Json(s.token_answer.clone()) }),
        )
        .route(
            "/user/emails",
            get(|State(s): State<Stub>| async move { Json(s.emails.clone()) }),
        )
        .with_state(stub);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stub");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (base, handle)
}

/// An app pointed at `base` for both GitHub endpoints, with a configured client id.
fn pointed_at(app: &Arc<App>, base: &str) -> Arc<App> {
    Arc::new(App {
        store: app.store.clone(),
        authority: vault42_contract::authority::Authority::open(
            None,
            &format!("{}/gh.key", std::env::temp_dir().display()),
            365,
        )
        .expect("authority"),
        session_ttl_secs: app.session_ttl_secs,
        register_token: None,
        otp: crate::config::OtpConfig {
            proof_secret: app.otp.proof_secret.clone(),
            ttl_secs: app.otp.ttl_secs,
            proof_ttl_secs: app.otp.proof_ttl_secs,
        },
        mail: crate::config::MailConfig {
            transport: crate::config::MailTransport::File(
                std::env::temp_dir().join("gh-outbox").display().to_string(),
            ),
            from: "devfast@archicode.codes".into(),
            host: String::new(),
            port: 0,
            password: None,
        },
        github: GithubConfig {
            client_id: Some("stub-client-id".into()),
            oauth_base: base.to_string(),
            api_base: base.to_string(),
        },
    })
}

/// A token answer that approves the sign-in.
fn approved() -> Value {
    json!({"access_token": "gho_stub_token"})
}

/// Drive one poll against the app and return its status and body.
async fn poll(app: &Arc<App>) -> (StatusCode, Value) {
    send(
        app,
        post(
            "/v1/github/device/poll",
            json!({"device_code": "dev-code-1"}),
        ),
    )
    .await
}

/// A deployment with no GitHub app says so, rather than 404.
///
/// The route existing and the feature being configured are different questions, and a 404 makes
/// them look identical to a client that is about to poll for fifteen minutes.
#[tokio::test]
async fn an_unconfigured_deployment_says_so() {
    let app = fresh_app("p5-gh-unset", None);
    for (path, body) in [
        ("/v1/github/device/start", json!({})),
        ("/v1/github/device/poll", json!({"device_code": "x"})),
    ] {
        let (status, answer) = send(&app, post(path, body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {answer}");
        assert!(
            answer["error"]
                .as_str()
                .is_some_and(|e| e.contains("not configured")),
            "the refusal must name the cause: {answer}"
        );
    }
}

/// The happy path: an approved grant for a verified address with an account mints a session.
#[tokio::test]
async fn an_approved_grant_for_a_known_verified_address_mints_a_session() {
    let base_app = fresh_app("p5-gh-ok", None);
    let email = "gh1@archicode.codes";
    signed_up(&base_app, email).await;
    let (base, server) = stub_github(Stub {
        token_answer: approved(),
        emails: json!([{"email": email, "verified": true, "primary": true}]),
    })
    .await;
    let app = pointed_at(&base_app, &base);

    let (status, grant) = send(&app, post("/v1/github/device/start", json!({}))).await;
    assert_eq!(status, StatusCode::OK, "{grant}");
    assert_eq!(grant["user_code"], "WXYZ-1234");

    let (status, body) = poll(&app).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["access_token"].as_str().expect("a session token");
    assert!(!token.is_empty());
    assert_ne!(
        token, "gho_stub_token",
        "the GitHub token must never be handed to the client"
    );

    let (status, me) = send(
        &app,
        crate::e2e::get_with("/v1/auth/me", &format!("Bearer {token}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the minted session works: {me}");
    assert_eq!(me["email"], email);
    server.abort();
}

/// An address GitHub has not verified is never honoured.
///
/// This is the account-takeover shape: anybody can type an address into a GitHub profile, so an
/// unverified one proves nothing about who owns it.
#[tokio::test]
async fn an_unverified_address_is_refused() {
    let base_app = fresh_app("p5-gh-unverified", None);
    let victim = "gh2-victim@archicode.codes";
    signed_up(&base_app, victim).await;
    let (base, server) = stub_github(Stub {
        token_answer: approved(),
        emails: json!([{"email": victim, "verified": false, "primary": true}]),
    })
    .await;
    let app = pointed_at(&base_app, &base);

    let (status, body) = poll(&app).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an unverified address must not sign anybody in: {body}"
    );
    server.abort();
}

/// A verified address with no account here signs nobody in, and creates nothing.
#[tokio::test]
async fn a_github_identity_cannot_create_an_account() {
    let base_app = fresh_app("p5-gh-noaccount", None);
    let (base, server) = stub_github(Stub {
        token_answer: approved(),
        emails: json!([{"email": "stranger@archicode.codes", "verified": true, "primary": true}]),
    })
    .await;
    let app = pointed_at(&base_app, &base);

    let (status, body) = poll(&app).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let (status, _) = send(
        &app,
        post(
            "/v1/auth/login",
            json!({"email": "stranger@archicode.codes", "password": crate::e2e::PASSWORD}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "and no account was created behind it"
    );
    server.abort();
}

/// An account that requires a second factor is not signed in by GitHub alone.
///
/// The check is not in this route; it is in the one function that mints sessions. This asserts the
/// behaviour that construction is meant to guarantee, because "GitHub approved it" is exactly the
/// answer that tempts an implementation to skip everything else.
#[tokio::test]
async fn github_alone_does_not_satisfy_a_required_second_factor() {
    let tag = "p5-gh-mfa";
    let base_app = fresh_app(tag, None);
    let email = "gh3@archicode.codes";
    let token = signed_up(&base_app, email).await;
    let proof = crate::e2e_secondfactor::proof_for(
        &base_app,
        email,
        &crate::e2e_secondfactor::code_for(&base_app, tag, email).await,
    )
    .await;
    let (status, body) = send(
        &base_app,
        crate::e2e::post_as(
            "/v1/auth/mfa",
            &token,
            json!({"required": true, "proof": proof}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let (base, server) = stub_github(Stub {
        token_answer: approved(),
        emails: json!([{"email": email, "verified": true, "primary": true}]),
    })
    .await;
    let app = pointed_at(&base_app, &base);
    let (status, body) = poll(&app).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a required second factor must survive a GitHub sign-in: {body}"
    );
    server.abort();
}

/// A grant nobody has approved yet keeps the client polling; a dead one stops it.
#[tokio::test]
async fn pending_keeps_polling_and_a_dead_grant_stops() {
    let base_app = fresh_app("p5-gh-pending", None);
    let (base, server) = stub_github(Stub {
        token_answer: json!({"error": "authorization_pending"}),
        emails: json!([]),
    })
    .await;
    let app = pointed_at(&base_app, &base);
    let (status, body) = poll(&app).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body["access_token"].is_null(),
        "pending is a null token, not an error: {body}"
    );
    server.abort();

    let (base, server) = stub_github(Stub {
        token_answer: json!({"error": "expired_token"}),
        emails: json!([]),
    })
    .await;
    let app = pointed_at(&base_app, &base);
    let (status, _) = poll(&app).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a dead grant must end the flow rather than poll forever"
    );
    server.abort();
}

/// The primary verified address wins over other verified ones, and unverified ones are invisible.
#[tokio::test]
async fn the_primary_verified_address_is_the_one_used() {
    let base_app = fresh_app("p5-gh-primary", None);
    let primary = "gh4-primary@archicode.codes";
    signed_up(&base_app, primary).await;
    let (base, server) = stub_github(Stub {
        token_answer: approved(),
        emails: json!([
            {"email": "gh4-other@archicode.codes", "verified": true, "primary": false},
            {"email": "gh4-fake@archicode.codes", "verified": false, "primary": true},
            {"email": primary, "verified": true, "primary": true},
        ]),
    })
    .await;
    let app = pointed_at(&base_app, &base);
    let (status, body) = poll(&app).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["access_token"].as_str().expect("token");
    let (_, me) = send(
        &app,
        crate::e2e::get_with("/v1/auth/me", &format!("Bearer {token}")),
    )
    .await;
    assert_eq!(me["email"], primary);
    server.abort();
}
