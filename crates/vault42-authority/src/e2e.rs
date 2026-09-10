/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   e2e.rs                                               :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The authority's in-process route battery.
//!
//! Every test drives the real router over a real temporary SQLite database, so it proves
//! the wiring a unit test cannot: extractor order, status codes, the Bearer guard, and the
//! database constraints. It runs in-process via `oneshot`, so there is no port to allocate
//! and no server to tear down.
//!
//! The security assertions are the point of this file. A token must stop working after
//! logout and after a password change; an unknown email and a wrong password must be
//! indistinguishable; a tenant name must not be stealable; and a wrong invite token must
//! not register.

use crate::app::App;
use crate::routes::router;
use crate::store::Store;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;
use vault42_contract::authority::Authority;
use vault42_contract::signing::now_unix;

/// A credible password that clears the length rule.
pub(crate) const PASSWORD: &str = "correct horse battery staple";

/// The proof secret every test app signs one-time-code proofs with.
///
/// Present in every test app so second factors are configured, and the battery therefore never
/// exercises the unconfigured path by accident while thinking it tested the configured one.
pub(crate) const PROOF_SECRET: &str = "test-otp-proof-secret";

/// Where a test app's mail lands, derived from its tag so a test can read its own outbox.
pub(crate) fn outbox_dir(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("v42-outbox-{}-{tag}", std::process::id()))
}

/// Build an app over a fresh temporary database, optionally behind an invite token.
///
/// Mail goes to the file transport in this app's own outbox, which is the same seam an operator
/// gets with `MAIL_TRANSPORT=file`. Nothing here is test-only: a battery driving a live authority
/// over HTTP reads codes exactly the same way.
pub(crate) fn fresh_app(tag: &str, register_token: Option<&str>) -> Arc<App> {
    let base = std::env::temp_dir().join(format!("v42-auth-{}-{tag}", std::process::id()));
    let db = format!("{}.db", base.display());
    let key = format!("{}.key", base.display());
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{db}{suffix}"));
    }
    let _ = std::fs::remove_file(&key);
    let outbox = outbox_dir(tag);
    let _ = std::fs::remove_dir_all(&outbox);
    Arc::new(App {
        store: Store::open(&db, now_unix()).expect("open store"),
        authority: Authority::open(None, &key, 365).expect("load authority"),
        session_ttl_secs: 3600,
        register_token: register_token.map(str::to_string),
        otp: crate::config::OtpConfig {
            proof_secret: Some(PROOF_SECRET.as_bytes().to_vec()),
            ttl_secs: 300,
            proof_ttl_secs: 600,
        },
        github: crate::config::GithubConfig {
            client_id: None,
            oauth_base: "http://127.0.0.1:1".into(),
            api_base: "http://127.0.0.1:1".into(),
        },
        mail: crate::config::MailConfig {
            transport: crate::config::MailTransport::File(outbox.display().to_string()),
            from: "devfast@archicode.codes".into(),
            host: String::new(),
            port: 0,
            password: None,
        },
    })
}

/// Drive one request through the real router and decode the response.
pub(crate) async fn send(app: &Arc<App>, request: Request<Body>) -> (StatusCode, Value) {
    let response = router(app.clone()).oneshot(request).await.expect("route");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// A JSON POST with no credentials.
pub(crate) fn post(path: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request")
}

/// A JSON POST carrying a bearer token.
pub(crate) fn post_as(path: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .expect("request")
}

/// A GET carrying a raw Authorization header value.
pub(crate) fn get_with(path: &str, authorization: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .header("authorization", authorization)
        .body(Body::empty())
        .expect("request")
}

/// Register an account and return a live session token.
pub(crate) async fn signed_up(app: &Arc<App>, email: &str) -> String {
    let (status, _) = send(
        app,
        post(
            "/v1/auth/signup",
            json!({"email": email, "password": PASSWORD}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "signup should succeed");
    let (status, body) = send(
        app,
        post(
            "/v1/auth/login",
            json!({"email": email, "password": PASSWORD}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login should succeed");
    body["token"]
        .as_str()
        .expect("token in login body")
        .to_string()
}

/// A fresh, valid Ed25519 author public key in hex.
pub(crate) fn author_pubkey() -> String {
    hex::encode(
        vault42_core::Identity::generate()
            .author_public()
            .to_bytes(),
    )
}

#[tokio::test]
async fn healthz_and_contract_key_are_public() {
    let app = fresh_app("public", None);
    let request = Request::builder()
        .uri("/healthz")
        .body(Body::empty())
        .unwrap();
    let response = router(app.clone()).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let request = Request::builder()
        .uri("/v1/contract-key")
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(&app, request).await;
    assert_eq!(status, StatusCode::OK);
    let key = body["public_key"].as_str().expect("public_key");
    assert_eq!(key.len(), 64, "an Ed25519 public key is 32 bytes of hex");
    assert!(hex::decode(key).is_ok());
}

#[tokio::test]
async fn signup_then_login_then_me_round_trips() {
    let app = fresh_app("roundtrip", None);
    let token = signed_up(&app, "dev@archicode.codes").await;
    let (status, body) = send(&app, get_with("/v1/auth/me", &format!("Bearer {token}"))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["email"], "dev@archicode.codes");
    assert_eq!(body["mfa_required"], false);
    assert!(body["account_id"].as_str().is_some_and(|id| id.len() == 36));
}

#[tokio::test]
async fn signup_normalizes_email_case_and_refuses_the_duplicate() {
    let app = fresh_app("dup", None);
    let (status, _) = send(
        &app,
        post(
            "/v1/auth/signup",
            json!({"email": "Dev@Archicode.Codes", "password": PASSWORD}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, body) = send(
        &app,
        post(
            "/v1/auth/signup",
            json!({"email": "dev@archicode.codes", "password": PASSWORD}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "case must not create a second account"
    );
    assert_eq!(body["error"], "email already registered");
}

#[tokio::test]
async fn signup_rejects_a_short_password_and_a_junk_email() {
    let app = fresh_app("reject", None);
    let (status, _) = send(
        &app,
        post(
            "/v1/auth/signup",
            json!({"email": "a@b.tld", "password": "short"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = send(
        &app,
        post(
            "/v1/auth/signup",
            json!({"email": "no-at-sign", "password": PASSWORD}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn password_guessing_runs_out_of_attempts() {
    let app = fresh_app("throttle-login", None);
    let _ = signed_up(&app, "guessed@archicode.codes").await;
    let wrong = |n: u32| {
        post(
            "/v1/auth/login",
            json!({"email": "guessed@archicode.codes", "password": format!("wrong-{n}")}),
        )
    };
    let mut seen_401 = 0;
    for n in 0..5 {
        let (status, _) = send(&app, wrong(n)).await;
        if status == StatusCode::UNAUTHORIZED {
            seen_401 += 1;
        }
    }
    assert!(
        seen_401 > 0,
        "positive control: early guesses must be answered 401, or the refusal below says \
         nothing about a limit"
    );
    let (status, _) = send(&app, wrong(99)).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "guessing must run out of attempts"
    );
}

/// While throttled, even the RIGHT password is refused. That is the property — a limit a correct
/// guess walks through is not a limit, and an attacker's last guess is a correct one.
#[tokio::test]
async fn the_correct_password_is_refused_while_throttled() {
    let app = fresh_app("throttle-correct", None);
    let _ = signed_up(&app, "locked@archicode.codes").await;
    for n in 0..6 {
        send(
            &app,
            post(
                "/v1/auth/login",
                json!({"email": "locked@archicode.codes", "password": format!("no-{n}")}),
            ),
        )
        .await;
    }
    let (status, _) = send(
        &app,
        post(
            "/v1/auth/login",
            json!({"email": "locked@archicode.codes", "password": PASSWORD}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "the correct password must not walk through the limit"
    );
}

/// A person who mistypes and then gets it right carries no penalty forward.
#[tokio::test]
async fn a_successful_login_clears_the_penalty() {
    let app = fresh_app("throttle-clears", None);
    let _ = signed_up(&app, "typo@archicode.codes").await;
    for n in 0..3 {
        send(
            &app,
            post(
                "/v1/auth/login",
                json!({"email": "typo@archicode.codes", "password": format!("oops-{n}")}),
            ),
        )
        .await;
    }
    let good = || {
        post(
            "/v1/auth/login",
            json!({"email": "typo@archicode.codes", "password": PASSWORD}),
        )
    };
    let (status, _) = send(&app, good()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "three typos must not lock anybody out"
    );
    for _ in 0..3 {
        let (status, _) = send(&app, good()).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the successful login must have cleared the count, not merely passed it"
        );
    }
}

#[tokio::test]
async fn a_wrong_password_and_an_unknown_email_are_indistinguishable() {
    let app = fresh_app("enumerate", None);
    let _ = signed_up(&app, "real@archicode.codes").await;
    let (wrong_status, wrong_body) = send(
        &app,
        post(
            "/v1/auth/login",
            json!({"email": "real@archicode.codes", "password": "wrong password here"}),
        ),
    )
    .await;
    let (absent_status, absent_body) = send(
        &app,
        post(
            "/v1/auth/login",
            json!({"email": "absent@archicode.codes", "password": "wrong password here"}),
        ),
    )
    .await;
    assert_eq!(wrong_status, StatusCode::UNAUTHORIZED);
    assert_eq!(absent_status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        wrong_body, absent_body,
        "the bodies must not reveal which email exists"
    );
}

#[tokio::test]
async fn me_refuses_every_malformed_or_absent_credential() {
    let app = fresh_app("guard", None);
    let request = Request::builder()
        .uri("/v1/auth/me")
        .body(Body::empty())
        .unwrap();
    let (status, _) = send(&app, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no header at all");
    for header in [
        "",
        "Bearer",
        "Bearer ",
        "Basic abc",
        "Bearer not-a-real-token",
    ] {
        let (status, _) = send(&app, get_with("/v1/auth/me", header)).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "header {header:?} must not authenticate"
        );
    }
}

#[tokio::test]
async fn the_bearer_scheme_is_case_insensitive() {
    let app = fresh_app("scheme", None);
    let token = signed_up(&app, "case@archicode.codes").await;
    for scheme in ["Bearer", "bearer", "BEARER"] {
        let (status, _) = send(&app, get_with("/v1/auth/me", &format!("{scheme} {token}"))).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "scheme {scheme} must be accepted per RFC 7235"
        );
    }
}

#[tokio::test]
async fn logout_revokes_only_the_presenting_token() {
    let app = fresh_app("logout", None);
    let first = signed_up(&app, "two@archicode.codes").await;
    let (status, body) = send(
        &app,
        post(
            "/v1/auth/login",
            json!({"email": "two@archicode.codes", "password": PASSWORD}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let second = body["token"].as_str().unwrap().to_string();

    let (status, _) = send(&app, post_as("/v1/auth/logout", &first, json!({}))).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = send(&app, get_with("/v1/auth/me", &format!("Bearer {first}"))).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the logged-out token must be dead"
    );
    let (status, _) = send(&app, get_with("/v1/auth/me", &format!("Bearer {second}"))).await;
    assert_eq!(status, StatusCode::OK, "the other session must survive");
}

#[tokio::test]
async fn changing_the_password_revokes_every_session_and_rotates_the_credential() {
    let app = fresh_app("passwd", None);
    let token = signed_up(&app, "rotate@archicode.codes").await;
    let fresh = "a brand new passphrase";

    let (status, _) = send(
        &app,
        post_as(
            "/v1/auth/passwd",
            &token,
            json!({"current_password": "not the password", "new_password": fresh}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a wrong current password must not rotate"
    );

    let (status, _) = send(
        &app,
        post_as(
            "/v1/auth/passwd",
            &token,
            json!({"current_password": PASSWORD, "new_password": fresh}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = send(&app, get_with("/v1/auth/me", &format!("Bearer {token}"))).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a password change must kill live sessions"
    );

    let (status, _) = send(
        &app,
        post(
            "/v1/auth/login",
            json!({"email": "rotate@archicode.codes", "password": PASSWORD}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the old password must be dead"
    );
    let (status, _) = send(
        &app,
        post(
            "/v1/auth/login",
            json!({"email": "rotate@archicode.codes", "password": fresh}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the new password must work");
}

#[tokio::test]
async fn passwd_enforces_the_length_rule_on_the_new_password() {
    let app = fresh_app("passwdlen", None);
    let token = signed_up(&app, "len@archicode.codes").await;
    let (status, _) = send(
        &app,
        post_as(
            "/v1/auth/passwd",
            &token,
            json!({"current_password": PASSWORD, "new_password": "tiny"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn register_issues_a_contract_that_verifies_against_the_published_key() {
    let app = fresh_app("register", None);
    let pubkey = author_pubkey();
    let (status, body) = send(
        &app,
        post(
            "/v1/register",
            json!({"tenant": "alice", "author_pubkey": pubkey}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["tenant"], "alice");

    let token = body["contract"].as_str().expect("contract token");
    let key_hex = app.authority.public_hex();
    let key: [u8; 32] = hex::decode(&key_hex).unwrap().try_into().unwrap();
    let contract =
        vault42_core::verify_contract(&key, token, now_unix()).expect("contract verifies");
    assert_eq!(contract.tenant, "alice");
    let expected_fp = vault42_core::fingerprint(&hex::decode(&pubkey).unwrap().try_into().unwrap());
    assert_eq!(
        contract.author_fp, expected_fp,
        "the contract must bind the presented key"
    );
    assert!(contract.expires_at > now_unix());
}

#[tokio::test]
async fn re_registering_the_same_key_is_idempotent_but_a_different_key_cannot_steal() {
    let app = fresh_app("steal", None);
    let mine = author_pubkey();
    let theirs = author_pubkey();
    let (status, _) = send(
        &app,
        post(
            "/v1/register",
            json!({"tenant": "acme", "author_pubkey": mine}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(
        &app,
        post(
            "/v1/register",
            json!({"tenant": "acme", "author_pubkey": mine}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the same key may refresh its contract"
    );
    let (status, body) = send(
        &app,
        post(
            "/v1/register",
            json!({"tenant": "acme", "author_pubkey": theirs}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a different key must not take the name"
    );
    assert_eq!(body["error"], "tenant name is taken");
}

#[tokio::test]
async fn register_validates_the_tenant_name_and_the_author_key() {
    let app = fresh_app("regvalidate", None);
    let pubkey = author_pubkey();
    for tenant in ["", "has space", "has/slash", &"x".repeat(65)] {
        let (status, _) = send(
            &app,
            post(
                "/v1/register",
                json!({"tenant": tenant, "author_pubkey": pubkey}),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "tenant {tenant:?} must be refused"
        );
    }
    for key in ["", "nothex", &"aa".repeat(31), &"00".repeat(32)] {
        let (status, _) = send(
            &app,
            post(
                "/v1/register",
                json!({"tenant": "ok", "author_pubkey": key}),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "author_pubkey {key:?} must be refused"
        );
    }
}

#[tokio::test]
async fn the_invite_gate_admits_only_the_configured_token() {
    let app = fresh_app("invite", Some("s3cret-invite"));
    let pubkey = author_pubkey();
    let (status, _) = send(
        &app,
        post(
            "/v1/register",
            json!({"tenant": "gated", "author_pubkey": pubkey}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a missing token must be refused"
    );
    let (status, _) = send(
        &app,
        post(
            "/v1/register",
            json!({"tenant": "gated", "author_pubkey": pubkey, "token": "wrong"}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a wrong token must be refused"
    );
    let (status, _) = send(
        &app,
        post(
            "/v1/register",
            json!({"tenant": "gated", "author_pubkey": pubkey, "token": "s3cret-invite"}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the configured token must be admitted"
    );
}
