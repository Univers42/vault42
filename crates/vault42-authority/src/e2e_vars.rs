/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   e2e_vars.rs                                          :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The variable battery: three-level precedence, and grant-based write authorization.
//!
//! Two things earn this gate. Precedence must be a property of the data, so a key set at
//! several levels resolves to the most specific one and says which level supplied it. And a
//! grant must actually decide something: a plain organization member with a `write` grant can
//! write, the same member with only `read` cannot, and neither is an administrator. Until that
//! holds, grants are bookkeeping rather than authorization.

use crate::e2e::{fresh_app, get_with, post_as, send, signed_up};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;

/// A PUT carrying a bearer token and a JSON body.
fn put_as(path: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(path)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .expect("request")
}

/// A DELETE carrying a bearer token.
fn delete_as(path: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request")
}

/// Found an org with a project and an environment; return `(token, org, project, account_id)`.
async fn scaffold(
    app: &Arc<crate::app::App>,
    email: &str,
    slug: &str,
) -> (String, String, String, String) {
    let token = signed_up(app, email).await;
    let (status, org) = send(
        app,
        post_as("/v1/orgs", &token, json!({"slug": slug, "name": "Co"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{org}");
    let (status, proj) = send(
        app,
        post_as(
            &format!("/v1/orgs/{slug}/projects"),
            &token,
            json!({"slug": "app", "name": "App"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{proj}");
    let project = proj["id"].as_str().unwrap().to_string();
    let (status, _) = send(
        app,
        post_as(
            &format!("/v1/projects/{project}/environments"),
            &token,
            json!({"name": "prod"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, me) = send(app, get_with("/v1/auth/me", &format!("Bearer {token}"))).await;
    let account_id = me["account_id"].as_str().unwrap().to_string();
    (token, slug.to_string(), project, account_id)
}

/// Invite `email` into `org` as a plain member and return `(token, account_id)`.
async fn member(app: &Arc<crate::app::App>, admin: (&str, &str), email: &str) -> (String, String) {
    let (org, admin_token) = admin;
    let token = signed_up(app, email).await;
    let (_, invite) = send(
        app,
        post_as(
            &format!("/v1/orgs/{org}/invites"),
            admin_token,
            json!({"email": email, "role": "member"}),
        ),
    )
    .await;
    let accept = invite["token"].as_str().unwrap().to_string();
    let (status, _) = send(
        app,
        post_as("/v1/invites/accept", &token, json!({"token": accept})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, me) = send(app, get_with("/v1/auth/me", &format!("Bearer {token}"))).await;
    let account_id = me["account_id"].as_str().unwrap().to_string();
    (token, account_id)
}

#[tokio::test]
async fn the_most_specific_scope_wins_and_says_which_it_was() {
    let app = fresh_app("v4-precedence", None);
    let (token, org, project, _) = scaffold(&app, "v1@archicode.codes", "precco").await;

    for (path, value) in [
        (format!("/v1/orgs/{org}/variables/SHARED"), "from-org"),
        (
            format!("/v1/projects/{project}/variables/SHARED"),
            "from-project",
        ),
        (
            format!("/v1/projects/{project}/environments/prod/variables/SHARED"),
            "from-env",
        ),
        (format!("/v1/orgs/{org}/variables/ORG_ONLY"), "org-only"),
        (
            format!("/v1/projects/{project}/variables/PROJ_ONLY"),
            "proj-only",
        ),
    ] {
        let (status, body) = send(&app, put_as(&path, &token, json!({"value": value}))).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{path} -> {body}");
    }

    let resolve = format!("/v1/projects/{project}/environments/prod/resolve");
    let (status, body) = send(&app, get_with(&resolve, &format!("Bearer {token}"))).await;
    assert_eq!(status, StatusCode::OK);
    let rows = body.as_array().unwrap();
    assert_eq!(rows.len(), 3, "one row per distinct key: {body}");
    let find = |key: &str| {
        rows.iter()
            .find(|r| r["key"] == key)
            .expect("key present")
            .clone()
    };
    assert_eq!(find("SHARED")["value"], "from-env");
    assert_eq!(find("SHARED")["scope_kind"], "env");
    assert_eq!(find("PROJ_ONLY")["scope_kind"], "project");
    assert_eq!(find("ORG_ONLY")["scope_kind"], "org");
}

#[tokio::test]
async fn deleting_the_specific_value_falls_back_to_the_next_level() {
    let app = fresh_app("v4-fallback", None);
    let (token, org, project, _) = scaffold(&app, "v2@archicode.codes", "fallco").await;
    send(
        &app,
        put_as(
            &format!("/v1/orgs/{org}/variables/K"),
            &token,
            json!({"value": "org"}),
        ),
    )
    .await;
    let env_path = format!("/v1/projects/{project}/environments/prod/variables/K");
    send(&app, put_as(&env_path, &token, json!({"value": "env"}))).await;

    let resolve = format!("/v1/projects/{project}/environments/prod/resolve");
    let (_, body) = send(&app, get_with(&resolve, &format!("Bearer {token}"))).await;
    assert_eq!(body[0]["value"], "env");

    let (status, _) = send(&app, delete_as(&env_path, &token)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, body) = send(&app, get_with(&resolve, &format!("Bearer {token}"))).await;
    assert_eq!(body[0]["value"], "org", "the org value must resurface");
    assert_eq!(body[0]["scope_kind"], "org");

    let (status, _) = send(&app, delete_as(&env_path, &token)).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "deleting an absent key is not an error"
    );
}

#[tokio::test]
async fn a_write_grant_lets_a_plain_member_write_and_a_read_grant_does_not() {
    let app = fresh_app("v4-rbac", None);
    let (owner, org, project, _) = scaffold(&app, "v3@archicode.codes", "rbacco").await;
    let (bob, bob_id) = member(&app, (&org, &owner), "bob-v3@archicode.codes").await;
    let env_path = format!("/v1/projects/{project}/environments/prod/variables/DB_URL");

    let (status, body) = send(&app, put_as(&env_path, &bob, json!({"value": "x"}))).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a member with no grant must not write: {body}"
    );

    let grants = format!("/v1/orgs/{org}/projects/{project}/grants");
    let (status, body) = send(
        &app,
        post_as(
            &grants,
            &owner,
            json!({"grantee_kind": "user", "grantee_id": bob_id, "project_role": "read"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, _) = send(&app, put_as(&env_path, &bob, json!({"value": "x"}))).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read grant must not permit a write"
    );

    let (status, body) = send(
        &app,
        post_as(
            &grants,
            &owner,
            json!({"grantee_kind": "user", "grantee_id": bob_id, "project_role": "write"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = send(
        &app,
        put_as(&env_path, &bob, json!({"value": "sealed-blob"})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "a write grant must permit it: {body}"
    );

    let (_, body) = send(
        &app,
        get_with(
            &format!("/v1/projects/{project}/environments/prod/variables"),
            &format!("Bearer {bob}"),
        ),
    )
    .await;
    assert_eq!(
        body[0]["value"], "sealed-blob",
        "stored verbatim, never interpreted"
    );
}

#[tokio::test]
async fn a_write_grant_reaching_through_a_team_also_permits_a_write() {
    let app = fresh_app("v4-teamgrant", None);
    let (owner, org, project, _) = scaffold(&app, "v4@archicode.codes", "teamgrantco").await;
    let (bob, bob_id) = member(&app, (&org, &owner), "bob-v4@archicode.codes").await;
    let (_, team) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/teams"),
            &owner,
            json!({"slug": "devs", "name": "Devs"}),
        ),
    )
    .await;
    let team_id = team["id"].as_str().unwrap().to_string();
    send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/teams/devs/members"),
            &owner,
            json!({"user_id": bob_id}),
        ),
    )
    .await;

    let grants = format!("/v1/orgs/{org}/projects/{project}/grants");
    let (status, body) = send(
        &app,
        post_as(
            &grants,
            &owner,
            json!({"grantee_kind": "team", "grantee_id": team_id, "project_role": "write"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let path = format!("/v1/projects/{project}/environments/prod/variables/VIA_TEAM");
    let (status, body) = send(&app, put_as(&path, &bob, json!({"value": "ok"}))).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "a team grant must reach its members: {body}"
    );
}

#[tokio::test]
async fn writing_an_org_variable_stays_administrator_only() {
    let app = fresh_app("v4-orgadmin", None);
    let (owner, org, project, _) = scaffold(&app, "v5@archicode.codes", "orgadminco").await;
    let (bob, bob_id) = member(&app, (&org, &owner), "bob-v5@archicode.codes").await;
    let grants = format!("/v1/orgs/{org}/projects/{project}/grants");
    send(
        &app,
        post_as(
            &grants,
            &owner,
            json!({"grantee_kind": "user", "grantee_id": bob_id, "project_role": "admin"}),
        ),
    )
    .await;

    let (status, _) = send(
        &app,
        put_as(
            &format!("/v1/orgs/{org}/variables/GLOBAL"),
            &bob,
            json!({"value": "x"}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a project-admin grant must not confer organization-level writes"
    );
}

#[tokio::test]
async fn keys_and_values_are_validated_at_the_boundary() {
    let app = fresh_app("v4-validate", None);
    let (token, org, _, _) = scaffold(&app, "v6@archicode.codes", "validco").await;
    // "has%20space" is percent-encoded so the URI is constructible and the SERVER sees the
    // space after decoding; a raw space would fail in the client builder and prove nothing.
    for bad in ["", "has-dash", "has%20space", "1LEADING", "has.dot"] {
        let (status, _) = send(
            &app,
            put_as(
                &format!("/v1/orgs/{org}/variables/{bad}"),
                &token,
                json!({"value": "x"}),
            ),
        )
        .await;
        assert_ne!(
            status,
            StatusCode::NO_CONTENT,
            "key {bad:?} must be refused"
        );
    }
    for good in ["OK", "_UNDER", "A1", "lower_case"] {
        let (status, _) = send(
            &app,
            put_as(
                &format!("/v1/orgs/{org}/variables/{good}"),
                &token,
                json!({"value": "x"}),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NO_CONTENT,
            "key {good:?} must be accepted"
        );
    }
    let oversized = "v".repeat((1 << 20) + 1);
    let (status, _) = send(
        &app,
        put_as(
            &format!("/v1/orgs/{org}/variables/BIG"),
            &token,
            json!({"value": oversized}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a value over the bound must be refused"
    );
}

/// Seal a payload to a throwaway scope key and return base64 of the opaque wire bytes, exactly
/// as a client stores a secret variable.
fn sealed_value() -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    let (keyset, _secret) = vault42_core::generate_keyset([8u8; 16], 1);
    let author = vault42_core::Identity::generate();
    let recipients = vault42_core::scope_recipients(&keyset, None);
    let envelope = vault42_core::seal(
        b"TOPSECRET=value",
        vault42_core::Metadata {
            version: 2,
            secret_id: "var".into(),
            tenant: "self".into(),
            owner: "scope:env".into(),
            rev: 1,
            content_type: "env".into(),
            recovery_optin: false,
            project_id: "p".into(),
            relative_path: String::new(),
            kind: vault42_core::Kind::Generic,
            mode: vault42_core::DEFAULT_MODE,
        },
        &recipients,
        author.signing_key(),
    )
    .expect("seal");
    STANDARD.encode(envelope.to_bytes().expect("encode"))
}

/// A secret variable round-trips byte-for-byte, and a value merely LABELLED secret is refused.
///
/// `is_secret` names a property rather than decorating a row. In a vault that claims the server
/// cannot read what it holds, a flag by that name on a value the server can read is the one thing
/// an operator would trust without checking, so storing plaintext under it is refused outright.
/// The authority still never opens the envelope — parsing its structure is what proves it sealed.
#[tokio::test]
async fn is_secret_round_trips_and_refuses_a_value_that_is_not_sealed() {
    let app = fresh_app("v4-secret", None);
    let (token, org, _, _) = scaffold(&app, "v7@archicode.codes", "secretco").await;
    send(
        &app,
        put_as(
            &format!("/v1/orgs/{org}/variables/PLAIN"),
            &token,
            json!({"value": "visible"}),
        ),
    )
    .await;
    for pretender in ["hunter2", "AAAAsealed"] {
        let (status, body) = send(
            &app,
            put_as(
                &format!("/v1/orgs/{org}/variables/FAKE"),
                &token,
                json!({"value": pretender, "is_secret": true}),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{pretender:?} must not be storable as a secret: {body}"
        );
    }
    let blob = sealed_value();
    let (status, body) = send(
        &app,
        put_as(
            &format!("/v1/orgs/{org}/variables/SEALED"),
            &token,
            json!({"value": blob, "is_secret": true}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let (status, body) = send(
        &app,
        get_with(
            &format!("/v1/orgs/{org}/variables"),
            &format!("Bearer {token}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let rows = body.as_array().unwrap();
    let plain = rows.iter().find(|r| r["key"] == "PLAIN").unwrap();
    let sealed = rows.iter().find(|r| r["key"] == "SEALED").unwrap();
    assert!(
        !rows.iter().any(|r| r["key"] == "FAKE"),
        "the refused value was never stored: {body}"
    );
    assert_eq!(plain["is_secret"], false);
    assert_eq!(sealed["is_secret"], true);
    assert_eq!(
        sealed["value"], blob,
        "the blob is returned exactly as stored"
    );
}

#[tokio::test]
async fn an_outsider_cannot_read_or_write_any_scope() {
    let app = fresh_app("v4-outsider", None);
    let (owner, org, project, _) = scaffold(&app, "v8@archicode.codes", "outco").await;
    let outsider = signed_up(&app, "out-v8@archicode.codes").await;
    send(
        &app,
        put_as(
            &format!("/v1/orgs/{org}/variables/K"),
            &owner,
            json!({"value": "v"}),
        ),
    )
    .await;

    for path in [
        format!("/v1/orgs/{org}/variables"),
        format!("/v1/projects/{project}/variables"),
        format!("/v1/projects/{project}/environments/prod/variables"),
        format!("/v1/projects/{project}/environments/prod/resolve"),
    ] {
        let (status, _) = send(&app, get_with(&path, &format!("Bearer {outsider}"))).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{path} must not be readable by an outsider"
        );
    }
    let (status, _) = send(
        &app,
        put_as(
            &format!("/v1/orgs/{org}/variables/K"),
            &outsider,
            json!({"value": "x"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
