/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   e2e_scope.rs                                         :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The scope-bridge battery: projects, environments, groups, member keys, and grants.
//!
//! The assertions that earn this gate are the ones a structural check cannot make. A proof of
//! possession must bind the organization's canonical id, so a proof signed over the slug is
//! refused. A grant must not name a grantee from another organization or an environment from
//! another project. `missing` must be exactly the authorized set that still lacks a wrap,
//! because the client drives provisioning and rotation from it. And a scope epoch must
//! advance, so a stale client cannot roll an environment back to a key removed members hold.

use crate::e2e::{fresh_app, get_with, post_as, send, signed_up};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use serde_json::{json, Value};
use std::sync::Arc;
use vault42_core::{pop_message, sign_request, Identity};

/// Base64-STANDARD, the encoding the client uses for key material.
fn b64(raw: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(raw)
}

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

/// Sign up, found an org, and return `(token, org_slug, org_id, account_id)`.
pub(crate) async fn founder(
    app: &Arc<crate::app::App>,
    email: &str,
    slug: &str,
) -> (String, String, String, String) {
    let token = signed_up(app, email).await;
    let (status, body) = send(
        app,
        post_as("/v1/orgs", &token, json!({"slug": slug, "name": "Co"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let org_id = body["id"].as_str().unwrap().to_string();
    let (_, me) = send(app, get_with("/v1/auth/me", &format!("Bearer {token}"))).await;
    let account_id = me["account_id"].as_str().unwrap().to_string();
    (token, slug.to_string(), org_id, account_id)
}

/// Build a pubkey registration body, signing the proof over `signed_org`.
fn pubkey_body(identity: &Identity, account_id: &str, signed_org: &str) -> Value {
    let x25519 = b64(&identity.encryption_public().to_bytes());
    let ed25519 = b64(&identity.author_public().to_bytes());
    let sig = sign_request(
        identity.signing_key(),
        &pop_message(account_id, signed_org, &x25519),
    );
    json!({
        "x25519_pub": x25519,
        "ed25519_pub": ed25519,
        "v42_address": "v42:test",
        "pubkey_sig": b64(&sig),
    })
}

/// Create a project in `org` and return its id.
pub(crate) async fn project(
    app: &Arc<crate::app::App>,
    token: &str,
    org: &str,
    slug: &str,
) -> String {
    let (status, body) = send(
        app,
        post_as(
            &format!("/v1/orgs/{org}/projects"),
            token,
            json!({"slug": slug, "name": "Proj"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body["id"].as_str().unwrap().to_string()
}

/// Create an environment under `proj` and return its id.
pub(crate) async fn environment(
    app: &Arc<crate::app::App>,
    token: &str,
    proj: &str,
    name: &str,
) -> String {
    let (status, body) = send(
        app,
        post_as(
            &format!("/v1/projects/{proj}/environments"),
            token,
            json!({"name": name}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn a_project_id_is_a_uuid_and_an_existing_one_can_be_adopted() {
    let app = fresh_app("p3-proj", None);
    let (token, org, _, _) = founder(&app, "p1@archicode.codes", "projco").await;
    let minted = project(&app, &token, &org, "fresh").await;
    assert!(
        uuid::Uuid::parse_str(&minted).is_ok(),
        "the authority must mint a UUID"
    );

    let adopted = uuid::Uuid::new_v4().to_string();
    let (status, body) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/projects"),
            &token,
            json!({"slug": "adopted", "name": "P", "id": adopted}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        body["id"], adopted,
        "a client's existing project id must be honoured"
    );

    let (status, _) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/projects"),
            &token,
            json!({"slug": "bad", "name": "P", "id": "not-a-uuid"}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a non-UUID id has no derivable scope"
    );
}

#[tokio::test]
async fn projects_and_environments_are_admin_only_to_create() {
    let app = fresh_app("p3-admin", None);
    let (owner, org, _, _) = founder(&app, "p2@archicode.codes", "adminco").await;
    let bob = signed_up(&app, "bob-p2@archicode.codes").await;
    let (_, invite) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/invites"),
            &owner,
            json!({"email": "bob-p2@archicode.codes", "role": "member"}),
        ),
    )
    .await;
    let token = invite["token"].as_str().unwrap().to_string();
    send(
        &app,
        post_as("/v1/invites/accept", &bob, json!({"token": token})),
    )
    .await;

    let (status, _) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/projects"),
            &bob,
            json!({"slug": "nope", "name": "P"}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a member must not create projects"
    );

    let proj = project(&app, &owner, &org, "app").await;
    let (status, _) = send(
        &app,
        post_as(
            &format!("/v1/projects/{proj}/environments"),
            &bob,
            json!({"name": "prod"}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a member must not create environments"
    );
    let (status, body) = send(
        &app,
        get_with(
            &format!("/v1/projects/{proj}/environments"),
            &format!("Bearer {bob}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "but a member may read them: {body}");
}

#[tokio::test]
async fn a_scope_epoch_must_advance() {
    let app = fresh_app("p3-epoch", None);
    let (token, org, _, _) = founder(&app, "p3@archicode.codes", "epochco").await;
    let proj = project(&app, &token, &org, "app").await;
    send(
        &app,
        post_as(
            &format!("/v1/projects/{proj}/environments"),
            &token,
            json!({"name": "prod"}),
        ),
    )
    .await;

    let path = format!("/v1/projects/{proj}/environments/prod/scopekey");
    let (status, body) = send(
        &app,
        put_as(
            &path,
            &token,
            json!({"scope_pubkey": "KEY1", "scope_epoch": 1}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["scope_epoch"], 1);
    assert_eq!(body["scope_pubkey"], "KEY1");

    for stale in [1, 0] {
        let (status, _) = send(
            &app,
            put_as(
                &path,
                &token,
                json!({"scope_pubkey": "OLD", "scope_epoch": stale}),
            ),
        )
        .await;
        assert_ne!(status, StatusCode::OK, "epoch {stale} must not be accepted");
    }
    let (status, body) = send(
        &app,
        put_as(
            &path,
            &token,
            json!({"scope_pubkey": "KEY2", "scope_epoch": 2}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["scope_pubkey"], "KEY2");
}

#[tokio::test]
async fn a_proof_of_possession_must_bind_the_canonical_org_id_not_its_slug() {
    let app = fresh_app("p3-pop-id", None);
    let (token, org, org_id, account_id) = founder(&app, "p4@archicode.codes", "popco").await;
    let identity = Identity::generate();
    let path = format!("/v1/orgs/{org}/pubkey");

    let over_slug = pubkey_body(&identity, &account_id, &org);
    let (status, body) = send(&app, put_as(&path, &token, over_slug)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a proof signed over the slug must not verify: {body}"
    );

    let over_id = pubkey_body(&identity, &account_id, &org_id);
    let (status, body) = send(&app, put_as(&path, &token, over_id)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a proof over the canonical id must verify: {body}"
    );
    assert_eq!(
        body["user_id"], account_id,
        "user_id comes from the session, never the body"
    );
}

#[tokio::test]
async fn a_proof_for_another_account_is_refused_and_stored_bytes_are_verbatim() {
    let app = fresh_app("p3-pop-other", None);
    let (token, org, org_id, account_id) = founder(&app, "p5@archicode.codes", "verbco").await;
    let identity = Identity::generate();
    let path = format!("/v1/orgs/{org}/pubkey");

    let for_someone_else = pubkey_body(&identity, "some-other-account", &org_id);
    let (status, _) = send(&app, put_as(&path, &token, for_someone_else)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let good = pubkey_body(&identity, &account_id, &org_id);
    let sent_sig = good["pubkey_sig"].as_str().unwrap().to_string();
    send(&app, put_as(&path, &token, good)).await;
    let (status, body) = send(
        &app,
        get_with(
            &format!("/v1/orgs/{org}/users/{account_id}/pubkey"),
            &format!("Bearer {token}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["pubkey_sig"].as_str().unwrap(),
        sent_sig,
        "the signature must be echoed byte-for-byte or no later verifier can check it"
    );
}

#[tokio::test]
async fn a_grant_cannot_name_a_grantee_or_environment_from_elsewhere() {
    let app = fresh_app("p3-grant-scope", None);
    let (alice, org_a, _, _) = founder(&app, "p6a@archicode.codes", "aco").await;
    let (bob, org_b, _, bob_id) = founder(&app, "p6b@archicode.codes", "bco").await;
    let proj_a = project(&app, &alice, &org_a, "app").await;
    let proj_b = project(&app, &bob, &org_b, "app").await;
    send(
        &app,
        post_as(
            &format!("/v1/projects/{proj_b}/environments"),
            &bob,
            json!({"name": "prod"}),
        ),
    )
    .await;
    let (_, envs) = send(
        &app,
        get_with(
            &format!("/v1/projects/{proj_b}/environments"),
            &format!("Bearer {bob}"),
        ),
    )
    .await;
    let foreign_env = envs[0]["id"].as_str().unwrap().to_string();

    let grants = format!("/v1/orgs/{org_a}/projects/{proj_a}/grants");
    let (status, body) = send(
        &app,
        post_as(
            &grants,
            &alice,
            json!({"grantee_kind": "user", "grantee_id": bob_id, "project_role": "read"}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a grantee from another org must be refused: {body}"
    );

    let (status, body) = send(&app, post_as(&grants, &alice,
        json!({"grantee_kind": "user", "grantee_id": "nobody", "project_role": "read", "env_id": foreign_env}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let mismatched = format!("/v1/orgs/{org_a}/projects/{proj_b}/grants");
    let (status, _) = send(&app, get_with(&mismatched, &format!("Bearer {alice}"))).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a project outside the named org must not resolve"
    );
}

#[tokio::test]
async fn missing_is_the_authorized_set_that_still_lacks_a_wrap() {
    let app = fresh_app("p3-fulfilled", None);
    let (owner, org, _, owner_id) = founder(&app, "p7@archicode.codes", "fulfilco").await;
    let bob = signed_up(&app, "bob-p7@archicode.codes").await;
    let (_, invite) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/invites"),
            &owner,
            json!({"email": "bob-p7@archicode.codes", "role": "member"}),
        ),
    )
    .await;
    let token = invite["token"].as_str().unwrap().to_string();
    send(
        &app,
        post_as("/v1/invites/accept", &bob, json!({"token": token})),
    )
    .await;
    let (_, me) = send(&app, get_with("/v1/auth/me", &format!("Bearer {bob}"))).await;
    let bob_id = me["account_id"].as_str().unwrap().to_string();

    let (_, team) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/teams"),
            &owner,
            json!({"slug": "core", "name": "Core"}),
        ),
    )
    .await;
    let team_id = team["id"].as_str().unwrap().to_string();
    for (who, role) in [(&owner_id, "admin"), (&bob_id, "member")] {
        let (status, body) = send(
            &app,
            post_as(
                &format!("/v1/orgs/{org}/teams/core/members"),
                &owner,
                json!({"user_id": who, "team_role": role}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    }

    let proj = project(&app, &owner, &org, "app").await;
    let grants = format!("/v1/orgs/{org}/projects/{proj}/grants");
    let (status, grant) = send(
        &app,
        post_as(
            &grants,
            &owner,
            json!({"grantee_kind": "team", "grantee_id": team_id, "project_role": "write"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{grant}");
    let grant_id = grant["id"].as_str().unwrap().to_string();

    let env = environment(&app, &owner, &proj, "prod").await;
    let fulfilled = format!("{grants}/{grant_id}/fulfilled?env_id={env}&epoch=1");
    let (status, body) = send(&app, get_with(&fulfilled, &format!("Bearer {owner}"))).await;
    assert_eq!(status, StatusCode::OK);
    let missing: Vec<&str> = body["missing"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(missing.len(), 2, "both team members need a wrap: {body}");
    assert!(missing.contains(&owner_id.as_str()) && missing.contains(&bob_id.as_str()));

    let wraps = format!("{grants}/{grant_id}/wraps");
    let wrap_bob = json!({"user_id": bob_id, "env_id": env, "epoch": 1});
    let (status, body) = send(&app, post_as(&wraps, &owner, wrap_bob)).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (_, body) = send(&app, get_with(&fulfilled, &format!("Bearer {owner}"))).await;
    assert_eq!(
        body["missing"].as_array().unwrap().len(),
        1,
        "the wrapped member drops out"
    );
    assert_eq!(body["missing"][0], owner_id);
    let members: Vec<&str> = body["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        members.len(),
        2,
        "members stays the full authorized set as missing empties: {body}"
    );

    let stranger = json!({"user_id": "stranger", "env_id": env, "epoch": 1});
    let (status, body) = send(&app, post_as(&wraps, &owner, stranger)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a wrap for an unauthorized account must be refused: {body}"
    );
}

#[tokio::test]
async fn a_project_wide_grant_records_no_environment() {
    let app = fresh_app("p3-projectwide", None);
    let (owner, org, _, owner_id) = founder(&app, "p8@archicode.codes", "wideco").await;
    let proj = project(&app, &owner, &org, "app").await;
    let grants = format!("/v1/orgs/{org}/projects/{proj}/grants");
    send(
        &app,
        post_as(
            &grants,
            &owner,
            json!({"grantee_kind": "user", "grantee_id": owner_id, "project_role": "admin"}),
        ),
    )
    .await;
    let (status, body) = send(&app, get_with(&grants, &format!("Bearer {owner}"))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert!(
        body[0]["env_id"].is_null(),
        "a project-wide grant applies to every environment"
    );
}

#[tokio::test]
async fn a_group_member_must_belong_to_the_organization() {
    let app = fresh_app("p3-group", None);
    let (owner, org, _, _) = founder(&app, "p9@archicode.codes", "groupco").await;
    let outsider = signed_up(&app, "out-p9@archicode.codes").await;
    let (_, me) = send(&app, get_with("/v1/auth/me", &format!("Bearer {outsider}"))).await;
    let outsider_id = me["account_id"].as_str().unwrap().to_string();
    let proj = project(&app, &owner, &org, "app").await;

    let (status, group) = send(
        &app,
        post_as(&format!("/v1/projects/{proj}/groups"), &owner, json!({})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "an empty body must be accepted: {group}"
    );
    let group_id = group["id"].as_str().unwrap().to_string();
    assert!(
        group["name"].as_str().is_some_and(|n| !n.is_empty()),
        "a group always has a name"
    );

    let (status, body) = send(
        &app,
        post_as(
            &format!("/v1/groups/{group_id}/members"),
            &owner,
            json!({"user_id": outsider_id}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["error"].as_str().unwrap().contains("organization"));
}
