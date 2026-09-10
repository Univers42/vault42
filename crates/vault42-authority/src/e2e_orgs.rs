/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   e2e_orgs.rs                                          :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The organization model's route battery.
//!
//! The assertions that matter here are the authorization ones. A plain member must not be
//! able to invite. A non-member must get 404 rather than 403, so organization slugs cannot
//! be enumerated. An invite must be single-use and bound to the address it was sent to. And
//! a team member must already belong to the organization, which is the rule the schema
//! enforces with a composite foreign key.

use crate::e2e::{fresh_app, get_with, post, post_as, send, signed_up};
use axum::http::StatusCode;
use serde_json::json;

/// Create an org as `owner_token` and return its slug.
async fn owned_org(app: &std::sync::Arc<crate::app::App>, token: &str, slug: &str) -> String {
    let (status, body) = send(
        app,
        post_as("/v1/orgs", token, json!({"slug": slug, "name": "Acme"})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "org create should succeed: {body}"
    );
    slug.to_string()
}

/// Invite `email` to `org` at `role`, accept it as `invitee_token`, and return nothing.
async fn joined(
    app: &std::sync::Arc<crate::app::App>,
    admin: (&str, &str),
    invitee: (&str, &str),
    role: &str,
) {
    let (org, admin_token) = admin;
    let (email, invitee_token) = invitee;
    let (status, body) = send(
        app,
        post_as(
            &format!("/v1/orgs/{org}/invites"),
            admin_token,
            json!({"email": email, "role": role}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "invite should issue: {body}");
    let token = body["token"].as_str().expect("invite token").to_string();
    let (status, body) = send(
        app,
        post_as("/v1/invites/accept", invitee_token, json!({"token": token})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "invite should accept: {body}");
}

#[tokio::test]
async fn creating_an_org_makes_the_creator_its_owner() {
    let app = fresh_app("org-create", None);
    let token = signed_up(&app, "owner@archicode.codes").await;
    let org = owned_org(&app, &token, "acme").await;
    let (status, body) = send(
        &app,
        get_with(
            &format!("/v1/orgs/{org}/members"),
            &format!("Bearer {token}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let members = body.as_array().expect("members array");
    assert_eq!(members.len(), 1);
    assert_eq!(members[0]["role"], "owner");
}

#[tokio::test]
async fn an_org_slug_is_unique_and_validated() {
    let app = fresh_app("org-slug", None);
    let token = signed_up(&app, "slug@archicode.codes").await;
    owned_org(&app, &token, "taken").await;
    let (status, _) = send(
        &app,
        post_as(
            "/v1/orgs",
            &token,
            json!({"slug": "taken", "name": "Other"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    for bad in ["", "has space", "has/slash"] {
        let (status, _) = send(
            &app,
            post_as("/v1/orgs", &token, json!({"slug": bad, "name": "X"})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "slug {bad:?} must be refused"
        );
    }
    let (status, _) = send(
        &app,
        post_as("/v1/orgs", &token, json!({"slug": "ok", "name": ""})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an empty name must be refused"
    );
}

#[tokio::test]
async fn creating_an_org_requires_a_session() {
    let app = fresh_app("org-anon", None);
    let (status, _) = send(&app, post("/v1/orgs", json!({"slug": "anon", "name": "X"}))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_non_member_gets_not_found_rather_than_forbidden() {
    let app = fresh_app("org-enum", None);
    let owner = signed_up(&app, "owner2@archicode.codes").await;
    let outsider = signed_up(&app, "outsider@archicode.codes").await;
    owned_org(&app, &owner, "secretco").await;
    let (status, _) = send(
        &app,
        get_with("/v1/orgs/secretco/members", &format!("Bearer {outsider}")),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an outsider must not learn the org exists"
    );
    let (status, _) = send(
        &app,
        get_with(
            "/v1/orgs/no-such-org/members",
            &format!("Bearer {outsider}"),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "and an absent org looks identical"
    );
}

#[tokio::test]
async fn an_admin_invites_and_the_invitee_appears_in_members() {
    let app = fresh_app("org-invite", None);
    let owner = signed_up(&app, "owner3@archicode.codes").await;
    let bob = signed_up(&app, "bob@archicode.codes").await;
    let org = owned_org(&app, &owner, "inviteco").await;
    joined(
        &app,
        (&org, &owner),
        ("bob@archicode.codes", &bob),
        "member",
    )
    .await;
    let (status, body) = send(
        &app,
        get_with(
            &format!("/v1/orgs/{org}/members"),
            &format!("Bearer {owner}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let roles: Vec<&str> = body
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["role"].as_str().unwrap())
        .collect();
    assert_eq!(roles.len(), 2);
    assert!(roles.contains(&"owner") && roles.contains(&"member"));
}

#[tokio::test]
async fn a_plain_member_cannot_invite() {
    let app = fresh_app("org-noinvite", None);
    let owner = signed_up(&app, "owner4@archicode.codes").await;
    let bob = signed_up(&app, "bob4@archicode.codes").await;
    let org = owned_org(&app, &owner, "strictco").await;
    joined(
        &app,
        (&org, &owner),
        ("bob4@archicode.codes", &bob),
        "member",
    )
    .await;
    let (status, _) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/invites"),
            &bob,
            json!({"email": "carol@archicode.codes", "role": "member"}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "only owner or admin may invite"
    );
}

#[tokio::test]
async fn an_invite_is_single_use_and_bound_to_its_address() {
    let app = fresh_app("org-invite-bound", None);
    let owner = signed_up(&app, "owner5@archicode.codes").await;
    let bob = signed_up(&app, "bob5@archicode.codes").await;
    let eve = signed_up(&app, "eve@archicode.codes").await;
    let org = owned_org(&app, &owner, "boundco").await;

    let (status, body) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/invites"),
            &owner,
            json!({"email": "bob5@archicode.codes", "role": "member"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let token = body["token"].as_str().unwrap().to_string();

    let (status, _) = send(
        &app,
        post_as("/v1/invites/accept", &eve, json!({"token": &token})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a token is useless to a different address"
    );

    let (status, _) = send(
        &app,
        post_as("/v1/invites/accept", &bob, json!({"token": &token})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(
        &app,
        post_as("/v1/invites/accept", &bob, json!({"token": &token})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "an invite is single-use");
}

#[tokio::test]
async fn an_unknown_or_empty_invite_token_is_refused() {
    let app = fresh_app("org-badtoken", None);
    let bob = signed_up(&app, "bob6@archicode.codes").await;
    let (status, _) = send(
        &app,
        post_as("/v1/invites/accept", &bob, json!({"token": "   "})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = send(
        &app,
        post_as(
            "/v1/invites/accept",
            &bob,
            json!({"token": "not-a-real-token"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn both_accept_paths_resolve_to_the_same_handler() {
    let app = fresh_app("org-accept-alias", None);
    let owner = signed_up(&app, "owner7@archicode.codes").await;
    let bob = signed_up(&app, "bob7@archicode.codes").await;
    let org = owned_org(&app, &owner, "aliasco").await;
    let (_, body) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/invites"),
            &owner,
            json!({"email": "bob7@archicode.codes", "role": "member"}),
        ),
    )
    .await;
    let token = body["token"].as_str().unwrap().to_string();
    let (status, body) = send(
        &app,
        post_as("/v1/orgs/invites/accept", &bob, json!({"token": token})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the org-scoped alias must work too");
    assert_eq!(body["scope_kind"], "org");
}

#[tokio::test]
async fn an_expired_invite_is_refused() {
    use crate::store::{Acceptance, NewInvite};
    let app = fresh_app("org-expired", None);
    let owner = signed_up(&app, "owner8@archicode.codes").await;
    let org = owned_org(&app, &owner, "expiredco").await;
    let org_id = app.store.resolve_org(org).await.unwrap().unwrap();
    let issued = crate::auth::session::mint(0, 0);
    app.store
        .issue_invite(NewInvite {
            id: "expired-invite".into(),
            token_hash: issued.token_hash.clone(),
            scope_kind: "org".into(),
            scope_id: org_id,
            email: "owner8@archicode.codes".into(),
            role: "member".into(),
            invited_by: app
                .store
                .account_by_email("owner8@archicode.codes".into())
                .await
                .unwrap()
                .unwrap()
                .id,
            expires_at: 1,
        })
        .await
        .unwrap();
    let refused = app
        .store
        .accept_invite(Acceptance {
            token_hash: issued.token_hash,
            account_id: "irrelevant".into(),
            email: "owner8@archicode.codes".into(),
            now: 10_000,
        })
        .await;
    assert!(
        matches!(refused, Err(crate::error::Error::Conflict(_))),
        "an expired invite must be refused"
    );
}

#[tokio::test]
async fn teams_are_created_listed_and_staffed_from_org_members() {
    let app = fresh_app("team-happy", None);
    let owner = signed_up(&app, "owner9@archicode.codes").await;
    let bob = signed_up(&app, "bob9@archicode.codes").await;
    let org = owned_org(&app, &owner, "teamco").await;
    joined(
        &app,
        (&org, &owner),
        ("bob9@archicode.codes", &bob),
        "member",
    )
    .await;

    let (status, body) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/teams"),
            &owner,
            json!({"slug": "platform", "name": "Platform"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, body) = send(
        &app,
        get_with(&format!("/v1/orgs/{org}/teams"), &format!("Bearer {owner}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert_eq!(body[0]["slug"], "platform");

    let bob_id = app
        .store
        .account_by_email("bob9@archicode.codes".into())
        .await
        .unwrap()
        .unwrap()
        .id;
    let (status, body) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/teams/platform/members"),
            &owner,
            json!({"user_id": bob_id, "team_role": "admin"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
}

#[tokio::test]
async fn a_team_member_must_already_belong_to_the_organization() {
    let app = fresh_app("team-invariant", None);
    let owner = signed_up(&app, "owner10@archicode.codes").await;
    let outsider = signed_up(&app, "outsider10@archicode.codes").await;
    let org = owned_org(&app, &owner, "invariantco").await;
    let _ = outsider;
    send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/teams"),
            &owner,
            json!({"slug": "core", "name": "Core"}),
        ),
    )
    .await;

    let outsider_id = app
        .store
        .account_by_email("outsider10@archicode.codes".into())
        .await
        .unwrap()
        .unwrap()
        .id;
    let (status, body) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/teams/core/members"),
            &owner,
            json!({"user_id": outsider_id}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the org-membership rule must hold"
    );
    assert!(
        body["error"].as_str().unwrap().contains("organization"),
        "{body}"
    );
}

#[tokio::test]
async fn accepting_a_team_invite_without_org_membership_is_refused() {
    let app = fresh_app("team-invite-order", None);
    let owner = signed_up(&app, "owner11@archicode.codes").await;
    let outsider = signed_up(&app, "outsider11@archicode.codes").await;
    let org = owned_org(&app, &owner, "orderco").await;
    send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/teams"),
            &owner,
            json!({"slug": "squad", "name": "Squad"}),
        ),
    )
    .await;

    let (status, body) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/teams/squad/invites"),
            &owner,
            json!({"email": "outsider11@archicode.codes", "role": "member"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let token = body["token"].as_str().unwrap().to_string();
    let (status, body) = send(
        &app,
        post_as("/v1/invites/accept", &outsider, json!({"token": token})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a team invite cannot bypass org membership"
    );
    assert!(
        body["error"].as_str().unwrap().contains("organization"),
        "{body}"
    );
}

#[tokio::test]
async fn junk_roles_are_refused_at_the_boundary() {
    let app = fresh_app("roles", None);
    let owner = signed_up(&app, "owner12@archicode.codes").await;
    let org = owned_org(&app, &owner, "roleco").await;
    let (status, _) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/invites"),
            &owner,
            json!({"email": "x@archicode.codes", "role": "root"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/teams"),
            &owner,
            json!({"slug": "t", "name": "T"}),
        ),
    )
    .await;
    let (status, _) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/teams/t/members"),
            &owner,
            json!({"user_id": "whoever", "team_role": "owner"}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "owner is an org role, not a team role"
    );
}

#[tokio::test]
async fn an_invite_is_readable_only_by_the_address_it_was_sent_to() {
    let app = fresh_app("invite-show", None);
    let owner = signed_up(&app, "owner13@archicode.codes").await;
    let bob = signed_up(&app, "bob13@archicode.codes").await;
    let org = owned_org(&app, &owner, "showco").await;
    let (_, body) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/invites"),
            &owner,
            json!({"email": "bob13@archicode.codes", "role": "member"}),
        ),
    )
    .await;
    let id = body["id"].as_str().unwrap().to_string();

    let (status, body) = send(
        &app,
        get_with(&format!("/v1/invites/{id}"), &format!("Bearer {bob}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "pending");
    assert_eq!(body["scope_kind"], "org");
    assert!(
        body.get("token").is_none(),
        "an invite must never echo its token"
    );

    let (status, _) = send(
        &app,
        get_with(&format!("/v1/invites/{id}"), &format!("Bearer {owner}")),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "only the invited address may read it"
    );
}

/// Create a project and one environment under `org`, returning `(project_id, env_id)`.
async fn project_with_env(
    app: &std::sync::Arc<crate::app::App>,
    token: &str,
    org: &str,
) -> (String, String) {
    let (status, body) = send(
        app,
        post_as(
            &format!("/v1/orgs/{org}/projects"),
            token,
            json!({"slug": "api", "name": "API"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "project create: {body}");
    let project = body["id"].as_str().expect("project id").to_string();
    let (status, body) = send(
        app,
        post_as(
            &format!("/v1/projects/{project}/environments"),
            token,
            json!({"name": "prod"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "env create: {body}");
    let env = body["id"].as_str().expect("env id").to_string();
    (project, env)
}

/// The account id behind a session token.
async fn account_id(app: &std::sync::Arc<crate::app::App>, token: &str) -> String {
    let (_, body) = send(app, get_with("/v1/auth/me", &format!("Bearer {token}"))).await;
    body["account_id"].as_str().expect("account_id").to_string()
}

#[tokio::test]
async fn a_grant_accepts_a_team_slug_an_email_and_an_env_name() {
    let app = fresh_app("grantrefs", None);
    let owner = signed_up(&app, "owner@example.com").await;
    let member = signed_up(&app, "member@example.com").await;
    let org = owned_org(&app, &owner, "acme").await;
    joined(
        &app,
        (&org, &owner),
        ("member@example.com", &member),
        "member",
    )
    .await;
    let (project, env_id) = project_with_env(&app, &owner, &org).await;

    let (status, _) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/teams"),
            &owner,
            json!({"slug": "backend", "name": "Backend"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Every identifier here is the one a person actually has: a team SLUG, and an env NAME.
    let (status, body) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/projects/{project}/grants"),
            &owner,
            json!({"grantee_kind": "team", "grantee_id": "backend",
                   "project_role": "write", "env_id": "prod"}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a team slug and an env name must be accepted: {body}"
    );

    let (_, listed) = send(
        &app,
        get_with(
            &format!("/v1/orgs/{org}/projects/{project}/grants"),
            &format!("Bearer {owner}"),
        ),
    )
    .await;
    assert_eq!(
        listed[0]["env_id"], env_id,
        "the env NAME must have been stored as the env's id, not verbatim"
    );

    // And a user grant by EMAIL must authorize that account, which is the whole point: a
    // grantee_id stored verbatim joins on nothing and reaches nobody.
    let (status, body) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/projects/{project}/grants"),
            &owner,
            json!({"grantee_kind": "user", "grantee_id": "member@example.com",
                   "project_role": "read"}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "an email must be accepted: {body}"
    );
    let grant = body["id"].as_str().expect("grant id");
    let (_, fulfilled) = send(
        &app,
        get_with(
            &format!(
                "/v1/orgs/{org}/projects/{project}/grants/{grant}/fulfilled?env_id={env_id}&epoch=1"
            ),
            &format!("Bearer {owner}"),
        ),
    )
    .await;
    let expected = account_id(&app, &member).await;
    assert_eq!(
        fulfilled["members"],
        json!([expected]),
        "the grant must authorize the account the address named"
    );
}

#[tokio::test]
async fn a_grant_refuses_an_address_that_is_not_a_member() {
    let app = fresh_app("grantstranger", None);
    let owner = signed_up(&app, "owner@example.com").await;
    signed_up(&app, "stranger@example.com").await;
    let org = owned_org(&app, &owner, "acme").await;
    let (project, _) = project_with_env(&app, &owner, &org).await;

    // The address HAS an account, and is still refused, because it is not in this org. The
    // answer must not distinguish it from an address with no account at all, or the route
    // becomes the enumeration oracle signup was changed to close.
    let mut answers = Vec::new();
    for email in ["stranger@example.com", "nobody-at-all@example.com"] {
        let (status, _) = send(
            &app,
            post_as(
                &format!("/v1/orgs/{org}/projects/{project}/grants"),
                &owner,
                json!({"grantee_kind": "user", "grantee_id": email, "project_role": "read"}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{email} must be refused");
        answers.push(status);
    }
    assert_eq!(
        answers[0], answers[1],
        "a registered non-member and a complete stranger must be indistinguishable"
    );
}

#[tokio::test]
async fn a_team_slug_from_another_org_cannot_be_granted() {
    let app = fresh_app("grantcrossorg", None);
    let owner = signed_up(&app, "owner@example.com").await;
    let org = owned_org(&app, &owner, "acme").await;
    let other = owned_org(&app, &owner, "rival").await;
    let (project, _) = project_with_env(&app, &owner, &org).await;
    let (status, _) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{other}/teams"),
            &owner,
            json!({"slug": "outsiders", "name": "Outsiders"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/projects/{project}/grants"),
            &owner,
            json!({"grantee_kind": "team", "grantee_id": "outsiders", "project_role": "write"}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "resolving a slug must stay scoped to the org, even for someone who owns both"
    );
}

#[tokio::test]
async fn adding_a_team_member_accepts_an_email() {
    let app = fresh_app("teamemail", None);
    let owner = signed_up(&app, "owner@example.com").await;
    let member = signed_up(&app, "member@example.com").await;
    let org = owned_org(&app, &owner, "acme").await;
    joined(
        &app,
        (&org, &owner),
        ("member@example.com", &member),
        "member",
    )
    .await;
    let (status, _) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/teams"),
            &owner,
            json!({"slug": "backend", "name": "Backend"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/teams/backend/members"),
            &owner,
            json!({"user_id": "member@example.com", "team_role": "member"}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "the CLI documents this field as 'user id or email': {body}"
    );
}
