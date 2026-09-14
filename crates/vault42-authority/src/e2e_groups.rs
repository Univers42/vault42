/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   e2e_groups.rs                                        :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/09/13 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/09/13 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Group grants: a project group carries a role, and its members hold that role.
//!
//! Groups could be created, joined, invited to and left, and authorized nothing — a grant could
//! name a user or a team only. So "put her in the group that may write" silently gave nothing.
//! Every rule below is paired with the positive that gives it meaning, because a permission
//! test's negative half passes on a system where nothing is permitted at all.
//!
//! The rules: a group grant reaches the group's CURRENT members only — leaving the group or the
//! organization ends it; its role is its role, so a read group does not write; and a group is a
//! project's, so it can only be granted on that project.

use crate::e2e::{fresh_app, get_with, post_as, send, signed_up};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;

type App = Arc<crate::app::App>;

fn put_as(path: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(path)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .expect("request")
}

fn delete_as(path: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request")
}

/// An organization with one project and a `prod` environment: `(owner, org, project, env)`.
async fn scaffold(app: &App, email: &str, slug: &str) -> (String, String, String, String) {
    let owner = signed_up(app, email).await;
    let (status, body) = send(
        app,
        post_as("/v1/orgs", &owner, json!({"slug": slug, "name": "Co"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let project = created_id(
        app,
        &owner,
        &format!("/v1/orgs/{slug}/projects"),
        json!({"slug": "app", "name": "App"}),
    )
    .await;
    let env = created_id(
        app,
        &owner,
        &format!("/v1/projects/{project}/environments"),
        json!({"name": "prod"}),
    )
    .await;
    (owner, slug.to_string(), project, env)
}

/// POST `body` to `path` as `token`, require 201, and return the created `id`.
async fn created_id(app: &App, token: &str, path: &str, body: Value) -> String {
    let (status, reply) = send(app, post_as(path, token, body)).await;
    assert_eq!(status, StatusCode::CREATED, "{path}: {reply}");
    reply["id"].as_str().expect("an id").to_string()
}

/// A plain member of `org`: `(token, account_id)`.
async fn member(app: &App, owner: &str, org: &str, email: &str) -> (String, String) {
    let token = signed_up(app, email).await;
    let (_, invite) = send(
        app,
        post_as(
            &format!("/v1/orgs/{org}/invites"),
            owner,
            json!({"email": email, "role": "member"}),
        ),
    )
    .await;
    let invite = invite["token"].as_str().expect("invite token").to_string();
    let (status, body) = send(
        app,
        post_as("/v1/invites/accept", &token, json!({"token": invite})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, me) = send(app, get_with("/v1/auth/me", &format!("Bearer {token}"))).await;
    (
        token,
        me["account_id"].as_str().expect("account").to_string(),
    )
}

/// A group in `project` holding `account`.
async fn group_with(app: &App, owner: &str, project: &str, account: &str) -> String {
    let group = created_id(
        app,
        owner,
        &format!("/v1/projects/{project}/groups"),
        json!({"name": "deployers"}),
    )
    .await;
    let (status, body) = send(
        app,
        post_as(
            &format!("/v1/groups/{group}/members"),
            owner,
            json!({"user_id": account}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    group
}

/// Grant `role` on `project` to `group`, returning the HTTP status and body.
async fn grant_group(
    app: &App,
    owner: &str,
    scope: (&str, &str),
    group: &str,
    role: &str,
) -> (StatusCode, Value) {
    let (org, project) = scope;
    send(
        app,
        post_as(
            &format!("/v1/orgs/{org}/projects/{project}/grants"),
            owner,
            json!({"grantee_kind": "group", "grantee_id": group, "project_role": role}),
        ),
    )
    .await
}

/// Whether `account` is among the members `grant` authorizes for `env` at epoch 1.
async fn authorized(
    app: &App,
    owner: &str,
    scope: (&str, &str, &str),
    grant: &str,
    account: &str,
) -> bool {
    let (org, project, env) = scope;
    let (status, body) = send(
        app,
        get_with(
            &format!(
                "/v1/orgs/{org}/projects/{project}/grants/{grant}/fulfilled?env_id={env}&epoch=1"
            ),
            &format!("Bearer {owner}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["members"]
        .as_array()
        .expect("members")
        .iter()
        .any(|m| m == account)
}

/// Write a variable in `project`'s prod environment as `token`, returning the status.
async fn write_variable(app: &App, token: &str, project: &str, key: &str) -> StatusCode {
    let path = format!("/v1/projects/{project}/environments/prod/variables/{key}");
    send(app, put_as(&path, token, json!({"value": "v"})))
        .await
        .0
}

#[tokio::test]
async fn a_group_granted_write_lets_its_member_write_and_a_read_group_does_not() {
    let app = fresh_app("group-grant-role", None);
    let (owner, org, project, _) = scaffold(&app, "gg1-owner@archicode.codes", "gg1co").await;
    let (writer, writer_id) = member(&app, &owner, &org, "gg1-writer@archicode.codes").await;
    let (reader, reader_id) = member(&app, &owner, &org, "gg1-reader@archicode.codes").await;
    assert_eq!(
        write_variable(&app, &writer, &project, "BEFORE").await,
        StatusCode::FORBIDDEN,
        "positive control: with no grant, the member cannot write"
    );

    let writers = group_with(&app, &owner, &project, &writer_id).await;
    let readers = group_with(&app, &owner, &project, &reader_id).await;
    let (status, body) = grant_group(&app, &owner, (&org, &project), &writers, "write").await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a group can be granted a role: {body}"
    );
    let (status, body) = grant_group(&app, &owner, (&org, &project), &readers, "read").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    assert_eq!(
        write_variable(&app, &writer, &project, "VIA_GROUP").await,
        StatusCode::NO_CONTENT,
        "a write grant to her group must let her write"
    );
    assert_eq!(
        write_variable(&app, &reader, &project, "VIA_GROUP").await,
        StatusCode::FORBIDDEN,
        "a read grant to his group must not"
    );
}

#[tokio::test]
async fn a_group_grant_reaches_members_only_while_they_are_in_the_group() {
    let app = fresh_app("group-grant-membership", None);
    let (owner, org, project, env) = scaffold(&app, "gg2-owner@archicode.codes", "gg2co").await;
    let (bob, bob_id) = member(&app, &owner, &org, "gg2-bob@archicode.codes").await;
    let group = group_with(&app, &owner, &project, &bob_id).await;
    let (status, grant) = grant_group(&app, &owner, (&org, &project), &group, "write").await;
    assert_eq!(status, StatusCode::CREATED, "{grant}");
    let grant = grant["id"].as_str().expect("grant id").to_string();

    assert!(
        authorized(&app, &owner, (&org, &project, &env), &grant, &bob_id).await,
        "the group's member is one of the grant's members, so rotation re-wraps to him"
    );
    let (status, _) = send(
        &app,
        delete_as(&format!("/v1/groups/{group}/members/{bob_id}"), &owner),
    )
    .await;
    assert!(status.is_success(), "removing him from the group: {status}");
    assert!(
        !authorized(&app, &owner, (&org, &project, &env), &grant, &bob_id).await,
        "out of the group, the grant no longer names him"
    );
    assert_eq!(
        write_variable(&app, &bob, &project, "AFTER_LEAVING").await,
        StatusCode::FORBIDDEN,
        "and he can no longer write"
    );
}

#[tokio::test]
async fn leaving_the_organization_ends_a_group_grant_too() {
    let app = fresh_app("group-grant-offboard", None);
    let (owner, org, project, env) = scaffold(&app, "gg3-owner@archicode.codes", "gg3co").await;
    let (_, carol_id) = member(&app, &owner, &org, "gg3-carol@archicode.codes").await;
    let group = group_with(&app, &owner, &project, &carol_id).await;
    let (_, grant) = grant_group(&app, &owner, (&org, &project), &group, "read").await;
    let grant = grant["id"].as_str().expect("grant id").to_string();
    assert!(authorized(&app, &owner, (&org, &project, &env), &grant, &carol_id).await);

    let (status, body) = send(
        &app,
        delete_as(&format!("/v1/orgs/{org}/members/{carol_id}"), &owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        !authorized(&app, &owner, (&org, &project, &env), &grant, &carol_id).await,
        "removed from the organization, she is gone from the group and from the grant"
    );
}

#[tokio::test]
async fn a_group_can_only_be_granted_on_its_own_project() {
    let app = fresh_app("group-grant-scope", None);
    let (owner, org, project, _) = scaffold(&app, "gg4-owner@archicode.codes", "gg4co").await;
    let (_, dan_id) = member(&app, &owner, &org, "gg4-dan@archicode.codes").await;
    let other = created_id(
        &app,
        &owner,
        &format!("/v1/orgs/{org}/projects"),
        json!({"slug": "other", "name": "Other"}),
    )
    .await;
    let elsewhere = group_with(&app, &owner, &other, &dan_id).await;

    let (status, body) = grant_group(&app, &owner, (&org, &project), &elsewhere, "admin").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a group belongs to one project; granting it on another would reach people nobody chose: {body}"
    );
    let (status, _) = grant_group(&app, &owner, (&org, &project), "no-such-group", "read").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an unknown group is refused"
    );
    let (status, body) = grant_group(&app, &owner, (&org, &other), &elsewhere, "read").await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "positive control: on its own project it is granted: {body}"
    );
}

#[tokio::test]
async fn a_group_grant_is_listed_as_the_group_by_name() {
    let app = fresh_app("group-grant-listing", None);
    let (owner, org, project, _) = scaffold(&app, "gg5-owner@archicode.codes", "gg5co").await;
    let (_, eve_id) = member(&app, &owner, &org, "gg5-eve@archicode.codes").await;
    let group = group_with(&app, &owner, &project, &eve_id).await;
    let (status, body) = grant_group(&app, &owner, (&org, &project), &group, "read").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (_, listed) = send(
        &app,
        get_with(
            &format!("/v1/orgs/{org}/projects/{project}/grants"),
            &format!("Bearer {owner}"),
        ),
    )
    .await;
    let row = &listed.as_array().expect("grants")[0];
    assert_eq!(row["grantee_kind"], "group", "{listed}");
    assert_eq!(row["grantee_id"], group.as_str(), "{listed}");
    assert_eq!(
        row["grantee"], "deployers",
        "a group reads by its name: {listed}"
    );
}

#[tokio::test]
async fn a_plain_member_cannot_grant_their_own_group_anything() {
    let app = fresh_app("group-grant-admin-only", None);
    let (owner, org, project, _) = scaffold(&app, "gg6-owner@archicode.codes", "gg6co").await;
    let (mallory, mallory_id) = member(&app, &owner, &org, "gg6-mallory@archicode.codes").await;
    let group = group_with(&app, &owner, &project, &mallory_id).await;
    let (status, body) = grant_group(&app, &mallory, (&org, &project), &group, "admin").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "granting stays administrator-only: {body}"
    );
    assert_eq!(
        write_variable(&app, &mallory, &project, "ESCALATED").await,
        StatusCode::FORBIDDEN,
        "and the refused grant gave her nothing"
    );
}
