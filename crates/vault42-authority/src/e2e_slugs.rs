/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   e2e_slugs.rs                                         :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Project slugs are unique inside an organization, not across them.
//!
//! Every route battery addressed projects by id, so nothing ever put two organizations' projects
//! under one slug. Production did, the second time a team created a project called `inception`:
//! the grant routes looked the slug up across every organization, found the first team's
//! project, saw it was not in the organization in the path and answered 404 — to the second
//! team, for its own project. Routes that name no organization were worse off, since they
//! authorized against whichever organization the first match belonged to.

use crate::e2e::{fresh_app, get_with, post_as, send, signed_up};
use axum::http::StatusCode;
use serde_json::{json, Value};
use std::sync::Arc;

/// An organization `org` owned by `token`, holding a project with slug `api`, and that
/// project's id.
async fn org_with_api(app: &Arc<crate::app::App>, token: &str, org: &str) -> String {
    let (status, body) = send(
        app,
        post_as("/v1/orgs", token, json!({"slug": org, "name": org})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "org create: {body}");
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
    body["id"].as_str().expect("project id").to_string()
}

/// A read grant for the organization's owner on project `api`, addressed by slug.
async fn grant_by_slug(app: &Arc<crate::app::App>, token: &str, org: &str) -> (StatusCode, Value) {
    send(
        app,
        post_as(
            &format!("/v1/orgs/{org}/projects/api/grants"),
            token,
            json!({"grantee_kind": "user", "grantee_id": format!("{org}@example.com"),
                   "project_role": "read"}),
        ),
    )
    .await
}

#[tokio::test]
async fn two_organizations_can_both_grant_on_a_project_slug_they_share() {
    let app = fresh_app("slug-grants", None);
    let first = signed_up(&app, "first@example.com").await;
    let second = signed_up(&app, "second@example.com").await;
    org_with_api(&app, &first, "first").await;
    let second_api = org_with_api(&app, &second, "second").await;

    for (org, token) in [("first", &first), ("second", &second)] {
        let (status, body) = grant_by_slug(&app, token, org).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "{org} must grant on its own `api`, whatever other organization also has one: {body}"
        );
    }
    let (status, listed) = send(
        &app,
        get_with(
            "/v1/orgs/second/projects/api/grants",
            &format!("Bearer {second}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert_eq!(
        listed.as_array().map(Vec::len),
        Some(1),
        "the second organization sees exactly its own grant, not the first's: {listed}"
    );
    let (status, by_id) = send(
        &app,
        get_with(
            &format!("/v1/orgs/second/projects/{second_api}/grants"),
            &format!("Bearer {second}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{by_id}");
    assert_eq!(
        by_id, listed,
        "the slug and the id must name the same project"
    );
}

#[tokio::test]
async fn a_route_without_an_organization_finds_the_callers_own_project() {
    let app = fresh_app("slug-env", None);
    let first = signed_up(&app, "first@example.com").await;
    let second = signed_up(&app, "second@example.com").await;
    org_with_api(&app, &first, "first").await;
    let second_api = org_with_api(&app, &second, "second").await;

    let (status, body) = send(
        &app,
        post_as(
            "/v1/projects/api/environments",
            &second,
            json!({"name": "prod"}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "`api` must mean the caller's project, not the first one ever created: {body}"
    );
    let (status, listed) = send(
        &app,
        get_with(
            &format!("/v1/projects/{second_api}/environments"),
            &format!("Bearer {second}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert_eq!(listed[0]["name"], "prod", "{listed}");
}

#[tokio::test]
async fn a_slug_the_caller_holds_in_two_organizations_is_refused_not_guessed() {
    let app = fresh_app("slug-ambiguous", None);
    let owner = signed_up(&app, "owner@example.com").await;
    let first_api = org_with_api(&app, &owner, "first").await;
    org_with_api(&app, &owner, "second").await;

    let (status, body) = send(
        &app,
        post_as(
            "/v1/projects/api/environments",
            &owner,
            json!({"name": "prod"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body.to_string().contains("use its id"),
        "the refusal must say how to be unambiguous: {body}"
    );
    let (status, body) = send(
        &app,
        post_as(
            &format!("/v1/projects/{first_api}/environments"),
            &owner,
            json!({"name": "prod"}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the id is never ambiguous: {body}"
    );
}

#[tokio::test]
async fn a_stranger_learns_nothing_from_a_slug_other_organizations_use() {
    let app = fresh_app("slug-stranger", None);
    let owner = signed_up(&app, "owner@example.com").await;
    let stranger = signed_up(&app, "stranger@example.com").await;
    org_with_api(&app, &owner, "first").await;
    org_with_api(&app, &owner, "second").await;

    let (status, body) = send(
        &app,
        post_as(
            "/v1/projects/api/environments",
            &stranger,
            json!({"name": "prod"}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a caller in neither organization gets 404, not a hint that two exist: {body}"
    );
}
