/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   e2e_wraps.rs                                         :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The wrap-bookkeeping battery: a scope-key wrap belongs to ONE environment at ONE epoch.
//!
//! Every assertion here is a bug that shipped. The wrap table was keyed by grant and account
//! alone, which made `missing` answer a question nobody asked. A project-wide grant covers
//! every environment, so provisioning a member in one environment dropped them from `missing`
//! in all the others and they were never wrapped there. An epoch-blind row still claimed a
//! wrap existed after a rotation had replaced the key, so rotation — which read the same list
//! — re-wrapped to nobody and destroyed the only copy of the new key.
//!
//! The other half of that failure was reading the wrong set. `missing` is a worklist that
//! empties as provisioning converges; `members` is everyone the grant authorizes. Rotation
//! needs `members`, so the response carries both and this battery pins the difference.

use crate::e2e::{fresh_app, get_with, post_as, send, signed_up};
use crate::e2e_scope::{environment, founder, project};
use axum::http::StatusCode;
use serde_json::{json, Value};

/// The `missing` list as plain owned strings.
fn missing(body: &Value) -> Vec<String> {
    body["missing"]
        .as_array()
        .expect("missing array")
        .iter()
        .map(|value| value.as_str().expect("account id").to_string())
        .collect()
}

/// Grant `account` a project-wide write role and return the grant id.
async fn project_wide_grant(
    app: &std::sync::Arc<crate::app::App>,
    owner: &str,
    path: (&str, &str),
    account: &str,
) -> String {
    let (org, proj) = path;
    let (status, body) = send(
        app,
        post_as(
            &format!("/v1/orgs/{org}/projects/{proj}/grants"),
            owner,
            json!({"grantee_kind": "user", "grantee_id": account, "project_role": "write"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body["id"].as_str().expect("grant id").to_string()
}

/// A wrap recorded for one environment must not report a member as provisioned in another.
///
/// A project-wide grant covers every environment in the project. Keyed by grant and account
/// alone, the wrap recorded for `prod` emptied `missing` for `staging` too, so `sync-keys`
/// against `staging` provisioned nobody and the member silently could not read it.
#[tokio::test]
async fn a_wrap_in_one_environment_does_not_provision_another() {
    let app = fresh_app("p45-cross-env", None);
    let (owner, org, _, owner_id) = founder(&app, "wrap1@archicode.codes", "wrapco").await;
    let proj = project(&app, &owner, &org, "app").await;
    let prod = environment(&app, &owner, &proj, "prod").await;
    let staging = environment(&app, &owner, &proj, "staging").await;
    let grant = project_wide_grant(&app, &owner, (&org, &proj), &owner_id).await;

    let grants = format!("/v1/orgs/{org}/projects/{proj}/grants");
    let wraps = format!("{grants}/{grant}/wraps");
    let (status, body) = send(
        &app,
        post_as(
            &wraps,
            &owner,
            json!({"user_id": owner_id, "env_id": prod, "epoch": 1}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let bearer = format!("Bearer {owner}");
    let at = |env: &str| format!("{grants}/{grant}/fulfilled?env_id={env}&epoch=1");
    let (_, in_prod) = send(&app, get_with(&at(&prod), &bearer)).await;
    assert!(
        missing(&in_prod).is_empty(),
        "the wrapped environment is provisioned: {in_prod}"
    );
    let (_, in_staging) = send(&app, get_with(&at(&staging), &bearer)).await;
    assert_eq!(
        missing(&in_staging),
        vec![owner_id],
        "a wrap for prod must not provision staging: {in_staging}"
    );
}

/// A wrap at the old epoch must not report a member as provisioned at the new one.
///
/// This is the rotation defect at its source. Rotation moves an environment to `epoch + 1`,
/// and every member needs a fresh wrap of the new key. An epoch-blind row still answered
/// "already wrapped", so the client's re-wrap set came back empty, the new key was wrapped to
/// nobody, and the environment was unreadable with no way back — an epoch never regresses.
#[tokio::test]
async fn a_wrap_at_the_old_epoch_does_not_survive_a_rotation() {
    let app = fresh_app("p45-epoch", None);
    let (owner, org, _, owner_id) = founder(&app, "wrap2@archicode.codes", "epochco").await;
    let proj = project(&app, &owner, &org, "app").await;
    let env = environment(&app, &owner, &proj, "prod").await;
    let grant = project_wide_grant(&app, &owner, (&org, &proj), &owner_id).await;

    let grants = format!("/v1/orgs/{org}/projects/{proj}/grants");
    let wraps = format!("{grants}/{grant}/wraps");
    send(
        &app,
        post_as(
            &wraps,
            &owner,
            json!({"user_id": owner_id, "env_id": env, "epoch": 1}),
        ),
    )
    .await;

    let bearer = format!("Bearer {owner}");
    let at = |epoch: u32| format!("{grants}/{grant}/fulfilled?env_id={env}&epoch={epoch}");
    let (_, first) = send(&app, get_with(&at(1), &bearer)).await;
    assert!(missing(&first).is_empty(), "epoch 1 is provisioned");
    let (_, second) = send(&app, get_with(&at(2), &bearer)).await;
    assert_eq!(
        missing(&second),
        vec![owner_id.clone()],
        "a rotation must report every member missing again: {second}"
    );

    send(
        &app,
        post_as(
            &wraps,
            &owner,
            json!({"user_id": owner_id, "env_id": env, "epoch": 2}),
        ),
    )
    .await;
    let (_, repaired) = send(&app, get_with(&at(2), &bearer)).await;
    assert!(
        missing(&repaired).is_empty(),
        "recording the new-epoch wrap converges: {repaired}"
    );
}

/// `members` is the authorized set and does not empty as `missing` does.
///
/// Rotation must re-wrap to everyone the grant authorizes. Reading `missing` for that — which
/// the client did — re-wraps to nobody the moment provisioning has converged, which is exactly
/// when a rotation is most likely to be run.
#[tokio::test]
async fn members_stays_the_authorized_set_while_missing_empties() {
    let app = fresh_app("p45-members", None);
    let (owner, org, _, owner_id) = founder(&app, "wrap3@archicode.codes", "memberco").await;
    let proj = project(&app, &owner, &org, "app").await;
    let env = environment(&app, &owner, &proj, "prod").await;
    let grant = project_wide_grant(&app, &owner, (&org, &proj), &owner_id).await;

    let grants = format!("/v1/orgs/{org}/projects/{proj}/grants");
    let fulfilled = format!("{grants}/{grant}/fulfilled?env_id={env}&epoch=1");
    let bearer = format!("Bearer {owner}");
    send(
        &app,
        post_as(
            &format!("{grants}/{grant}/wraps"),
            &owner,
            json!({"user_id": owner_id, "env_id": env, "epoch": 1}),
        ),
    )
    .await;
    let (_, body) = send(&app, get_with(&fulfilled, &bearer)).await;
    assert!(missing(&body).is_empty(), "provisioning converged: {body}");
    assert_eq!(
        body["members"].as_array().expect("members array").len(),
        1,
        "members must still name the authorized member: {body}"
    );
}

/// A fulfilment question without both coordinates is refused rather than answered vaguely.
///
/// Defaulting either one would answer about a different scope than the caller is provisioning,
/// which is the class of silence this whole battery exists to remove.
#[tokio::test]
async fn a_fulfilment_query_must_name_the_environment_and_the_epoch() {
    let app = fresh_app("p45-required", None);
    let (owner, org, _, owner_id) = founder(&app, "wrap4@archicode.codes", "reqco").await;
    let proj = project(&app, &owner, &org, "app").await;
    let env = environment(&app, &owner, &proj, "prod").await;
    let grant = project_wide_grant(&app, &owner, (&org, &proj), &owner_id).await;

    let grants = format!("/v1/orgs/{org}/projects/{proj}/grants");
    let bearer = format!("Bearer {owner}");
    for query in ["", &format!("?env_id={env}"), "?epoch=1"] {
        let path = format!("{grants}/{grant}/fulfilled{query}");
        let (status, body) = send(&app, get_with(&path, &bearer)).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "an under-specified fulfilment query must be refused: {body}"
        );
    }
}

/// A wrap must not be recorded against an environment the grant does not cover.
///
/// Two ways to get that wrong: an environment in another project, and an environment in this
/// project that an env-scoped grant does not name. Either would empty `missing` for a scope
/// the member was never provisioned in.
#[tokio::test]
async fn a_wrap_against_an_uncovered_environment_is_refused() {
    let app = fresh_app("p45-foreign-env", None);
    let (owner, org, _, owner_id) = founder(&app, "wrap5@archicode.codes", "foreignco").await;
    let proj = project(&app, &owner, &org, "app").await;
    let other = project(&app, &owner, &org, "other").await;
    let prod = environment(&app, &owner, &proj, "prod").await;
    let staging = environment(&app, &owner, &proj, "staging").await;
    let elsewhere = environment(&app, &owner, &other, "prod").await;

    let grants = format!("/v1/orgs/{org}/projects/{proj}/grants");
    let (status, body) = send(
        &app,
        post_as(
            &grants,
            &owner,
            json!({"grantee_kind": "user", "grantee_id": owner_id,
                   "project_role": "write", "env_id": prod}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let grant = body["id"].as_str().expect("grant id").to_string();

    let wraps = format!("{grants}/{grant}/wraps");
    for env in [&elsewhere, &staging] {
        let (status, body) = send(
            &app,
            post_as(
                &wraps,
                &owner,
                json!({"user_id": owner_id, "env_id": env, "epoch": 1}),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "an environment this grant does not cover must be refused: {body}"
        );
    }

    let (status, body) = send(
        &app,
        post_as(
            &wraps,
            &owner,
            json!({"user_id": owner_id, "env_id": prod, "epoch": 1}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
}

/// A member of the organization who holds no grant never appears in either set.
///
/// `members` is new, and it must not become a second way to leak the org roster: it is the
/// grant's authorized set, not everyone who could ask.
#[tokio::test]
async fn an_ungranted_member_appears_in_neither_set() {
    let app = fresh_app("p45-ungranted", None);
    let (owner, org, _, owner_id) = founder(&app, "wrap6@archicode.codes", "ungrantco").await;
    let bob = signed_up(&app, "wrap6-bob@archicode.codes").await;
    let (_, invite) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/invites"),
            &owner,
            json!({"email": "wrap6-bob@archicode.codes", "role": "member"}),
        ),
    )
    .await;
    let token = invite["token"].as_str().expect("token").to_string();
    send(
        &app,
        post_as("/v1/invites/accept", &bob, json!({"token": token})),
    )
    .await;
    let (_, me) = send(&app, get_with("/v1/auth/me", &format!("Bearer {bob}"))).await;
    let bob_id = me["account_id"].as_str().expect("account id").to_string();

    let proj = project(&app, &owner, &org, "app").await;
    let env = environment(&app, &owner, &proj, "prod").await;
    let grant = project_wide_grant(&app, &owner, (&org, &proj), &owner_id).await;
    let path =
        format!("/v1/orgs/{org}/projects/{proj}/grants/{grant}/fulfilled?env_id={env}&epoch=1");
    let (_, body) = send(&app, get_with(&path, &format!("Bearer {owner}"))).await;
    let listed = format!("{body}");
    assert!(
        !listed.contains(&bob_id),
        "an ungranted org member must not be listed: {body}"
    );
}
