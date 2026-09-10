/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   e2e_offboard.rs                                      :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The offboarding battery: taking access away, and being honest about what that achieves.
//!
//! Before these routes existed the authority had 29 of them and not one DELETE. Nobody could
//! stop being a member of anything, so rotation's promise — "a revoked member loses access by
//! absence at the new epoch" — described a state that was unreachable. For a secrets vault
//! offboarding is the operation that matters most after storing a secret.
//!
//! The assertion that carries the security model is the last one in
//! `removing_an_org_member_cascades_every_derived_membership`: after removal the grant's
//! `members` list must no longer name them. That list is what rotation re-wraps to, so if
//! removal did not change it a rotation would hand the departing member a fresh key.
//!
//! What removal does NOT do is also pinned. It cannot reach a scope key already wrapped to
//! somebody, because that lives in vault42 under their own key, so every response says a
//! rotation is still required. An operator who reads `removed: true` as "locked out" has been
//! misled at the worst possible moment.

use crate::e2e::{fresh_app, get_with, post_as, send, signed_up};
use crate::e2e_scope::{environment, founder, project, pubkey_body, put_as};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;
use vault42_core::Identity;

/// A DELETE carrying a bearer token.
fn delete_as(path: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request")
}

/// Sign somebody up, invite them into `org` at `role`, accept, and return `(token, id)`.
async fn joined(
    app: &Arc<crate::app::App>,
    owner: &str,
    org: &str,
    who: (&str, &str),
) -> (String, String) {
    let (email, role) = who;
    let token = signed_up(app, email).await;
    let (_, invite) = send(
        app,
        post_as(
            &format!("/v1/orgs/{org}/invites"),
            owner,
            json!({"email": email, "role": role}),
        ),
    )
    .await;
    let invite_token = invite["token"].as_str().expect("invite token").to_string();
    let (status, body) = send(
        app,
        post_as("/v1/invites/accept", &token, json!({"token": invite_token})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, me) = send(app, get_with("/v1/auth/me", &format!("Bearer {token}"))).await;
    let id = me["account_id"].as_str().expect("account id").to_string();
    (token, id)
}

/// The account ids a grant currently authorizes, which is what rotation re-wraps to.
async fn granted_members(
    app: &Arc<crate::app::App>,
    token: &str,
    path: (&str, &str, &str),
    env: &str,
) -> Vec<String> {
    let (org, proj, grant) = path;
    let uri =
        format!("/v1/orgs/{org}/projects/{proj}/grants/{grant}/fulfilled?env_id={env}&epoch=1");
    let (_, body) = send(app, get_with(&uri, &format!("Bearer {token}"))).await;
    body["members"]
        .as_array()
        .map(|list| {
            list.iter()
                .map(|value| value.as_str().expect("account id").to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Whether an account appears in the organization's member list.
async fn is_org_member(app: &Arc<crate::app::App>, token: &str, org: &str, who: &str) -> bool {
    let (_, body) = send(
        app,
        get_with(
            &format!("/v1/orgs/{org}/members"),
            &format!("Bearer {token}"),
        ),
    )
    .await;
    format!("{body}").contains(who)
}

/// Removing somebody from an organization takes every derived membership with them, and — the
/// assertion the whole battery exists for — takes them out of the grant member set that
/// rotation re-wraps to.
#[tokio::test]
async fn removing_an_org_member_cascades_every_derived_membership() {
    let app = fresh_app("p46-cascade", None);
    let (owner, org, org_id, _) = founder(&app, "off1@archicode.codes", "offco").await;
    let (bob, bob_id) = joined(&app, &owner, &org, ("off1-bob@archicode.codes", "member")).await;
    let proj = project(&app, &owner, &org, "app").await;
    let env = environment(&app, &owner, &proj, "prod").await;

    let (_, team) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/teams"),
            &owner,
            json!({"slug": "core", "name": "Core"}),
        ),
    )
    .await;
    let team_id = team["id"].as_str().expect("team id").to_string();
    let (status, body) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/teams/core/members"),
            &owner,
            json!({"user_id": bob_id, "team_role": "member"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let (_, group) = send(
        &app,
        post_as(
            &format!("/v1/projects/{proj}/groups"),
            &owner,
            json!({"name": "readers"}),
        ),
    )
    .await;
    let group_id = group["id"].as_str().expect("group id").to_string();
    let (status, body) = send(
        &app,
        post_as(
            &format!("/v1/groups/{group_id}/members"),
            &owner,
            json!({"user_id": bob_id}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let identity = Identity::generate();
    let (status, body) = send(
        &app,
        put_as(
            &format!("/v1/orgs/{org}/pubkey"),
            &bob,
            pubkey_body(&identity, &bob_id, &org_id),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let grants = format!("/v1/orgs/{org}/projects/{proj}/grants");
    let (_, team_grant) = send(
        &app,
        post_as(
            &grants,
            &owner,
            json!({"grantee_kind": "team", "grantee_id": team_id, "project_role": "write"}),
        ),
    )
    .await;
    let team_grant = team_grant["id"].as_str().expect("grant id").to_string();
    let (_, own_grant) = send(
        &app,
        post_as(
            &grants,
            &owner,
            json!({"grantee_kind": "user", "grantee_id": bob_id, "project_role": "read"}),
        ),
    )
    .await;
    let own_grant = own_grant["id"].as_str().expect("grant id").to_string();

    assert!(
        granted_members(&app, &owner, (&org, &proj, &team_grant), &env)
            .await
            .contains(&bob_id),
        "the team grant reaches him while he is a member"
    );

    let (status, body) = send(
        &app,
        delete_as(&format!("/v1/orgs/{org}/members/{bob_id}"), &owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["rotate_required"], true,
        "the response must say a rotation is still needed: {body}"
    );

    assert!(!is_org_member(&app, &owner, &org, &bob_id).await, "org");
    let (status, _) = send(
        &app,
        get_with(
            &format!("/v1/orgs/{org}/users/{bob_id}/pubkey"),
            &format!("Bearer {owner}"),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "his public key went with him"
    );

    let (_, listed) = send(&app, get_with(&grants, &format!("Bearer {owner}"))).await;
    assert!(
        !format!("{listed}").contains(&own_grant),
        "his own grant is revoked: {listed}"
    );
    assert!(
        !granted_members(&app, &owner, (&org, &proj, &team_grant), &env)
            .await
            .contains(&bob_id),
        "the team grant must no longer reach him — this is what rotation re-wraps to"
    );
}

/// A revoked grant authorizes nobody and stops being addressable.
#[tokio::test]
async fn a_revoked_grant_authorizes_nobody() {
    let app = fresh_app("p46-revoke", None);
    let (owner, org, _, owner_id) = founder(&app, "off2@archicode.codes", "revokeco").await;
    let proj = project(&app, &owner, &org, "app").await;
    let env = environment(&app, &owner, &proj, "prod").await;
    let grants = format!("/v1/orgs/{org}/projects/{proj}/grants");
    let (_, grant) = send(
        &app,
        post_as(
            &grants,
            &owner,
            json!({"grantee_kind": "user", "grantee_id": owner_id, "project_role": "write"}),
        ),
    )
    .await;
    let grant = grant["id"].as_str().expect("grant id").to_string();
    assert_eq!(
        granted_members(&app, &owner, (&org, &proj, &grant), &env).await,
        vec![owner_id],
        "the grant reaches its holder first"
    );

    let path = format!("{grants}/{grant}");
    let (status, body) = send(&app, delete_as(&path, &owner)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = send(&app, delete_as(&path, &owner)).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "revoking twice reports nothing left to revoke"
    );
    let (_, listed) = send(&app, get_with(&grants, &format!("Bearer {owner}"))).await;
    assert_eq!(
        listed.as_array().expect("grants array").len(),
        0,
        "a revoked grant is not listed: {listed}"
    );
}

/// An organization can never lose its last owner, by any route.
#[tokio::test]
async fn the_last_owner_can_be_removed_by_no_route() {
    let app = fresh_app("p46-lastowner", None);
    let (owner, org, _, owner_id) = founder(&app, "off3@archicode.codes", "lastco").await;

    let (status, body) = send(
        &app,
        delete_as(&format!("/v1/orgs/{org}/members/{owner_id}"), &owner),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "the only owner must not be able to leave: {body}"
    );
    let (status, body) = send(&app, delete_as("/v1/auth/account", &owner)).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "nor delete the account out from under the organization: {body}"
    );
    assert!(
        is_org_member(&app, &owner, &org, &owner_id).await,
        "and after both refusals she is still there"
    );
}

/// An admin may remove plain members but may not unseat an owner, or one admin could remove
/// every owner and inherit the organization.
#[tokio::test]
async fn an_admin_cannot_unseat_an_owner() {
    let app = fresh_app("p46-hierarchy", None);
    let (owner, org, _, owner_id) = founder(&app, "off4@archicode.codes", "hierco").await;
    let (admin, _) = joined(&app, &owner, &org, ("off4-admin@archicode.codes", "admin")).await;
    let (_, plain_id) = joined(&app, &owner, &org, ("off4-plain@archicode.codes", "member")).await;

    let (status, body) = send(
        &app,
        delete_as(&format!("/v1/orgs/{org}/members/{owner_id}"), &admin),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = send(
        &app,
        delete_as(&format!("/v1/orgs/{org}/members/{plain_id}"), &admin),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an admin may remove a member: {body}"
    );
}

/// Nobody is trapped: a plain member can leave without an administrator, and cannot remove
/// anybody else on the way out.
#[tokio::test]
async fn a_member_may_leave_but_may_not_remove_others() {
    let app = fresh_app("p46-leave", None);
    let (owner, org, _, _) = founder(&app, "off5@archicode.codes", "leaveco").await;
    let (bob, bob_id) = joined(&app, &owner, &org, ("off5-bob@archicode.codes", "member")).await;
    let (_, eve_id) = joined(&app, &owner, &org, ("off5-eve@archicode.codes", "member")).await;

    let (status, body) = send(
        &app,
        delete_as(&format!("/v1/orgs/{org}/members/{eve_id}"), &bob),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = send(
        &app,
        delete_as(&format!("/v1/orgs/{org}/members/{bob_id}"), &bob),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "leaving is always allowed: {body}");
    assert!(!is_org_member(&app, &owner, &org, &bob_id).await);
}

/// Deleting an account ends every session it had, so the token that asked cannot be reused.
#[tokio::test]
async fn deleting_an_account_ends_its_sessions() {
    let app = fresh_app("p46-account", None);
    let (owner, org, _, _) = founder(&app, "off6@archicode.codes", "acctco").await;
    let (bob, bob_id) = joined(&app, &owner, &org, ("off6-bob@archicode.codes", "member")).await;

    let bearer = format!("Bearer {bob}");
    let (status, _) = send(&app, get_with("/v1/auth/me", &bearer)).await;
    assert_eq!(status, StatusCode::OK, "his session works beforehand");
    let (status, body) = send(&app, delete_as("/v1/auth/account", &bob)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = send(&app, get_with("/v1/auth/me", &bearer)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the session died with the account"
    );
    assert!(!is_org_member(&app, &owner, &org, &bob_id).await);

    let (status, _) = send(
        &app,
        crate::e2e::post(
            "/v1/auth/login",
            json!({"email": "off6-bob@archicode.codes", "password": crate::e2e::PASSWORD}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the old credentials must not mint a new session"
    );
    let (status, _) = send(
        &app,
        crate::e2e::post(
            "/v1/auth/signup",
            json!({"email": "off6-bob@archicode.codes", "password": "a-brand-new-password-4z"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (status, _) = send(
        &app,
        crate::e2e::post(
            "/v1/auth/login",
            json!({"email": "off6-bob@archicode.codes", "password": "a-brand-new-password-4z"}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "erasure frees the address: the NEW password must mint a session, which is the only \
         evidence left now that signup answers 202 whether the address was free or not"
    );
}

/// Re-inviting somebody does not resurrect the grants they used to hold.
///
/// Their direct grants are revoked on removal, so a second stint starts from nothing. Silently
/// restoring old project access to a returning member would be a surprise in the one direction
/// that matters.
#[tokio::test]
async fn rejoining_does_not_restore_an_old_grant() {
    let app = fresh_app("p46-rejoin", None);
    let (owner, org, _, _) = founder(&app, "off7@archicode.codes", "rejoinco").await;
    let bob_email = "off7-bob@archicode.codes";
    let (_, bob_id) = joined(&app, &owner, &org, (bob_email, "member")).await;
    let proj = project(&app, &owner, &org, "app").await;
    let env = environment(&app, &owner, &proj, "prod").await;
    let grants = format!("/v1/orgs/{org}/projects/{proj}/grants");
    let (_, grant) = send(
        &app,
        post_as(
            &grants,
            &owner,
            json!({"grantee_kind": "user", "grantee_id": bob_id, "project_role": "write"}),
        ),
    )
    .await;
    let grant = grant["id"].as_str().expect("grant id").to_string();

    send(
        &app,
        delete_as(&format!("/v1/orgs/{org}/members/{bob_id}"), &owner),
    )
    .await;
    let (_, invite) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/invites"),
            &owner,
            json!({"email": bob_email, "role": "member"}),
        ),
    )
    .await;
    let token = invite["token"].as_str().expect("invite token").to_string();
    let back = signed_up_again(&app, bob_email).await;
    let (status, body) = send(
        &app,
        post_as("/v1/invites/accept", &back, json!({"token": token})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "he can be invited back: {body}");
    assert!(is_org_member(&app, &owner, &org, &bob_id).await);

    let uri = format!("{grants}/{grant}/fulfilled?env_id={env}&epoch=1");
    let (status, body) = send(&app, get_with(&uri, &format!("Bearer {owner}"))).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the revoked grant stays revoked across a rejoin: {body}"
    );
}

/// Log an existing account back in, for a member who was removed but never deleted.
async fn signed_up_again(app: &Arc<crate::app::App>, email: &str) -> String {
    let (status, body) = send(
        app,
        crate::e2e::post(
            "/v1/auth/login",
            json!({"email": email, "password": crate::e2e::PASSWORD}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["token"].as_str().expect("token").to_string()
}

/// A removal route is not a membership oracle: an outsider learns nothing from it.
#[tokio::test]
async fn an_outsider_cannot_probe_membership_through_a_removal() {
    let app = fresh_app("p46-outsider", None);
    let (owner, org, _, owner_id) = founder(&app, "off8@archicode.codes", "outco").await;
    let mallory = signed_up(&app, "off8-mallory@archicode.codes").await;
    let (status, body) = send(
        &app,
        delete_as(&format!("/v1/orgs/{org}/members/{owner_id}"), &mallory),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an outsider must not learn the organization exists: {body}"
    );
    assert!(is_org_member(&app, &owner, &org, &owner_id).await);
}

/// The removal response never claims more than it achieved.
#[tokio::test]
async fn a_removal_always_says_a_rotation_is_still_required() {
    let app = fresh_app("p46-honest", None);
    let (owner, org, _, _) = founder(&app, "off9@archicode.codes", "honestco").await;
    let (_, bob_id) = joined(&app, &owner, &org, ("off9-bob@archicode.codes", "member")).await;
    let (_, body): (StatusCode, Value) = send(
        &app,
        delete_as(&format!("/v1/orgs/{org}/members/{bob_id}"), &owner),
    )
    .await;
    assert_eq!(body["removed"], true);
    assert_eq!(body["rotate_required"], true);
    let detail = body["detail"].as_str().expect("detail");
    assert!(
        detail.contains("rotate-scope"),
        "the response must name the follow-up an operator has to run: {detail}"
    );
}

/// A grant never authorizes somebody who is not currently a member, whatever removed them.
///
/// The removal routes revoke a departing member's direct grants in the same transaction, and
/// team membership cascades from a composite foreign key, so both of those protect the member
/// set without `authorized_members` having to. This asserts the remaining guarantee directly:
/// strip only the membership row, leaving the grant live, and the grant must still name nobody.
///
/// It is deliberately white-box, reaching past the routes to delete one row, because that is the
/// only way to exercise the rule in isolation — and a rule no test can reach is a rule that will
/// be quietly removed. The first version of this battery asserted only the two protected paths
/// and passed with the join deleted.
#[tokio::test]
async fn a_grant_never_authorizes_a_non_member() {
    let app = fresh_app("p46-nonmember", None);
    let (owner, org, _, _) = founder(&app, "off10@archicode.codes", "nonmemberco").await;
    let (_, bob_id) = joined(&app, &owner, &org, ("off10-bob@archicode.codes", "member")).await;
    let proj = project(&app, &owner, &org, "app").await;
    let env = environment(&app, &owner, &proj, "prod").await;
    let (_, grant) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/projects/{proj}/grants"),
            &owner,
            json!({"grantee_kind": "user", "grantee_id": bob_id, "project_role": "write"}),
        ),
    )
    .await;
    let grant = grant["id"].as_str().expect("grant id").to_string();
    assert_eq!(
        granted_members(&app, &owner, (&org, &proj, &grant), &env).await,
        vec![bob_id.clone()],
        "the grant reaches him while he is a member"
    );

    let stripped = bob_id.clone();
    app.store
        .call(move |conn| {
            conn.execute(
                "DELETE FROM org_members WHERE account_id=?1",
                rusqlite::params![stripped],
            )
            .expect("strip the membership row only");
            Ok(())
        })
        .await
        .expect("store call");

    assert!(
        granted_members(&app, &owner, (&org, &proj, &grant), &env)
            .await
            .is_empty(),
        "a live grant must name nobody once its holder is not a member"
    );
}

/// The identifier an operator has for a colleague is their ADDRESS, not a UUID they have never
/// seen. Every removal route took the reference raw, so an address matched no account and the
/// removal answered for somebody plainly in the organization as though they were absent.
#[tokio::test]
async fn a_member_can_be_removed_by_their_address() {
    let app = fresh_app("offboard-email", None);
    let (owner, org, _, _) = founder(&app, "obe-own@archicode.codes", "obeco").await;
    let mail = "obe-bob@archicode.codes";
    let (_, bob_id) = joined(&app, &owner, &org, (mail, "member")).await;
    assert!(is_org_member(&app, &owner, &org, &bob_id).await);

    let (status, body) = send(
        &app,
        delete_as(&format!("/v1/orgs/{org}/members/{mail}"), &owner),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an address must be accepted: {body}"
    );
    assert!(
        !is_org_member(&app, &owner, &org, &bob_id).await,
        "the account the address named must be the one removed"
    );
}

/// Leaving is always allowed, and it has to stay allowed for the identifier people actually
/// type. `may_remove` permits self-removal by comparing IDS, so resolution must happen before
/// that check — resolve afterwards and a plain member typing their own address is refused for
/// lack of admin, which reads as "you may not leave".
#[tokio::test]
async fn a_plain_member_may_leave_using_their_own_address() {
    let app = fresh_app("offboard-self", None);
    let (owner, org, _, _) = founder(&app, "osl-own@archicode.codes", "oslco").await;
    let mail = "osl-bob@archicode.codes";
    let (bob, bob_id) = joined(&app, &owner, &org, (mail, "member")).await;

    let (status, body) = send(
        &app,
        delete_as(&format!("/v1/orgs/{org}/members/{mail}"), &bob),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "leaving must be allowed: {body}");
    assert!(!is_org_member(&app, &owner, &org, &bob_id).await);
}

/// A team membership is removable by address too.
#[tokio::test]
async fn a_team_member_can_be_removed_by_their_address() {
    let app = fresh_app("offboard-team-email", None);
    let (owner, org, _, _) = founder(&app, "ote-own@archicode.codes", "oteco").await;
    let mail = "ote-bob@archicode.codes";
    joined(&app, &owner, &org, (mail, "member")).await;
    let (status, _) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/teams"),
            &owner,
            json!({"slug": "core", "name": "Core"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, body) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org}/teams/core/members"),
            &owner,
            json!({"user_id": mail, "team_role": "member"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let (status, body) = send(
        &app,
        delete_as(&format!("/v1/orgs/{org}/teams/core/members/{mail}"), &owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// An address belonging to nobody in this organization is refused, and refused the same way
/// whether or not it has an account elsewhere — the removal routes must not become the
/// membership oracle that scoping resolution to the org exists to avoid.
#[tokio::test]
async fn removing_an_address_outside_the_organization_is_refused() {
    let app = fresh_app("offboard-stranger", None);
    let (owner, org, _, _) = founder(&app, "ost-own@archicode.codes", "ostco").await;
    signed_up(&app, "ost-stranger@archicode.codes").await;

    let mut answers = Vec::new();
    for who in ["ost-stranger@archicode.codes", "ost-nobody@archicode.codes"] {
        let (status, _) = send(
            &app,
            delete_as(&format!("/v1/orgs/{org}/members/{who}"), &owner),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{who} must be refused");
        answers.push(status);
    }
    assert_eq!(
        answers[0], answers[1],
        "a registered non-member and a stranger must be indistinguishable"
    );
}
