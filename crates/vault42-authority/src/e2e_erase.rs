/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   e2e_erase.rs                                         :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/10/13 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/10/13 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Erasing a member's account: `DELETE /v1/orgs/{org}/members/{user}/account`.
//!
//! Two promises are pinned here. The hierarchy one: the caller must be able to remove the
//! member from every organization the member sits in, so an owner of one organization never
//! reaches a person who also belongs to an organization that owner does not run. The erasure
//! one: afterwards the address appears nowhere in the authority, including the tables keyed by
//! the address rather than the account id, which the tombstone alone never reached.

use crate::e2e::{fresh_app, get_with, post, post_as, send, signed_up, PASSWORD};
use crate::e2e_offboard::{delete_as, is_org_member, joined};
use crate::e2e_scope::founder;
use axum::http::StatusCode;
use serde_json::json;
use std::sync::Arc;

/// Rows anywhere in the authority that still carry `email`, and sessions still tied to `id`.
async fn traces(app: &Arc<crate::app::App>, email: &str, id: &str) -> i64 {
    let (email, id) = (email.to_string(), id.to_string());
    app.store
        .call(move |conn| {
            conn.query_row(
                "SELECT (SELECT COUNT(*) FROM accounts WHERE email=?1)
                      + (SELECT COUNT(*) FROM invites WHERE email=?1)
                      + (SELECT COUNT(*) FROM otp_codes WHERE email=?1)
                      + (SELECT COUNT(*) FROM escrow WHERE email=?1)
                      + (SELECT COUNT(*) FROM attempts WHERE subject=?1)
                      + (SELECT COUNT(*) FROM sessions WHERE account_id=?2)",
                rusqlite::params![email, id],
                |row| row.get(0),
            )
            .map_err(|e| crate::error::Error::Internal(e.into()))
        })
        .await
        .expect("count traces")
}

/// Seed the address-keyed tables a real account accumulates: a code, an escrow blob.
async fn seed_address_rows(app: &Arc<crate::app::App>, email: &str) {
    let email = email.to_string();
    app.store
        .call(move |conn| {
            conn.execute_batch(&format!(
                "INSERT INTO otp_codes(email, code_hash, created_at, expires_at)
                      VALUES ('{email}', 'h', 0, 1);
                 INSERT INTO escrow(email, blob, updated_at) VALUES ('{email}', 'b', 0);"
            ))
            .map_err(|e| crate::error::Error::Internal(e.into()))
        })
        .await
        .expect("seed address rows");
}

/// The case this route was built for: an owner erases an admin who exists only inside the
/// owner's organization, and nothing of the address is left behind.
#[tokio::test]
async fn an_owner_erases_a_member_account_and_every_trace_of_the_address() {
    let app = fresh_app("erase-owner", None);
    let (owner, org, _, _) = founder(&app, "er1@archicode.codes", "eraseco").await;
    let (_, side, _, _) = founder(&app, "er1-side@archicode.codes", "sideco").await;
    let bob_mail = "er1-bob@archicode.codes";
    let (bob, bob_id) = joined(&app, &owner, &org, (bob_mail, "admin")).await;
    let (status, body) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{side}/invites"),
            &signed_up(&app, "er1-side@archicode.codes").await,
            json!({"email": bob_mail, "role": "member"}),
        ),
    )
    .await;
    assert!(status.is_success(), "a pending invite to him: {body}");
    send(
        &app,
        post(
            "/v1/auth/login",
            json!({"email": bob_mail, "password": "wrong-guess-123456"}),
        ),
    )
    .await;
    seed_address_rows(&app, bob_mail).await;
    assert!(
        traces(&app, bob_mail, &bob_id).await > 0,
        "the haystack is not empty"
    );

    let (status, body) = send(
        &app,
        delete_as(
            &format!("/v1/orgs/{org}/members/{bob_mail}/account"),
            &owner,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rotate_required"], true, "{body}");
    assert_eq!(
        traces(&app, bob_mail, &bob_id).await,
        0,
        "the address is forgotten (checked before the login below, which throttles it anew)"
    );

    let (status, _) = send(&app, get_with("/v1/auth/me", &format!("Bearer {bob}"))).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "his session died with the account"
    );
    let (status, _) = send(
        &app,
        post(
            "/v1/auth/login",
            json!({"email": bob_mail, "password": PASSWORD}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "his credentials are gone");
    assert!(!is_org_member(&app, &owner, &org, &bob_id).await);
}

/// The hierarchy of a single removal holds for an erasure: an admin reaches plain members only,
/// and a plain member reaches nobody.
#[tokio::test]
async fn erasing_follows_the_removal_hierarchy() {
    let app = fresh_app("erase-hierarchy", None);
    let (owner, org, _, owner_id) = founder(&app, "er2@archicode.codes", "hierer").await;
    let (admin, _) = joined(&app, &owner, &org, ("er2-admin@archicode.codes", "admin")).await;
    let (_, peer_id) = joined(&app, &owner, &org, ("er2-peer@archicode.codes", "admin")).await;
    let (plain, plain_id) =
        joined(&app, &owner, &org, ("er2-plain@archicode.codes", "member")).await;
    let (_, other_id) = joined(&app, &owner, &org, ("er2-other@archicode.codes", "member")).await;

    for (caller, target) in [(&admin, &owner_id), (&admin, &peer_id), (&plain, &other_id)] {
        let (status, body) = send(
            &app,
            delete_as(&format!("/v1/orgs/{org}/members/{target}/account"), caller),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }
    let (status, body) = send(
        &app,
        delete_as(
            &format!("/v1/orgs/{org}/members/{plain_id}/account"),
            &admin,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an admin may erase a plain member: {body}"
    );
}

/// A seat in an organization the caller does not run shields the whole account: the owner here
/// may remove him from this organization, not erase him from the platform.
#[tokio::test]
async fn a_seat_in_another_organization_shields_the_account() {
    let app = fresh_app("erase-shield", None);
    let (alice, org_a, _, _) = founder(&app, "er3-alice@archicode.codes", "alicer").await;
    let (carol, org_c, _, _) = founder(&app, "er3-carol@archicode.codes", "caroler").await;
    let bob_mail = "er3-bob@archicode.codes";
    let (bob, _) = joined(&app, &alice, &org_a, (bob_mail, "member")).await;
    let (status, invite) = send(
        &app,
        post_as(
            &format!("/v1/orgs/{org_c}/invites"),
            &carol,
            json!({"email": bob_mail, "role": "member"}),
        ),
    )
    .await;
    assert!(status.is_success(), "{invite}");
    let token = invite["token"].as_str().expect("invite token");
    let (status, body) = send(
        &app,
        post_as("/v1/invites/accept", &bob, json!({"token": token})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = send(
        &app,
        delete_as(
            &format!("/v1/orgs/{org_a}/members/{bob_mail}/account"),
            &alice,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, _) = send(&app, get_with("/v1/auth/me", &format!("Bearer {bob}"))).await;
    assert_eq!(status, StatusCode::OK, "his account is untouched");
}

/// The membership the route resolved must still hold inside the erasing transaction: a target
/// who left every organization in between has no standing left to check, and must not be
/// erased unchecked.
#[tokio::test]
async fn a_target_who_left_in_between_is_not_erased_unchecked() {
    let app = fresh_app("erase-race", None);
    let (owner, org, org_id, owner_id) = founder(&app, "er4@archicode.codes", "raceco").await;
    let (bob, bob_id) = joined(&app, &owner, &org, ("er4-bob@archicode.codes", "member")).await;
    let (status, body) = send(
        &app,
        delete_as(&format!("/v1/orgs/{org}/members/{bob_id}"), &bob),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "he leaves: {body}");

    let refused = app
        .store
        .erase_member_account(
            owner_id,
            (org_id, bob_id),
            crate::handlers::offboard::may_remove,
        )
        .await;
    assert!(
        refused.is_err(),
        "an erase with no standing to check must refuse"
    );
    let (status, _) = send(&app, get_with("/v1/auth/me", &format!("Bearer {bob}"))).await;
    assert_eq!(status, StatusCode::OK, "his account is untouched");
}
