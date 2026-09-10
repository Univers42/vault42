/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   e2e_secondfactor.rs                                  :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The second-factor battery: one-time codes, keystore escrow, and the switch itself.
//!
//! Six digits is a million possibilities, which is only survivable because everything around the
//! code is strict. So each rule gets its own assertion: single use, expiry, an attempt bound, and
//! a binding to the address it was mailed to. A code that is merely "usually right" is worse than
//! no second factor, because it is trusted.
//!
//! Two properties are about what is NOT said. Requesting a code answers 200 for an address with
//! no account, so the route is not a way to enumerate who has one. And every way a code can fail
//! answers 401 with the same body, so nobody can tell "expired" from "wrong" from "already used"
//! and learn whether an address currently has a live code.
//!
//! The switch is the part worth attacking hardest. Once an account requires a factor, every path
//! that mints a session must demand it. There is one such path by construction —
//! `auth::handlers::mint_session` — and this battery asserts the behaviour that construction is
//! supposed to guarantee, so that a future route which mints a session another way is caught here
//! rather than in production.

use crate::e2e::{fresh_app, get_with, outbox_dir, post, post_as, send, signed_up, PASSWORD};
use crate::e2e_scope::put_as;
use axum::http::StatusCode;
use serde_json::json;
use std::sync::Arc;

/// The filename prefix the outbox uses for an address.
fn outbox_prefix(email: &str) -> String {
    email
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// Every message delivered to `email`, oldest first.
fn delivered(tag: &str, email: &str) -> Vec<String> {
    let prefix = outbox_prefix(email);
    let mut names: Vec<_> = match std::fs::read_dir(outbox_dir(tag)) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
            .map(|entry| entry.path())
            .collect(),
        Err(_) => Vec::new(),
    };
    names.sort();
    names
        .iter()
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .collect()
}

/// The six-digit code inside one rendered message.
fn code_in(message: &str) -> String {
    message
        .split_whitespace()
        .find(|word| word.len() == 6 && word.bytes().all(|b| b.is_ascii_digit()))
        .expect("a six-digit code in the body")
        .to_string()
}

/// Request a code and return it, as a person reading their mail would.
///
/// It waits for a message BEYOND the ones already delivered, which matters because delivery is
/// off the request path: reading "the newest file" right after a second request returns the
/// previous code, and the previous code is already dead because a new request replaces it. Any
/// harness reading the outbox needs this, so it is worth stating rather than discovering.
pub(crate) async fn code_for(app: &Arc<crate::app::App>, tag: &str, email: &str) -> String {
    let already = delivered(tag, email).len();
    let (status, _) = send(app, post("/v1/auth/otp/request", json!({"email": email}))).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "requesting a code always answers 200"
    );
    for _ in 0..200 {
        let messages = delivered(tag, email);
        if messages.len() > already {
            return code_in(&messages[already]);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("no new code was delivered to {email}");
}

/// Exchange a code for a proof.
pub(crate) async fn proof_for(app: &Arc<crate::app::App>, email: &str, code: &str) -> String {
    let (status, body) = send(
        app,
        post("/v1/auth/otp/verify", json!({"email": email, "code": code})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["proof"].as_str().expect("proof").to_string()
}

/// A code works once, and the proof it earns is bound to the address that received it.
/// The code-request limit must not become an account-enumeration oracle.
///
/// The unthrottled path was already careful: an address with an account and one without both
/// answer 200, so an attacker learns nothing from asking. A limit applied AFTER the account lookup
/// would have undone that — the throttled answer would arrive only for addresses that exist, and
/// the defence would have handed over exactly what the original design refused to.
///
/// So both addresses are driven to the limit and their sequences of statuses are required to be
/// identical, not merely both eventually refused.
#[tokio::test]
async fn the_code_request_limit_answers_the_same_for_a_known_and_an_unknown_address() {
    let app = fresh_app("code-oracle", None);
    let _ = signed_up(&app, "known@archicode.codes").await;

    let sequence = |app: std::sync::Arc<crate::app::App>, email: &'static str| async move {
        let mut seen = Vec::new();
        for _ in 0..7 {
            let (status, _) =
                send(&app, post("/v1/auth/otp/request", json!({"email": email}))).await;
            seen.push(status);
        }
        seen
    };

    let known = sequence(app.clone(), "known@archicode.codes").await;
    let unknown = sequence(app.clone(), "nobody@archicode.codes").await;

    assert!(
        known.contains(&StatusCode::OK),
        "positive control: early requests must be answered 200, or comparing the two sequences \
         compares two walls of refusals and proves nothing"
    );
    assert!(
        known.contains(&StatusCode::TOO_MANY_REQUESTS),
        "positive control: the limit must actually be reached within the sequence"
    );
    assert_eq!(
        known, unknown,
        "a known address and an unknown one must answer identically at every step; a limit that \
         differs is an enumeration oracle"
    );
}

#[tokio::test]
async fn a_code_earns_a_proof_once() {
    let tag = "p5-once";
    let app = fresh_app(tag, None);
    let email = "sf1@archicode.codes";
    signed_up(&app, email).await;
    let code = code_for(&app, tag, email).await;
    let proof = proof_for(&app, email, &code).await;
    assert!(!proof.is_empty());

    let (status, _) = send(
        &app,
        post("/v1/auth/otp/verify", json!({"email": email, "code": code})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the same code must not work twice"
    );
}

/// Requesting a code for an address with no account still answers 200 and mails nothing.
#[tokio::test]
async fn an_unknown_address_is_not_an_oracle() {
    let tag = "p5-oracle";
    let app = fresh_app(tag, None);
    let (status, body) = send(
        &app,
        post(
            "/v1/auth/otp/request",
            json!({"email": "nobody@archicode.codes"}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a different answer here enumerates accounts: {body}"
    );
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        delivered(tag, "nobody@archicode.codes").is_empty(),
        "and nothing is mailed to an address with no account"
    );
    let (status, _) = send(
        &app,
        post(
            "/v1/auth/otp/verify",
            json!({"email": "nobody@archicode.codes", "code": "000000"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// A code is bound to the address it was mailed to, so it cannot be spent as another account's.
#[tokio::test]
async fn a_code_cannot_be_used_for_another_account() {
    let tag = "p5-crossaccount";
    let app = fresh_app(tag, None);
    let mine = "sf2-mine@archicode.codes";
    let theirs = "sf2-theirs@archicode.codes";
    signed_up(&app, mine).await;
    signed_up(&app, theirs).await;
    let code = code_for(&app, tag, mine).await;
    let (status, _) = send(
        &app,
        post(
            "/v1/auth/otp/verify",
            json!({"email": theirs, "code": code}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a code is bound to one address"
    );
    proof_for(&app, mine, &code).await;
}

/// Wrong guesses are bounded, and the bound closes the code even to the right answer.
#[tokio::test]
async fn guessing_is_bounded_and_closes_the_code() {
    let tag = "p5-attempts";
    let app = fresh_app(tag, None);
    let email = "sf3@archicode.codes";
    signed_up(&app, email).await;
    let code = code_for(&app, tag, email).await;
    let wrong = if code == "000000" { "111111" } else { "000000" };
    for _ in 0..crate::otp::MAX_ATTEMPTS {
        let (status, _) = send(
            &app,
            post(
                "/v1/auth/otp/verify",
                json!({"email": email, "code": wrong}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _) = send(
        &app,
        post("/v1/auth/otp/verify", json!({"email": email, "code": code})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the attempt bound closes the code even to the correct answer"
    );
}

/// A malformed submission is refused without spending an attempt.
#[tokio::test]
async fn a_malformed_code_costs_no_attempt() {
    let tag = "p5-shape";
    let app = fresh_app(tag, None);
    let email = "sf4@archicode.codes";
    signed_up(&app, email).await;
    let code = code_for(&app, tag, email).await;
    for junk in ["12345", "abcdef", "", "1234567"] {
        let (status, _) = send(
            &app,
            post("/v1/auth/otp/verify", json!({"email": email, "code": junk})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{junk:?} is not a candidate code"
        );
    }
    proof_for(&app, email, &code).await;
}

/// Requesting a second code replaces the first, so requests do not accumulate guesses.
#[tokio::test]
async fn a_new_request_replaces_the_previous_code() {
    let tag = "p5-replace";
    let app = fresh_app(tag, None);
    let email = "sf5@archicode.codes";
    signed_up(&app, email).await;
    let first = code_for(&app, tag, email).await;
    let mut second = code_for(&app, tag, email).await;
    for _ in 0..5 {
        if second != first {
            break;
        }
        second = code_for(&app, tag, email).await;
    }
    assert_ne!(second, first, "a fresh request should mint a fresh code");
    let (status, _) = send(
        &app,
        post(
            "/v1/auth/otp/verify",
            json!({"email": email, "code": first}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the old code is dead");
    proof_for(&app, email, &second).await;
}

/// Once an account requires a second factor, a password alone mints no session.
#[tokio::test]
async fn a_required_second_factor_gates_every_login() {
    let tag = "p5-switch";
    let app = fresh_app(tag, None);
    let email = "sf6@archicode.codes";
    let token = signed_up(&app, email).await;
    let code = code_for(&app, tag, email).await;
    let proof = proof_for(&app, email, &code).await;
    let (status, body) = send(
        &app,
        post_as(
            "/v1/auth/mfa",
            &token,
            json!({"required": true, "proof": proof}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (_, me) = send(&app, get_with("/v1/auth/me", &format!("Bearer {token}"))).await;
    assert_eq!(me["mfa_required"], true);

    let (status, _) = send(
        &app,
        post(
            "/v1/auth/login",
            json!({"email": email, "password": PASSWORD}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the password alone must not be enough once a factor is required"
    );
    let (status, _) = send(
        &app,
        post(
            "/v1/auth/login",
            json!({"email": email, "password": PASSWORD, "otp_proof": "not.a.proof"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "nor is a forged proof");

    let fresh = proof_for(&app, email, &code_for(&app, tag, email).await).await;
    let (status, body) = send(
        &app,
        post(
            "/v1/auth/login",
            json!({"email": email, "password": PASSWORD, "otp_proof": fresh}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["token"].as_str().is_some_and(|t| !t.is_empty()));
}

/// A proof for one address cannot satisfy another account's second factor.
#[tokio::test]
async fn a_proof_for_another_address_does_not_satisfy_the_factor() {
    let tag = "p5-crossproof";
    let app = fresh_app(tag, None);
    let mine = "sf7-mine@archicode.codes";
    let theirs = "sf7-theirs@archicode.codes";
    let token = signed_up(&app, mine).await;
    signed_up(&app, theirs).await;
    let proof = proof_for(&app, mine, &code_for(&app, tag, mine).await).await;
    send(
        &app,
        post_as(
            "/v1/auth/mfa",
            &token,
            json!({"required": true, "proof": proof}),
        ),
    )
    .await;
    let elsewhere = proof_for(&app, theirs, &code_for(&app, tag, theirs).await).await;
    let (status, _) = send(
        &app,
        post(
            "/v1/auth/login",
            json!({"email": mine, "password": PASSWORD, "otp_proof": elsewhere}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a proof is bound to the address it was minted for"
    );
}

/// Turning the factor off needs a fresh proof too, so a stolen session cannot strip it.
#[tokio::test]
async fn disabling_the_factor_also_needs_a_proof() {
    let tag = "p5-disable";
    let app = fresh_app(tag, None);
    let email = "sf8@archicode.codes";
    let token = signed_up(&app, email).await;
    let proof = proof_for(&app, email, &code_for(&app, tag, email).await).await;
    send(
        &app,
        post_as(
            "/v1/auth/mfa",
            &token,
            json!({"required": true, "proof": proof}),
        ),
    )
    .await;
    let (status, _) = send(
        &app,
        post_as(
            "/v1/auth/mfa",
            &token,
            json!({"required": false, "proof": "forged.proof.bytes"}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a session alone must not remove the factor protecting it"
    );
    let fresh = proof_for(&app, email, &code_for(&app, tag, email).await).await;
    let (status, body) = send(
        &app,
        post_as(
            "/v1/auth/mfa",
            &token,
            json!({"required": false, "proof": fresh}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
}

/// Escrow round-trips ciphertext to a proof holder and to nobody else.
#[tokio::test]
async fn escrow_round_trips_only_for_the_address_that_proved_itself() {
    let tag = "p5-escrow";
    let app = fresh_app(tag, None);
    let mine = "sf9-mine@archicode.codes";
    let theirs = "sf9-theirs@archicode.codes";
    signed_up(&app, mine).await;
    signed_up(&app, theirs).await;
    let blob = "c2VhbGVkLWtleXN0b3JlLWNpcGhlcnRleHQ=";
    let proof = proof_for(&app, mine, &code_for(&app, tag, mine).await).await;
    let (status, body) = send(
        &app,
        put_as(
            "/v1/auth/escrow",
            "",
            json!({"email": mine, "proof": proof, "blob": blob}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let fetch = proof_for(&app, mine, &code_for(&app, tag, mine).await).await;
    let (status, body) = send(
        &app,
        post(
            "/v1/auth/escrow/fetch",
            json!({"email": mine, "proof": fetch}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["blob"], blob, "the ciphertext comes back untouched");

    let elsewhere = proof_for(&app, theirs, &code_for(&app, tag, theirs).await).await;
    let (status, _) = send(
        &app,
        post(
            "/v1/auth/escrow/fetch",
            json!({"email": mine, "proof": elsewhere}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "somebody else's proof must not fetch my keystore"
    );
    let (status, _) = send(
        &app,
        post(
            "/v1/auth/escrow/fetch",
            json!({"email": theirs, "proof": elsewhere}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an address with no escrow is not found rather than served something"
    );
}

/// Escrow refuses a blob outside its bounds, and never stores a partial write.
#[tokio::test]
async fn escrow_bounds_the_blob() {
    let tag = "p5-escrowbounds";
    let app = fresh_app(tag, None);
    let email = "sf10@archicode.codes";
    signed_up(&app, email).await;
    for blob in [String::new(), "A".repeat(64 * 1024 + 1)] {
        let proof = proof_for(&app, email, &code_for(&app, tag, email).await).await;
        let (status, _) = send(
            &app,
            put_as(
                "/v1/auth/escrow",
                "",
                json!({"email": email, "proof": proof, "blob": blob}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "a bounded blob only");
    }
    let proof = proof_for(&app, email, &code_for(&app, tag, email).await).await;
    let (status, _) = send(
        &app,
        post(
            "/v1/auth/escrow/fetch",
            json!({"email": email, "proof": proof}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "nothing was stored");
}

/// The delivered message carries the code in its body and never in its subject.
#[tokio::test]
async fn the_delivered_message_keeps_the_code_out_of_the_subject() {
    let tag = "p5-message";
    let app = fresh_app(tag, None);
    let email = "sf11@archicode.codes";
    signed_up(&app, email).await;
    let code = code_for(&app, tag, email).await;
    let dir = outbox_dir(tag);
    let rendered: String = std::fs::read_dir(&dir)
        .expect("outbox")
        .filter_map(|entry| entry.ok())
        .map(|entry| std::fs::read_to_string(entry.path()).expect("read"))
        .collect();
    let subject = rendered
        .lines()
        .find(|line| line.starts_with("Subject:"))
        .expect("a subject");
    assert!(
        !subject.contains(&code),
        "a locked screen shows the subject: {subject}"
    );
    assert!(rendered.contains(&code), "the body carries the code");
}

/// A code that has expired is refused, even though it is the right code and unused.
///
/// The window cannot be waited out in a test, so the expiry is written directly through the store
/// seam. It is the one rule of the five that no request sequence can reach quickly, and leaving it
/// untested would leave the shortest-lived guarantee the least covered.
#[tokio::test]
async fn an_expired_code_is_refused() {
    let tag = "p5-expiry";
    let app = fresh_app(tag, None);
    let email = "sf12@archicode.codes";
    signed_up(&app, email).await;
    let code = "424242";
    app.store
        .put_code(crate::store::NewCode {
            email: email.to_string(),
            code_hash: crate::otp::hash_code(email, code),
            expires_at: vault42_contract::signing::now_unix() - 1,
        })
        .await
        .expect("store an already-expired code");

    let (status, body) = send(
        &app,
        post("/v1/auth/otp/verify", json!({"email": email, "code": code})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an expired code is not a credential: {body}"
    );
    assert_eq!(
        body["error"], "unauthorized",
        "and it is indistinguishable from a wrong code"
    );
}

/// With no proof secret configured, the code routes refuse rather than pretending to work.
///
/// The dangerous alternative is treating an unconfigured second factor as "no proof needed",
/// which would turn a deployment that forgot the secret into one that skips the check.
#[tokio::test]
async fn an_unconfigured_authority_refuses_to_issue_codes() {
    let tag = "p5-unconfigured";
    let dir = outbox_dir(tag);
    std::fs::create_dir_all(&dir).expect("outbox");
    let bare = Arc::new(crate::app::App {
        store: crate::store::Store::open(
            &format!("{}/bare.db", dir.display()),
            vault42_contract::signing::now_unix(),
        )
        .expect("store"),
        authority: vault42_contract::authority::Authority::open(
            None,
            &format!("{}/bare.key", dir.display()),
            365,
        )
        .expect("authority"),
        session_ttl_secs: 3600,
        register_token: None,
        otp: crate::config::OtpConfig {
            proof_secret: None,
            ttl_secs: 300,
            proof_ttl_secs: 600,
        },
        github: crate::config::GithubConfig {
            client_id: None,
            oauth_base: "http://127.0.0.1:1".into(),
            api_base: "http://127.0.0.1:1".into(),
        },
        mail: crate::config::MailConfig {
            transport: crate::config::MailTransport::File(dir.display().to_string()),
            from: "devfast@archicode.codes".into(),
            host: String::new(),
            port: 0,
            password: None,
        },
    });
    for path in ["/v1/auth/otp/request", "/v1/auth/otp/verify"] {
        let (status, _) = send(
            &bare,
            post(
                path,
                json!({"email": "x@archicode.codes", "code": "000000"}),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{path} must refuse rather than improvise"
        );
    }
}
