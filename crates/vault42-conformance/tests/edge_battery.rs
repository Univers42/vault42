/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   edge_battery.rs                                      :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Crypto-core edge-case battery: hundreds-to-thousands of cases (proptest 256× each,
//! plus exhaustive byte-flip loops) exercising the zero-knowledge contract under random
//! and adversarial input. Auth/transport-independent — this pins the crypto itself.

use proptest::prelude::*;
use vault42_core::{
    fingerprint, open, seal, verify_envelope_author, Envelope, Identity, Metadata, ReadScope,
    RecipientKind, RecipientPublicKey, Recipients,
};

/// Build metadata for a case.
fn meta(owner: &str, secret: &str, rev: u64, recovery: bool) -> Metadata {
    Metadata {
        version: 1,
        secret_id: secret.to_string(),
        tenant: "t".to_string(),
        owner: owner.to_string(),
        rev,
        content_type: "opaque".to_string(),
        recovery_optin: recovery,
    }
}

/// Seal for a single self identity, returning the envelope.
fn seal_self(id: &Identity, owner: &str, secret_id: &str, rev: u64, plaintext: &[u8]) -> Envelope {
    let users = [id.encryption_public()];
    let recipients = Recipients {
        users: &users,
        recovery: None,
    };
    seal(
        plaintext,
        meta(owner, secret_id, rev, false),
        &recipients,
        id.signing_key(),
    )
    .expect("seal")
}

/// Open helper pinned to the right author + scope, returning a plain copy.
fn open_self(
    env: &Envelope,
    id: &Identity,
    secret_id: &str,
    min_rev: u64,
) -> vault42_core::Result<Vec<u8>> {
    let scope = ReadScope { secret_id, min_rev };
    open(env, id.encryption_secret(), &id.author_public(), &scope).map(|z| z.to_vec())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn roundtrip_arbitrary_plaintext(plaintext in prop::collection::vec(any::<u8>(), 0..4096usize),
                                     owner in "[a-z0-9]{1,40}", secret in "[a-z0-9/_-]{1,60}") {
        let id = Identity::generate();
        let env = seal_self(&id, &owner, &secret, 7, &plaintext);
        let bytes = env.to_bytes().expect("encode");
        let back = Envelope::from_bytes(&bytes).expect("decode");
        let opened = open_self(&back, &id, &secret, 0).expect("open");
        prop_assert_eq!(&opened[..], &plaintext[..]);
    }

    #[test]
    fn sentinel_plaintext_never_on_the_wire(tag in "[A-Z]{8,16}") {
        let id = Identity::generate();
        let sentinel = format!("SENTINEL-{tag}-SENTINEL");
        let env = seal_self(&id, "o", "s", 1, sentinel.as_bytes());
        let bytes = env.to_bytes().expect("encode");
        prop_assert!(!bytes.windows(sentinel.len()).any(|w| w == sentinel.as_bytes()));
    }

    #[test]
    fn rollback_and_substitution_rejected(rev in 1u64..1000, bump in 1u64..1000) {
        let id = Identity::generate();
        let env = seal_self(&id, "o", "secret-A", rev, b"data");
        prop_assert!(open_self(&env, &id, "secret-A", rev + bump).is_err()); // rollback (min_rev too high)
        prop_assert!(open_self(&env, &id, "secret-B", 0).is_err());          // substitution (wrong id)
    }

    #[test]
    fn wrong_identity_cannot_open(_seed in any::<u64>()) {
        let author = Identity::generate();
        let env = seal_self(&author, "o", "s", 1, b"top-secret");
        let stranger = Identity::generate();
        let scope = ReadScope { secret_id: "s", min_rev: 0 };
        // wrong recipient secret AND wrong pinned author both fail
        prop_assert!(open(&env, stranger.encryption_secret(), &author.author_public(), &scope).is_err());
        prop_assert!(open(&env, author.encryption_secret(), &stranger.author_public(), &scope).is_err());
    }

    #[test]
    fn multi_recipient_all_open_outsider_denied(n in 1usize..8) {
        let author = Identity::generate();
        let readers: Vec<Identity> = (0..n).map(|_| Identity::generate()).collect();
        let users: Vec<RecipientPublicKey> = readers.iter().map(|r| r.encryption_public()).collect();
        let recipients = Recipients { users: &users, recovery: None };
        let env = seal(b"shared", meta("o", "s", 1, false), &recipients, author.signing_key()).expect("seal");
        let scope = ReadScope { secret_id: "s", min_rev: 0 };
        for reader in &readers {
            let opened = open(&env, reader.encryption_secret(), &author.author_public(), &scope).expect("reader opens");
            prop_assert_eq!(&opened[..], b"shared");
        }
        let outsider = Identity::generate();
        prop_assert!(open(&env, outsider.encryption_secret(), &author.author_public(), &scope).is_err());
    }
}

#[test]
fn every_single_byte_flip_is_rejected() {
    let id = Identity::generate();
    let env = seal_self(&id, "owner", "secret", 3, b"the-crown-jewels");
    let bytes = env.to_bytes().expect("encode");
    let mut rejected = 0usize;
    for i in 0..bytes.len() {
        for bit in 0..8u8 {
            let mut tampered = bytes.clone();
            tampered[i] ^= 1 << bit;
            if tampered == bytes {
                continue;
            }
            let bad = match Envelope::from_bytes(&tampered) {
                Ok(env) => open_self(&env, &id, "secret", 0).is_err(),
                Err(_) => true,
            };
            assert!(
                bad,
                "a single-bit flip at byte {i} bit {bit} produced a readable secret"
            );
            rejected += 1;
        }
    }
    assert!(
        rejected > 500,
        "expected hundreds of tamper cases, ran {rejected}"
    );
}

#[test]
fn duplicate_recipient_is_rejected() {
    let id = Identity::generate();
    let key = id.encryption_public();
    let users = [key, key];
    let recipients = Recipients {
        users: &users,
        recovery: None,
    };
    assert!(seal(
        b"x",
        meta("o", "s", 1, false),
        &recipients,
        id.signing_key()
    )
    .is_err());
}

#[test]
fn recovery_wrap_without_optin_is_rejected_on_open() {
    let id = Identity::generate();
    let recovery = Identity::generate();
    let users = [id.encryption_public()];
    let recovery_pub = recovery.encryption_public();
    let recipients = Recipients {
        users: &users,
        recovery: Some(&recovery_pub),
    };
    // seal WITH a recovery wrap but metadata says optin=false → open must reject
    let env = seal(
        b"x",
        meta("o", "s", 1, false),
        &recipients,
        id.signing_key(),
    )
    .expect("seal");
    assert!(matches!(
        open_self(&env, &id, "s", 0),
        Err(vault42_core::Error::RecoveryNotAllowed)
    ));
}

#[test]
fn server_side_author_verification_matrix() {
    let author = Identity::generate();
    let env = seal_self(&author, "o", "s", 1, b"data");
    assert!(verify_envelope_author(&env, &author.author_public().to_bytes()).is_ok());
    let attacker = Identity::generate();
    assert!(verify_envelope_author(&env, &attacker.author_public().to_bytes()).is_err());
    // fingerprint is the binding between the two checks
    assert_eq!(
        fingerprint(&author.author_public().to_bytes()),
        env.author_pubkey_id
    );
}

#[test]
fn recipient_kind_relabel_breaks_open() {
    let id = Identity::generate();
    let mut env = seal_self(&id, "o", "s", 1, b"data");
    // flip a user wrap to claim it is a recovery wrap → AAD mismatch → open fails
    if let Some(w) = env.wrapped.first_mut() {
        w.kind = RecipientKind::Recovery;
    }
    assert!(open_self(&env, &id, "s", 0).is_err());
}
