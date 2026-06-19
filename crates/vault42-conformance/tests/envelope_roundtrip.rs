/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   envelope_roundtrip.rs                                :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! End-to-end envelope tests over the public API (these used to live inside
//! `vault42-core`; moved here so the core modules stay ≤5 functions each). They pin
//! the zero-knowledge contract: roundtrip, tamper→fail, non-recipient denied,
//! recipient-strip/relabel→sig-fail, scope/rollback rejection, recovery-opt-in gate.

use vault42_core::{
    open, open_keystore, seal, seal_keystore, Envelope, Error, Identity, KdfParams, Metadata,
    ReadScope, RecipientKind, Recipients,
};

fn metadata(rev: u64, recovery_optin: bool) -> Metadata {
    Metadata {
        version: 1,
        secret_id: "secret-1".into(),
        tenant: "tenant-1".into(),
        owner: "api-key:abc".into(),
        rev,
        content_type: "env".into(),
        recovery_optin,
    }
}

fn scope() -> ReadScope<'static> {
    ReadScope {
        secret_id: "secret-1",
        min_rev: 0,
    }
}

#[test]
fn seal_open_roundtrip() {
    let alice = Identity::generate();
    let author = Identity::generate();
    let users = [alice.encryption_public()];
    let recipients = Recipients {
        users: &users,
        recovery: None,
    };
    let env = seal(
        b"pw=hunter2",
        metadata(1, false),
        &recipients,
        author.signing_key(),
    )
    .expect("seal");
    let pt = open(
        &env,
        alice.encryption_secret(),
        &author.author_public(),
        &scope(),
    )
    .expect("open");
    assert_eq!(&pt[..], b"pw=hunter2");
}

#[test]
fn non_recipient_cannot_open() {
    let alice = Identity::generate();
    let bob = Identity::generate();
    let author = Identity::generate();
    let users = [alice.encryption_public()];
    let recipients = Recipients {
        users: &users,
        recovery: None,
    };
    let env = seal(b"x", metadata(1, false), &recipients, author.signing_key()).expect("seal");
    assert!(matches!(
        open(
            &env,
            bob.encryption_secret(),
            &author.author_public(),
            &scope()
        ),
        Err(Error::NotARecipient)
    ));
}

#[test]
fn recovery_recipient_opens_when_opted_in() {
    let alice = Identity::generate();
    let recovery = Identity::generate();
    let author = Identity::generate();
    let users = [alice.encryption_public()];
    let recovery_pub = recovery.encryption_public();
    let recipients = Recipients {
        users: &users,
        recovery: Some(&recovery_pub),
    };
    let env = seal(b"x", metadata(1, true), &recipients, author.signing_key()).expect("seal");
    let pt = open(
        &env,
        recovery.encryption_secret(),
        &author.author_public(),
        &scope(),
    )
    .expect("recover");
    assert_eq!(&pt[..], b"x");
}

#[test]
fn tampered_ciphertext_fails() {
    let alice = Identity::generate();
    let author = Identity::generate();
    let users = [alice.encryption_public()];
    let recipients = Recipients {
        users: &users,
        recovery: None,
    };
    let mut env = seal(
        b"secret",
        metadata(1, false),
        &recipients,
        author.signing_key(),
    )
    .expect("seal");
    env.ciphertext[0] ^= 0x01;
    assert!(open(
        &env,
        alice.encryption_secret(),
        &author.author_public(),
        &scope()
    )
    .is_err());
}

#[test]
fn stripping_recovery_breaks_signature() {
    let alice = Identity::generate();
    let recovery = Identity::generate();
    let author = Identity::generate();
    let users = [alice.encryption_public()];
    let recovery_pub = recovery.encryption_public();
    let recipients = Recipients {
        users: &users,
        recovery: Some(&recovery_pub),
    };
    let mut env = seal(b"x", metadata(1, true), &recipients, author.signing_key()).expect("seal");
    env.wrapped.retain(|w| w.kind == RecipientKind::User);
    assert!(matches!(
        open(
            &env,
            alice.encryption_secret(),
            &author.author_public(),
            &scope()
        ),
        Err(Error::Signature)
    ));
}

#[test]
fn relabeling_recovery_breaks_signature() {
    let alice = Identity::generate();
    let recovery = Identity::generate();
    let author = Identity::generate();
    let users = [alice.encryption_public()];
    let recovery_pub = recovery.encryption_public();
    let recipients = Recipients {
        users: &users,
        recovery: Some(&recovery_pub),
    };
    let mut env = seal(b"x", metadata(1, true), &recipients, author.signing_key()).expect("seal");
    for wrap in env.wrapped.iter_mut() {
        wrap.kind = RecipientKind::User;
    }
    assert!(matches!(
        open(
            &env,
            alice.encryption_secret(),
            &author.author_public(),
            &scope()
        ),
        Err(Error::Signature)
    ));
}

#[test]
fn recovery_wrap_with_optin_false_rejected() {
    let alice = Identity::generate();
    let recovery = Identity::generate();
    let author = Identity::generate();
    let users = [alice.encryption_public()];
    let recovery_pub = recovery.encryption_public();
    let recipients = Recipients {
        users: &users,
        recovery: Some(&recovery_pub),
    };
    let env = seal(b"x", metadata(1, false), &recipients, author.signing_key()).expect("seal");
    assert!(matches!(
        open(
            &env,
            alice.encryption_secret(),
            &author.author_public(),
            &scope()
        ),
        Err(Error::RecoveryNotAllowed)
    ));
}

#[test]
fn wrong_secret_id_is_scope_mismatch() {
    let alice = Identity::generate();
    let author = Identity::generate();
    let users = [alice.encryption_public()];
    let recipients = Recipients {
        users: &users,
        recovery: None,
    };
    let env = seal(b"x", metadata(1, false), &recipients, author.signing_key()).expect("seal");
    let other = ReadScope {
        secret_id: "secret-2",
        min_rev: 0,
    };
    assert!(matches!(
        open(
            &env,
            alice.encryption_secret(),
            &author.author_public(),
            &other
        ),
        Err(Error::ScopeMismatch)
    ));
}

#[test]
fn stale_revision_is_scope_mismatch() {
    let alice = Identity::generate();
    let author = Identity::generate();
    let users = [alice.encryption_public()];
    let recipients = Recipients {
        users: &users,
        recovery: None,
    };
    let env = seal(b"x", metadata(1, false), &recipients, author.signing_key()).expect("seal");
    let newer = ReadScope {
        secret_id: "secret-1",
        min_rev: 2,
    };
    assert!(matches!(
        open(
            &env,
            alice.encryption_secret(),
            &author.author_public(),
            &newer
        ),
        Err(Error::ScopeMismatch)
    ));
}

#[test]
fn duplicate_recipient_rejected() {
    let alice = Identity::generate();
    let author = Identity::generate();
    let users = [alice.encryption_public()];
    let recipients = Recipients {
        users: &users,
        recovery: None,
    };
    let mut env = seal(b"x", metadata(1, false), &recipients, author.signing_key()).expect("seal");
    let dup = env.wrapped[0].clone();
    env.wrapped.push(dup);
    assert!(matches!(
        open(
            &env,
            alice.encryption_secret(),
            &author.author_public(),
            &scope()
        ),
        Err(Error::DuplicateRecipient)
    ));
}

#[test]
fn wrong_author_rejected() {
    let alice = Identity::generate();
    let author = Identity::generate();
    let attacker = Identity::generate();
    let users = [alice.encryption_public()];
    let recipients = Recipients {
        users: &users,
        recovery: None,
    };
    let env = seal(b"x", metadata(1, false), &recipients, author.signing_key()).expect("seal");
    assert!(matches!(
        open(
            &env,
            alice.encryption_secret(),
            &attacker.author_public(),
            &scope()
        ),
        Err(Error::AuthorMismatch)
    ));
}

#[test]
fn serialization_roundtrip_preserves_decryptability() {
    let alice = Identity::generate();
    let author = Identity::generate();
    let users = [alice.encryption_public()];
    let recipients = Recipients {
        users: &users,
        recovery: None,
    };
    let env = seal(
        b"payload",
        metadata(2, false),
        &recipients,
        author.signing_key(),
    )
    .expect("seal");
    let bytes = env.to_bytes().expect("to_bytes");
    let restored = Envelope::from_bytes(&bytes).expect("from_bytes");
    let scope = ReadScope {
        secret_id: "secret-1",
        min_rev: 0,
    };
    let pt = open(
        &restored,
        alice.encryption_secret(),
        &author.author_public(),
        &scope,
    )
    .expect("open");
    assert_eq!(&pt[..], b"payload");
}

#[test]
fn from_bytes_rejects_trailing_garbage() {
    let alice = Identity::generate();
    let author = Identity::generate();
    let users = [alice.encryption_public()];
    let recipients = Recipients {
        users: &users,
        recovery: None,
    };
    let env = seal(b"x", metadata(1, false), &recipients, author.signing_key()).expect("seal");
    let mut bytes = env.to_bytes().expect("to_bytes");
    bytes.push(0xFF);
    assert!(matches!(Envelope::from_bytes(&bytes), Err(Error::Codec)));
}

#[test]
fn keystore_passphrase_change_preserves_identity() {
    let id = Identity::generate();
    let first = seal_keystore(&id, b"old", KdfParams::fast_for_tests()).expect("seal");
    let recovered = open_keystore(&first, b"old").expect("open");
    let second = seal_keystore(&recovered, b"new", KdfParams::fast_for_tests()).expect("reseal");
    let back = open_keystore(&second, b"new").expect("open new");
    assert_eq!(
        id.encryption_public().to_bytes(),
        back.encryption_public().to_bytes()
    );
}
