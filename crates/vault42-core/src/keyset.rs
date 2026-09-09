/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   keyset.rs                                            :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/21 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/21 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Scope-keypair (KEK hierarchy): an environment scope owns its own X25519 keypair.
//! Secrets are sealed to the scope's PUBLIC key (`scope_recipients`); the scope's
//! PRIVATE key is `recipient::wrap`-wrapped to each member's personal X25519 key and
//! signed by a granting admin (`grant_scope_key`). A member does a TWO-HOP unwrap —
//! `open_scope_key` recovers the scope secret, then `open()` reads the secret. The
//! granter signature is bound to `scope_id ‖ epoch ‖ member_id ‖ wrapped` with the
//! same length-prefixed injective framing as `aad.rs`, so a server cannot move a
//! grant to another scope/epoch/member without breaking the signature. Zero-knowledge
//! holds: every step runs client-side and the scope private key never leaves a
//! `Zeroizing` buffer.

use crate::error::{Error, Result};
use crate::keyset_sig::canonical_grant;
use crate::recipient::{self, RecipientKind, WrappedDek};
use crate::seal::Recipients;
use bincode::Options;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Upper bound on a serialized grant, enforced by the codec so a malicious server
/// cannot drive an unbounded allocation through `from_bytes`. A grant is a few
/// hundred bytes; 64 KiB is generous headroom.
const MAX_GRANT_BYTES: u64 = 64 * 1024;

/// The public half of a scope keyset: the scope identity, its key epoch, and the
/// X25519 public key secrets are sealed to. `scope_id`/`epoch` are bound into every
/// grant signature, so a rotated epoch's grants cannot be replayed against an old one.
pub struct ScopeKeyset {
    pub scope_id: [u8; 16],
    pub epoch: u32,
    pub public: PublicKey,
}

/// A scope private key wrapped to one member and signed by a granting admin. Holding
/// this plus the member's X25519 secret yields the scope secret via `open_scope_key`.
/// `Serialize`/`Deserialize` let the server store and verify it opaquely (it carries no
/// scope secret in the clear — only the AEAD-wrapped material and the granter signature).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrantedScopeKey {
    pub scope_id: [u8; 16],
    pub epoch: u32,
    pub member_id: [u8; 16],
    pub wrapped: WrappedDek,
    pub granter_sig: Vec<u8>,
    pub granter_pubkey_id: [u8; 16],
}

/// The bincode configuration for a grant blob: fixed-int encoding (stable across
/// versions) and a hard size limit (DoS bound).
fn grant_codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_GRANT_BYTES)
}

impl GrantedScopeKey {
    /// Serialize to opaque bytes the server can store and round-trip. The blob carries
    /// no scope secret in the clear — only AEAD-wrapped material the server cannot open.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        grant_codec().serialize(self).map_err(|_| Error::Codec)
    }

    /// Deserialize from stored bytes; malformed/oversized input returns `Codec`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        grant_codec().deserialize(bytes).map_err(|_| Error::Codec)
    }
}

/// Generate a fresh scope keyset: a new X25519 keypair from the OS CSPRNG. Returns the
/// public keyset and the scope private key in a zeroizing buffer (never persisted raw).
pub fn generate_keyset(scope_id: [u8; 16], epoch: u32) -> (ScopeKeyset, Zeroizing<[u8; 32]>) {
    let secret = StaticSecret::random();
    let public = PublicKey::from(&secret);
    let scope_secret = Zeroizing::new(secret.to_bytes());
    (
        ScopeKeyset {
            scope_id,
            epoch,
            public,
        },
        scope_secret,
    )
}

/// Wrap `scope_secret` to `member_pub` and sign the canonical grant with `granter`.
/// The signature binds `scope_id`/`epoch`/`member_id`/`wrapped`, so the grant cannot
/// be re-pointed at another scope, epoch, member, or wrap without detection.
pub fn grant_scope_key(
    scope_secret: &Zeroizing<[u8; 32]>,
    member_pub: &PublicKey,
    granter: &SigningKey,
    scope_id: [u8; 16],
    epoch: u32,
) -> Result<GrantedScopeKey> {
    let wrapped = recipient::wrap(scope_secret, member_pub, RecipientKind::User)?;
    let member_id = recipient::key_id(member_pub.as_bytes());
    let message = canonical_grant(&scope_id, epoch, &member_id, &wrapped);
    let granter_sig = granter.sign(&message).to_bytes().to_vec();
    let granter_pubkey_id = recipient::key_id(granter.verifying_key().as_bytes());
    Ok(GrantedScopeKey {
        scope_id,
        epoch,
        member_id,
        wrapped,
        granter_sig,
        granter_pubkey_id,
    })
}

/// Pin the granter and verify the grant signature over the canonical bytes WITHOUT
/// unwrapping (no member secret needed). A bad/forged signature or a mutated
/// `scope_id`/`epoch`/`member_id`/`wrapped` returns `GranterMismatch`. This is the gate
/// the orchestrating server runs server-side before storing a grant — it proves the
/// grant is granter-authentic while staying zero-knowledge (it never opens the wrap).
pub fn verify_grant_signature(g: &GrantedScopeKey, granter_pub: &VerifyingKey) -> Result<()> {
    if g.granter_sig.len() != 64 || recipient::key_id(granter_pub.as_bytes()) != g.granter_pubkey_id
    {
        return Err(Error::GranterMismatch);
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&g.granter_sig);
    let message = canonical_grant(&g.scope_id, g.epoch, &g.member_id, &g.wrapped);
    granter_pub
        .verify_strict(&message, &Signature::from_bytes(&signature))
        .map_err(|_| Error::GranterMismatch)
}

/// Pin the granter, verify the grant signature over the canonical bytes, then unwrap
/// the scope secret with the member's X25519 key. A bad/forged signature or a mutated
/// `scope_id`/`epoch`/`member_id`/`wrapped` returns `GranterMismatch`; a non-member
/// secret fails the AEAD open. Returns the scope private key in a zeroizing buffer.
pub fn open_scope_key(
    g: &GrantedScopeKey,
    member_secret: &StaticSecret,
    granter_pub: &VerifyingKey,
) -> Result<Zeroizing<[u8; 32]>> {
    verify_grant_signature(g, granter_pub)?;
    recipient::unwrap(&g.wrapped, member_secret)
}

/// Build the `Recipients` that seal a secret to this scope: the sole user recipient is
/// the scope public key, plus the optional recovery key. The member never appears here
/// — members reach the secret only via the wrapped scope key (`open_scope_key`).
pub fn scope_recipients<'a>(
    keyset: &'a ScopeKeyset,
    recovery: Option<&'a PublicKey>,
) -> Recipients<'a> {
    Recipients {
        users: std::slice::from_ref(&keyset.public),
        recovery,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::{Kind, Metadata, ReadScope, DEFAULT_MODE};
    use crate::{open, seal};
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn scope_meta() -> Metadata {
        Metadata {
            version: 2,
            secret_id: "scope-secret".into(),
            tenant: "t-scope".into(),
            owner: "scope:env-prod".into(),
            rev: 1,
            content_type: "env".into(),
            recovery_optin: false,
            project_id: "p-scope".into(),
            relative_path: String::new(),
            kind: Kind::Generic,
            mode: DEFAULT_MODE,
        }
    }

    fn recover_scope_secret(scope_priv: &Zeroizing<[u8; 32]>) -> StaticSecret {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&scope_priv[..]);
        StaticSecret::from(bytes)
    }

    #[test]
    fn two_hop_roundtrip_recovers_plaintext() {
        let author = SigningKey::generate(&mut OsRng);
        let granter = SigningKey::generate(&mut OsRng);
        let member = StaticSecret::random();
        let member_pub = PublicKey::from(&member);
        let (keyset, scope_secret) = generate_keyset([1u8; 16], 1);
        let plaintext = b"DATABASE_URL=postgres://prod";
        let recipients = scope_recipients(&keyset, None);
        let env = seal(plaintext, scope_meta(), &recipients, &author).expect("seal");
        let grant =
            grant_scope_key(&scope_secret, &member_pub, &granter, [1u8; 16], 1).expect("grant");
        let opened_scope =
            open_scope_key(&grant, &member, &granter.verifying_key()).expect("open scope");
        let scope_priv = recover_scope_secret(&opened_scope);
        let scope = ReadScope {
            secret_id: "scope-secret",
            min_rev: 0,
        };
        let out = open(&env, &scope_priv, &author.verifying_key(), &scope).expect("open secret");
        assert_eq!(&out[..], plaintext);
    }

    #[test]
    fn opened_scope_key_equals_generated_secret() {
        let granter = SigningKey::generate(&mut OsRng);
        let member = StaticSecret::random();
        let member_pub = PublicKey::from(&member);
        let (_keyset, scope_secret) = generate_keyset([2u8; 16], 4);
        let grant =
            grant_scope_key(&scope_secret, &member_pub, &granter, [2u8; 16], 4).expect("grant");
        let opened = open_scope_key(&grant, &member, &granter.verifying_key()).expect("open");
        assert_eq!(&opened[..], &scope_secret[..]);
    }

    #[test]
    fn wrong_member_cannot_open_scope_key() {
        let granter = SigningKey::generate(&mut OsRng);
        let member = StaticSecret::random();
        let member_pub = PublicKey::from(&member);
        let intruder = StaticSecret::random();
        let (_keyset, scope_secret) = generate_keyset([3u8; 16], 1);
        let grant =
            grant_scope_key(&scope_secret, &member_pub, &granter, [3u8; 16], 1).expect("grant");
        assert!(open_scope_key(&grant, &intruder, &granter.verifying_key()).is_err());
    }

    #[test]
    fn tampered_granter_sig_is_rejected() {
        let granter = SigningKey::generate(&mut OsRng);
        let member = StaticSecret::random();
        let member_pub = PublicKey::from(&member);
        let (_keyset, scope_secret) = generate_keyset([4u8; 16], 2);
        let mut grant =
            grant_scope_key(&scope_secret, &member_pub, &granter, [4u8; 16], 2).expect("grant");
        grant.granter_sig[0] ^= 0x01;
        assert!(matches!(
            open_scope_key(&grant, &member, &granter.verifying_key()),
            Err(Error::GranterMismatch)
        ));
    }

    #[test]
    fn mutated_scope_id_breaks_signature() {
        let granter = SigningKey::generate(&mut OsRng);
        let member = StaticSecret::random();
        let member_pub = PublicKey::from(&member);
        let (_keyset, scope_secret) = generate_keyset([5u8; 16], 1);
        let mut grant =
            grant_scope_key(&scope_secret, &member_pub, &granter, [5u8; 16], 1).expect("grant");
        grant.scope_id[0] ^= 0x01;
        assert!(matches!(
            open_scope_key(&grant, &member, &granter.verifying_key()),
            Err(Error::GranterMismatch)
        ));
    }

    #[test]
    fn mutated_epoch_breaks_signature() {
        let granter = SigningKey::generate(&mut OsRng);
        let member = StaticSecret::random();
        let member_pub = PublicKey::from(&member);
        let (_keyset, scope_secret) = generate_keyset([6u8; 16], 1);
        let mut grant =
            grant_scope_key(&scope_secret, &member_pub, &granter, [6u8; 16], 1).expect("grant");
        grant.epoch = 2;
        assert!(matches!(
            open_scope_key(&grant, &member, &granter.verifying_key()),
            Err(Error::GranterMismatch)
        ));
    }

    #[test]
    fn wrong_granter_key_is_rejected() {
        let granter = SigningKey::generate(&mut OsRng);
        let attacker = SigningKey::generate(&mut OsRng);
        let member = StaticSecret::random();
        let member_pub = PublicKey::from(&member);
        let (_keyset, scope_secret) = generate_keyset([8u8; 16], 1);
        let grant =
            grant_scope_key(&scope_secret, &member_pub, &granter, [8u8; 16], 1).expect("grant");
        assert!(matches!(
            open_scope_key(&grant, &member, &attacker.verifying_key()),
            Err(Error::GranterMismatch)
        ));
    }

    #[test]
    fn verify_grant_signature_accepts_genuine_grant() {
        let granter = SigningKey::generate(&mut OsRng);
        let member_pub = PublicKey::from(&StaticSecret::random());
        let (_keyset, scope_secret) = generate_keyset([9u8; 16], 3);
        let grant =
            grant_scope_key(&scope_secret, &member_pub, &granter, [9u8; 16], 3).expect("grant");
        assert!(verify_grant_signature(&grant, &granter.verifying_key()).is_ok());
    }

    #[test]
    fn verify_grant_signature_rejects_tamper_and_wrong_granter() {
        let granter = SigningKey::generate(&mut OsRng);
        let attacker = SigningKey::generate(&mut OsRng);
        let member_pub = PublicKey::from(&StaticSecret::random());
        let (_keyset, scope_secret) = generate_keyset([10u8; 16], 1);
        let mut grant =
            grant_scope_key(&scope_secret, &member_pub, &granter, [10u8; 16], 1).expect("grant");
        assert!(matches!(
            verify_grant_signature(&grant, &attacker.verifying_key()),
            Err(Error::GranterMismatch)
        ));
        grant.granter_sig[0] ^= 0x01;
        assert!(matches!(
            verify_grant_signature(&grant, &granter.verifying_key()),
            Err(Error::GranterMismatch)
        ));
    }

    #[test]
    fn grant_bytes_roundtrip_and_verify() {
        let granter = SigningKey::generate(&mut OsRng);
        let member_pub = PublicKey::from(&StaticSecret::random());
        let (_keyset, scope_secret) = generate_keyset([11u8; 16], 7);
        let grant =
            grant_scope_key(&scope_secret, &member_pub, &granter, [11u8; 16], 7).expect("grant");
        let bytes = grant.to_bytes().expect("to_bytes");
        let back = GrantedScopeKey::from_bytes(&bytes).expect("from_bytes");
        assert_eq!(back.scope_id, grant.scope_id);
        assert_eq!(back.epoch, grant.epoch);
        assert!(verify_grant_signature(&back, &granter.verifying_key()).is_ok());
    }
}
