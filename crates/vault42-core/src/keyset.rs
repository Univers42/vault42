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
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

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
pub struct GrantedScopeKey {
    pub scope_id: [u8; 16],
    pub epoch: u32,
    pub member_id: [u8; 16],
    pub wrapped: WrappedDek,
    pub granter_sig: Vec<u8>,
    pub granter_pubkey_id: [u8; 16],
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

/// Pin the granter, verify the grant signature over the canonical bytes, then unwrap
/// the scope secret with the member's X25519 key. A bad/forged signature or a mutated
/// `scope_id`/`epoch`/`member_id`/`wrapped` returns `GranterMismatch`; a non-member
/// secret fails the AEAD open. Returns the scope private key in a zeroizing buffer.
pub fn open_scope_key(
    g: &GrantedScopeKey,
    member_secret: &StaticSecret,
    granter_pub: &VerifyingKey,
) -> Result<Zeroizing<[u8; 32]>> {
    if g.granter_sig.len() != 64 || recipient::key_id(granter_pub.as_bytes()) != g.granter_pubkey_id
    {
        return Err(Error::GranterMismatch);
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&g.granter_sig);
    let message = canonical_grant(&g.scope_id, g.epoch, &g.member_id, &g.wrapped);
    granter_pub
        .verify_strict(&message, &Signature::from_bytes(&signature))
        .map_err(|_| Error::GranterMismatch)?;
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
}
