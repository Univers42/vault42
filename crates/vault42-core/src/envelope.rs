//! The zero-knowledge envelope: the single wire type the server stores opaquely.
//! WRITE enciphers locally under a fresh DEK, wraps the DEK per recipient (plus the
//! recovery recipient when opted in), and signs the canonical AAD. READ verifies
//! the author signature BEFORE decrypting. The server never sees the DEK or
//! plaintext — THREAT-MODEL: the one guarantee.

use crate::aad;
use crate::aead;
use crate::error::{Error, Result};
use crate::recipient::{self, RecipientKind, WrappedDek};
use crate::sign;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Authenticated, non-secret metadata. Bound into the AAD, so the server cannot
/// alter any field without invalidating the author signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Metadata {
    pub version: u32,
    pub secret_id: String,
    pub tenant: String,
    pub owner: String,
    pub rev: u64,
    pub content_type: String,
    pub recovery_optin: bool,
}

/// A stored secret. `ciphertext`/`nonce` are the AEAD payload; `wrapped` carries one
/// DEK wrap per recipient; `author_sig` (64 bytes) binds metadata + recipients + ct.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 24],
    pub wrapped: Vec<WrappedDek>,
    pub metadata: Metadata,
    pub author_sig: Vec<u8>,
    pub author_pubkey_id: [u8; 16],
}

impl Envelope {
    /// Serialize to opaque bytes for the grobase `vault42_secrets.envelope` column.
    /// The server treats the result as opaque — it cannot decrypt it.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|_| Error::Codec)
    }

    /// Deserialize from stored bytes; malformed input returns `Codec`, never panics.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|_| Error::Codec)
    }
}

/// Collect recipient public keys (users first, then the optional recovery
/// recipient) so seal wraps and binds exactly this set.
fn recipient_list<'a>(
    users: &'a [PublicKey],
    recovery: Option<&'a PublicKey>,
) -> Vec<(&'a PublicKey, RecipientKind)> {
    let mut all: Vec<(&PublicKey, RecipientKind)> =
        users.iter().map(|p| (p, RecipientKind::User)).collect();
    if let Some(recovery_key) = recovery {
        all.push((recovery_key, RecipientKind::Recovery));
    }
    all
}

/// Seal `plaintext` for `users` (and `recovery` when opted in), authored by
/// `author`. A fresh random DEK + nonce are used; the DEK is zeroized after
/// wrapping. Returns the signed envelope.
pub fn seal(
    plaintext: &[u8],
    metadata: Metadata,
    users: &[PublicKey],
    author: &SigningKey,
    recovery: Option<&PublicKey>,
) -> Result<Envelope> {
    let all = recipient_list(users, recovery);
    let ids: Vec<[u8; 16]> = all
        .iter()
        .map(|(p, _)| recipient::key_id(p.as_bytes()))
        .collect();
    let canonical = aad::canonical(&metadata, &ids);
    let mut dek = Zeroizing::new([0u8; 32]); // sec: DEK zeroized on drop
    crate::fill_random(dek.as_mut())?;
    let mut nonce = [0u8; 24];
    crate::fill_random(&mut nonce)?;
    let ciphertext = aead::encrypt(&dek, &nonce, plaintext, &canonical)?;
    let mut wrapped = Vec::with_capacity(all.len());
    for (pubkey, kind) in &all {
        wrapped.push(recipient::wrap(&dek, pubkey, *kind)?);
    }
    let author_sig = sign::sign(author, &canonical, &ciphertext).to_vec();
    let author_pubkey_id = recipient::key_id(author.verifying_key().as_bytes());
    Ok(Envelope {
        ciphertext,
        nonce,
        wrapped,
        metadata,
        author_sig,
        author_pubkey_id,
    })
}

/// Open an envelope addressed to `recipient_secret`, verifying it was authored by
/// the pinned `author`. The author signature (and author identity) are checked
/// BEFORE any decryption. Returns the plaintext in a zeroizing buffer.
pub fn open(
    env: &Envelope,
    recipient_secret: &StaticSecret,
    author: &VerifyingKey,
) -> Result<Zeroizing<Vec<u8>>> {
    let ids: Vec<[u8; 16]> = env.wrapped.iter().map(|w| w.recipient_id).collect();
    let canonical = aad::canonical(&env.metadata, &ids);
    if env.author_sig.len() != 64 {
        return Err(Error::Format("signature length"));
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&env.author_sig);
    if recipient::key_id(author.as_bytes()) != env.author_pubkey_id {
        return Err(Error::AuthorMismatch); // sec: pin the author key before trusting the signature
    }
    sign::verify(author, &canonical, &env.ciphertext, &signature)?; // sec: verify before decrypt
    let my_id = recipient::key_id(PublicKey::from(recipient_secret).as_bytes());
    let mine = env
        .wrapped
        .iter()
        .find(|w| w.recipient_id == my_id)
        .ok_or(Error::NotARecipient)?;
    let dek = recipient::unwrap(mine, recipient_secret)?;
    aead::decrypt(&dek, &env.nonce, &env.ciphertext, &canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::Identity;

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

    #[test]
    fn seal_open_roundtrip() {
        let alice = Identity::generate();
        let author = Identity::generate();
        let env = seal(
            b"pw=hunter2",
            metadata(1, false),
            &[alice.encryption_public()],
            author.signing_key(),
            None,
        )
        .expect("seal");
        let pt = open(&env, alice.encryption_secret(), &author.author_public()).expect("open");
        assert_eq!(&pt[..], b"pw=hunter2");
    }

    #[test]
    fn non_recipient_cannot_open() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let author = Identity::generate();
        let env = seal(
            b"x",
            metadata(1, false),
            &[alice.encryption_public()],
            author.signing_key(),
            None,
        )
        .expect("seal");
        assert!(matches!(
            open(&env, bob.encryption_secret(), &author.author_public()),
            Err(Error::NotARecipient)
        ));
    }

    #[test]
    fn recovery_recipient_can_open_when_opted_in() {
        let alice = Identity::generate();
        let recovery = Identity::generate();
        let author = Identity::generate();
        let env = seal(
            b"x",
            metadata(1, true),
            &[alice.encryption_public()],
            author.signing_key(),
            Some(&recovery.encryption_public()),
        )
        .expect("seal");
        let pt =
            open(&env, recovery.encryption_secret(), &author.author_public()).expect("recover");
        assert_eq!(&pt[..], b"x");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let alice = Identity::generate();
        let author = Identity::generate();
        let mut env = seal(
            b"secret",
            metadata(1, false),
            &[alice.encryption_public()],
            author.signing_key(),
            None,
        )
        .expect("seal");
        env.ciphertext[0] ^= 0x01;
        assert!(open(&env, alice.encryption_secret(), &author.author_public()).is_err());
    }

    #[test]
    fn stripping_recovery_recipient_breaks_signature() {
        let alice = Identity::generate();
        let recovery = Identity::generate();
        let author = Identity::generate();
        let mut env = seal(
            b"x",
            metadata(1, true),
            &[alice.encryption_public()],
            author.signing_key(),
            Some(&recovery.encryption_public()),
        )
        .expect("seal");
        env.wrapped.retain(|w| w.kind == RecipientKind::User);
        assert!(matches!(
            open(&env, alice.encryption_secret(), &author.author_public()),
            Err(Error::Signature)
        ));
    }

    #[test]
    fn wrong_author_rejected() {
        let alice = Identity::generate();
        let author = Identity::generate();
        let attacker = Identity::generate();
        let env = seal(
            b"x",
            metadata(1, false),
            &[alice.encryption_public()],
            author.signing_key(),
            None,
        )
        .expect("seal");
        assert!(matches!(
            open(&env, alice.encryption_secret(), &attacker.author_public()),
            Err(Error::AuthorMismatch)
        ));
    }

    #[test]
    fn serialization_roundtrip_preserves_decryptability() {
        let alice = Identity::generate();
        let author = Identity::generate();
        let env = seal(
            b"payload",
            metadata(2, false),
            &[alice.encryption_public()],
            author.signing_key(),
            None,
        )
        .expect("seal");
        let bytes = env.to_bytes().expect("to_bytes");
        let restored = Envelope::from_bytes(&bytes).expect("from_bytes");
        let pt = open(
            &restored,
            alice.encryption_secret(),
            &author.author_public(),
        )
        .expect("open");
        assert_eq!(&pt[..], b"payload");
    }
}
