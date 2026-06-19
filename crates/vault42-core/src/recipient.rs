/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   recipient.rs                                         :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Per-recipient DEK wrapping: a fresh ephemeral X25519 ECDH → HKDF-SHA256 → a
//! one-time Key-Encryption-Key (KEK) that AEAD-wraps the DEK. This is age's design
//! (a per-recipient stanza) without age's format (DECISIONS.md D6). Adding a
//! recipient is a client-side metadata mutation; the server never sees a DEK. All
//! intermediate secrets (the ECDH output, the KEK, the DEK) are zeroized on drop.

use crate::aead;
use crate::error::{Error, Result};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Whether a wrapped DEK is for a normal user recipient or the (operator-rooted)
/// recovery recipient (DECISIONS.md D5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecipientKind {
    User,
    Recovery,
}

impl RecipientKind {
    /// The stable byte code bound into the canonical AAD, so relabeling a wrap
    /// (User↔Recovery) breaks the author signature.
    pub(crate) fn code(self) -> u8 {
        match self {
            RecipientKind::User => 0,
            RecipientKind::Recovery => 1,
        }
    }
}

/// One recipient's wrapped DEK plus the ephemeral public key needed to re-derive
/// the KEK. `wrapped` is `AEAD(KEK, DEK, aad = recipient_id)`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrappedDek {
    pub recipient_id: [u8; 16],
    pub ephemeral_pub: [u8; 32],
    pub wrap_nonce: [u8; 24],
    pub wrapped: Vec<u8>,
    pub kind: RecipientKind,
}

/// The 16-byte fingerprint of a public key (first 16 bytes of its BLAKE3 hash),
/// used as a recipient/author identifier in metadata and the canonical AAD.
pub(crate) fn key_id(public_key_bytes: &[u8]) -> [u8; 16] {
    let hash = blake3::hash(public_key_bytes);
    let mut id = [0u8; 16];
    id.copy_from_slice(&hash.as_bytes()[..16]);
    id
}

/// Derive the one-time KEK from the ECDH shared secret, salted by both public keys
/// and domain-separated, so the KEK is unique per (ephemeral, recipient) pair.
fn derive_kek(
    shared: &[u8; 32],
    ephemeral_pub: &[u8; 32],
    recipient_pub: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(ephemeral_pub);
    salt.extend_from_slice(recipient_pub);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut kek = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"vault42/v1/wrap", kek.as_mut())
        .map_err(|_| Error::Kdf)?;
    Ok(kek)
}

/// Wrap `dek` for `recipient` using a fresh ephemeral key; only the wrapped DEK is
/// retained (the shared secret and KEK zeroize on drop).
pub fn wrap(dek: &[u8; 32], recipient: &PublicKey, kind: RecipientKind) -> Result<WrappedDek> {
    let ephemeral = StaticSecret::random();
    let ephemeral_pub = PublicKey::from(&ephemeral);
    let shared = Zeroizing::new(*ephemeral.diffie_hellman(recipient).as_bytes());
    let recipient_id = key_id(recipient.as_bytes());
    let kek = derive_kek(&shared, ephemeral_pub.as_bytes(), recipient.as_bytes())?;
    let mut wrap_nonce = [0u8; 24];
    crate::fill_random(&mut wrap_nonce)?;
    let wrapped = aead::encrypt(&kek, &wrap_nonce, dek, &recipient_id)?;
    Ok(WrappedDek {
        recipient_id,
        ephemeral_pub: ephemeral_pub.to_bytes(),
        wrap_nonce,
        wrapped,
        kind,
    })
}

/// Unwrap the DEK from `w` using the recipient's secret key, returning it in a
/// zeroizing buffer. A non-recipient (wrong secret) fails the AEAD open.
pub fn unwrap(w: &WrappedDek, recipient_secret: &StaticSecret) -> Result<Zeroizing<[u8; 32]>> {
    let ephemeral_pub = PublicKey::from(w.ephemeral_pub);
    let shared = Zeroizing::new(*recipient_secret.diffie_hellman(&ephemeral_pub).as_bytes());
    let recipient_pub = PublicKey::from(recipient_secret).to_bytes();
    let kek = derive_kek(&shared, &w.ephemeral_pub, &recipient_pub)?;
    let opened = aead::decrypt(&kek, &w.wrap_nonce, &w.wrapped, &w.recipient_id)?;
    if opened.len() != 32 {
        return Err(Error::Format("wrapped DEK length"));
    }
    let mut dek = Zeroizing::new([0u8; 32]);
    dek.copy_from_slice(&opened);
    Ok(dek)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_roundtrip() {
        let secret = StaticSecret::random();
        let public = PublicKey::from(&secret);
        let dek = [42u8; 32];
        let w = wrap(&dek, &public, RecipientKind::User).expect("wrap");
        let out = unwrap(&w, &secret).expect("unwrap");
        assert_eq!(&out[..], &dek[..]);
    }

    #[test]
    fn wrong_secret_cannot_unwrap() {
        let secret = StaticSecret::random();
        let public = PublicKey::from(&secret);
        let other = StaticSecret::random();
        let w = wrap(&[1u8; 32], &public, RecipientKind::User).expect("wrap");
        assert!(unwrap(&w, &other).is_err());
    }

    #[test]
    fn tampered_recipient_id_fails_unwrap() {
        let secret = StaticSecret::random();
        let public = PublicKey::from(&secret);
        let mut w = wrap(&[7u8; 32], &public, RecipientKind::User).expect("wrap");
        w.recipient_id[0] ^= 0x01;
        assert!(matches!(unwrap(&w, &secret), Err(Error::Aead)));
    }
}
