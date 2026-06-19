/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   sign.rs                                              :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Ed25519 author signatures. The author signs over the canonical AAD concatenated
//! with `blake3(ciphertext)`, so one signature binds the metadata, the recipient
//! set, and the exact ciphertext. A reader MUST verify the signature (and that the
//! author key matches the pinned identity) BEFORE attempting decryption.

use crate::error::{Error, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// Build the signed message: `canonical_aad || blake3(ciphertext)`.
fn message(aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(aad.len() + 32);
    msg.extend_from_slice(aad);
    msg.extend_from_slice(blake3::hash(ciphertext).as_bytes());
    msg
}

/// Sign `(aad, ciphertext)` with the author's signing key, returning the 64-byte
/// detached Ed25519 signature.
pub fn sign(author: &SigningKey, aad: &[u8], ciphertext: &[u8]) -> [u8; 64] {
    author.sign(&message(aad, ciphertext)).to_bytes()
}

/// Verify the author signature with `verify_strict` (rejects malleable / weak-key
/// signatures) — the pre-decrypt verification gate. Returns `Err(Signature)` on any
/// mismatch; the caller does not decrypt on failure.
pub fn verify(
    author: &VerifyingKey,
    aad: &[u8],
    ciphertext: &[u8],
    signature: &[u8; 64],
) -> Result<()> {
    let signature = Signature::from_bytes(signature);
    author
        .verify_strict(&message(aad, ciphertext), &signature)
        .map_err(|_| Error::Signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn sign_then_verify_ok() {
        let signing = SigningKey::generate(&mut OsRng);
        let signature = sign(&signing, b"aad", b"ct");
        assert!(verify(&signing.verifying_key(), b"aad", b"ct", &signature).is_ok());
    }

    #[test]
    fn tampered_signature_fails() {
        let signing = SigningKey::generate(&mut OsRng);
        let mut signature = sign(&signing, b"aad", b"ct");
        signature[0] ^= 0x01;
        assert!(verify(&signing.verifying_key(), b"aad", b"ct", &signature).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let signing = SigningKey::generate(&mut OsRng);
        let attacker = SigningKey::generate(&mut OsRng);
        let signature = sign(&signing, b"aad", b"ct");
        assert!(verify(&attacker.verifying_key(), b"aad", b"ct", &signature).is_err());
    }
}
