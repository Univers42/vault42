/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   request.rs                                           :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Transport request authentication — pure crypto shared by the server (verify) and
//! the CLI (sign), so the principal identifier and the challenge signature have ONE
//! definition. The principal is the 16-byte fingerprint of the caller's Ed25519
//! author key (the same key that authors envelopes), so storage owner-scoping and
//! envelope authorship resolve to the same identity with no extra credential.

use crate::recipient;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// The 16-byte principal fingerprint of an Ed25519 author public key — the stable
/// owner identifier the server scopes storage by (same derivation the envelope uses).
pub fn fingerprint(author_public_key: &[u8; 32]) -> [u8; 16] {
    recipient::key_id(author_public_key)
}

/// Sign a transport challenge (the caller builds `ts\nmethod`) with the author
/// signing key, returning the 64-byte detached Ed25519 signature.
pub fn sign_request(signing_key: &SigningKey, challenge: &[u8]) -> [u8; 64] {
    signing_key.sign(challenge).to_bytes()
}

/// Verify a transport challenge signature against an author public key. Returns
/// `false` on any malformed key/signature rather than erroring, so the caller maps a
/// bad signature straight to an authentication denial.
///
/// Uses `verify_strict`, matching `open()`. Plain `verify` accepts small-order public
/// keys, and a small-order key is one anybody can produce a passing signature for — so
/// the owner id derived from such a key would be impersonable by any caller. Every
/// legitimate signature comes from a dalek signer and is canonical, so strictness costs
/// nothing and closes that gap.
pub fn verify_request(author_public_key: &[u8; 32], challenge: &[u8], sig: &[u8; 64]) -> bool {
    match VerifyingKey::from_bytes(author_public_key) {
        Ok(vk) => vk
            .verify_strict(challenge, &Signature::from_bytes(sig))
            .is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    #[test]
    fn sign_then_verify_roundtrips() {
        let key = SigningKey::generate(&mut OsRng);
        let pubkey = key.verifying_key().to_bytes();
        let sig = sign_request(&key, b"1700\n/vault.v1.Vault/Push");
        assert!(verify_request(&pubkey, b"1700\n/vault.v1.Vault/Push", &sig));
    }

    #[test]
    fn wrong_challenge_fails() {
        let key = SigningKey::generate(&mut OsRng);
        let pubkey = key.verifying_key().to_bytes();
        let sig = sign_request(&key, b"1700\n/vault.v1.Vault/Push");
        assert!(!verify_request(&pubkey, b"1700\n/vault.v1.Vault/Get", &sig));
    }

    #[test]
    fn fingerprint_matches_envelope_author_id() {
        let key = SigningKey::generate(&mut OsRng);
        let pubkey = key.verifying_key().to_bytes();
        assert_eq!(fingerprint(&pubkey), recipient::key_id(&pubkey));
    }

    #[test]
    fn a_small_order_public_key_cannot_authenticate() {
        let zeros = [0u8; 32];
        let key = SigningKey::generate(&mut OsRng);
        let sig = sign_request(&key, b"challenge");
        assert!(
            !verify_request(&zeros, b"challenge", &sig),
            "verify_strict must refuse a small-order public key"
        );
        for candidate in [[0u8; 32], {
            let mut one = [0u8; 32];
            one[0] = 1;
            one
        }] {
            assert!(
                !verify_request(&candidate, b"challenge", &[0u8; 64]),
                "a small-order key must never verify, whatever the signature"
            );
        }
    }
}
