/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   aead.rs                                              :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Authenticated encryption over a Data-Encryption-Key (DEK), via
//! XChaCha20-Poly1305. The 192-bit (24-byte) nonce makes random nonces
//! collision-safe by construction, so callers may always pick a fresh random
//! nonce (no counter state, no reuse hazard — THREAT-MODEL R10).

use crate::error::{Error, Result};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

/// Encrypt `plaintext` under `key` with the given 24-byte `nonce`, binding `aad`
/// (the additional authenticated data — tampering with it fails the open). The
/// returned vector is ciphertext with the 16-byte Poly1305 tag appended.
pub fn encrypt(key: &[u8; 32], nonce: &[u8; 24], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Aead)
}

/// Decrypt `ciphertext` under `key`/`nonce`, requiring `aad` to match what was
/// bound at seal time. Any single-byte tamper of ciphertext, nonce, or AAD makes
/// this return `Err(Aead)` — never partial or unauthenticated plaintext. The
/// recovered plaintext is wrapped in `Zeroizing` so it is wiped on drop.
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Aead)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixtures() -> ([u8; 32], [u8; 24]) {
        ([7u8; 32], [9u8; 24])
    }

    #[test]
    fn roundtrip_recovers_plaintext() {
        let (key, nonce) = fixtures();
        let ct = encrypt(&key, &nonce, b"top secret", b"aad").expect("encrypt");
        let pt = decrypt(&key, &nonce, &ct, b"aad").expect("decrypt");
        assert_eq!(&pt[..], b"top secret");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (key, nonce) = fixtures();
        let mut ct = encrypt(&key, &nonce, b"top secret", b"aad").expect("encrypt");
        ct[0] ^= 0x01;
        assert!(matches!(
            decrypt(&key, &nonce, &ct, b"aad"),
            Err(Error::Aead)
        ));
    }

    #[test]
    fn wrong_aad_fails() {
        let (key, nonce) = fixtures();
        let ct = encrypt(&key, &nonce, b"top secret", b"aad").expect("encrypt");
        assert!(matches!(
            decrypt(&key, &nonce, &ct, b"other"),
            Err(Error::Aead)
        ));
    }
}
