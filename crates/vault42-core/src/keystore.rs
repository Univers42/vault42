/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   keystore.rs                                          :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The passphrase-wrapped identity keystore. The X25519 + Ed25519 private keys are
//! AEAD-encrypted under the Argon2id-derived KSK; the stored blob holds only
//! ciphertext + public KDF parameters (safe to escrow — the server cannot open it).
//! Wrapping the keypair means a passphrase change re-wraps only this blob.

use crate::aead;
use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::kdf::{self, KdfParams};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

/// The serialized, passphrase-wrapped keystore.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeystoreBlob {
    pub salt: [u8; 16],
    pub nonce: [u8; 24],
    pub params: KdfParams,
    pub ct: Vec<u8>,
}

/// AAD binding the public KDF header to the ciphertext, so a swapped salt or cost
/// parameter is detected on open.
fn header_aad(salt: &[u8; 16], params: KdfParams) -> Vec<u8> {
    let mut aad = Vec::with_capacity(40);
    aad.extend_from_slice(b"vault42/keystore/v1");
    aad.extend_from_slice(salt);
    aad.extend_from_slice(&params.m_cost.to_le_bytes());
    aad.extend_from_slice(&params.t_cost.to_le_bytes());
    aad.extend_from_slice(&params.p_cost.to_le_bytes());
    aad
}

/// Seal `identity` under `passphrase`. The 64-byte secret (X25519 ‖ Ed25519) is
/// AEAD-encrypted under the KSK; only ciphertext is retained.
pub fn seal_keystore(
    identity: &Identity,
    passphrase: &[u8],
    params: KdfParams,
) -> Result<KeystoreBlob> {
    let mut salt = [0u8; 16];
    crate::fill_random(&mut salt)?;
    let ksk = kdf::derive_ksk(passphrase, &salt, params)?;
    let mut secret = Zeroizing::new(Vec::with_capacity(64));
    secret.extend_from_slice(&identity.enc.to_bytes());
    secret.extend_from_slice(&identity.sign.to_bytes());
    let mut nonce = [0u8; 24];
    crate::fill_random(&mut nonce)?;
    let ct = aead::encrypt(&ksk, &nonce, &secret, &header_aad(&salt, params))?;
    Ok(KeystoreBlob {
        salt,
        nonce,
        params,
        ct,
    })
}

/// Open a keystore with `passphrase`, reconstructing the identity. A wrong passphrase
/// (or any tamper) fails the AEAD open and returns `Passphrase`.
pub fn open_keystore(blob: &KeystoreBlob, passphrase: &[u8]) -> Result<Identity> {
    let ksk = kdf::derive_ksk(passphrase, &blob.salt, blob.params)?;
    let aad = header_aad(&blob.salt, blob.params);
    let secret = aead::decrypt(&ksk, &blob.nonce, &blob.ct, &aad).map_err(|_| Error::Passphrase)?;
    if secret.len() != 64 {
        return Err(Error::Format("keystore secret length"));
    }
    let mut enc = [0u8; 32];
    enc.copy_from_slice(&secret[..32]);
    let mut sgn = [0u8; 32];
    sgn.copy_from_slice(&secret[32..]);
    Ok(Identity {
        enc: StaticSecret::from(enc),
        sign: SigningKey::from_bytes(&sgn),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let id = Identity::generate();
        let blob = seal_keystore(&id, b"correct horse", KdfParams::fast_for_tests()).expect("seal");
        let back = open_keystore(&blob, b"correct horse").expect("open");
        assert_eq!(
            id.encryption_public().to_bytes(),
            back.encryption_public().to_bytes()
        );
        assert_eq!(
            id.author_public().to_bytes(),
            back.author_public().to_bytes()
        );
    }

    #[test]
    fn wrong_passphrase_fails() {
        let id = Identity::generate();
        let blob = seal_keystore(&id, b"right", KdfParams::fast_for_tests()).expect("seal");
        assert!(matches!(
            open_keystore(&blob, b"wrong"),
            Err(Error::Passphrase)
        ));
    }

    #[test]
    fn tampered_salt_fails_open() {
        let id = Identity::generate();
        let mut blob = seal_keystore(&id, b"pw", KdfParams::fast_for_tests()).expect("seal");
        blob.salt[0] ^= 0x01;
        assert!(matches!(
            open_keystore(&blob, b"pw"),
            Err(Error::Passphrase)
        ));
    }

    #[test]
    fn tampered_cost_param_fails_open() {
        let id = Identity::generate();
        let mut blob = seal_keystore(&id, b"pw", KdfParams::fast_for_tests()).expect("seal");
        blob.params.t_cost += 1;
        assert!(matches!(
            open_keystore(&blob, b"pw"),
            Err(Error::Passphrase)
        ));
    }
}
