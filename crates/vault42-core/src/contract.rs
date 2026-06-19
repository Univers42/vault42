/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   contract.rs                                          :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The grobase↔vault42 CONTRACT token: a compact Ed25519-signed credential the
//! authority issues once at registration and vault42 verifies OFFLINE on every request
//! (no per-request call back to the authority). It binds a tenant to an author key
//! fingerprint with an expiry, so the authority idles after issuing while the consuming
//! server does the work. base64url-wrapped; the layout is FROZEN like the envelope.

use crate::error::{Error, Result};
use base64::Engine as _;
use bincode::Options;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// A contract's authenticated claims.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contract {
    pub version: u8,
    pub tenant: String,
    pub author_fp: [u8; 16],
    pub issued_at: i64,
    pub expires_at: i64,
}

/// Wire shape: the contract payload bytes + the authority signature over them.
#[derive(Serialize, Deserialize)]
struct Signed {
    payload: Vec<u8>,
    sig: Vec<u8>,
}

/// Bincode options for the contract: fixed-int, 64 KiB cap, reject trailing input.
fn codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(64 * 1024)
}

/// Issue a base64url contract token signed by the authority `signing_key`.
pub fn issue_contract(signing_key: &SigningKey, contract: &Contract) -> Result<String> {
    let payload = codec().serialize(contract).map_err(|_| Error::Codec)?;
    let sig = signing_key.sign(&payload).to_bytes().to_vec();
    let signed = codec()
        .serialize(&Signed { payload, sig })
        .map_err(|_| Error::Codec)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signed))
}

/// Verify a contract token against the authority public key, checking the signature and
/// expiry at `now` (unix seconds). Returns the claims; the caller still binds author_fp.
pub fn verify_contract(authority_pub: &[u8; 32], token: &str, now: i64) -> Result<Contract> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| Error::Format("contract encoding"))?;
    let signed: Signed = codec().deserialize(&raw).map_err(|_| Error::Codec)?;
    if signed.sig.len() != 64 {
        return Err(Error::Format("contract signature length"));
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&signed.sig);
    let verifying =
        VerifyingKey::from_bytes(authority_pub).map_err(|_| Error::Format("authority key"))?;
    verifying
        .verify_strict(&signed.payload, &Signature::from_bytes(&sig))
        .map_err(|_| Error::Signature)?;
    let contract: Contract = codec()
        .deserialize(&signed.payload)
        .map_err(|_| Error::Codec)?;
    if now > contract.expires_at {
        return Err(Error::Expired);
    }
    Ok(contract)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn contract() -> Contract {
        Contract {
            version: 1,
            tenant: "acme".into(),
            author_fp: [7u8; 16],
            issued_at: 1000,
            expires_at: 2000,
        }
    }

    #[test]
    fn issue_then_verify_roundtrips() {
        let key = SigningKey::generate(&mut OsRng);
        let token = issue_contract(&key, &contract()).expect("issue");
        let out = verify_contract(&key.verifying_key().to_bytes(), &token, 1500).expect("verify");
        assert_eq!(out.tenant, "acme");
        assert_eq!(out.author_fp, [7u8; 16]);
    }

    #[test]
    fn expired_is_rejected() {
        let key = SigningKey::generate(&mut OsRng);
        let token = issue_contract(&key, &contract()).expect("issue");
        assert!(matches!(
            verify_contract(&key.verifying_key().to_bytes(), &token, 2500),
            Err(Error::Expired)
        ));
    }

    #[test]
    fn wrong_authority_key_is_rejected() {
        let key = SigningKey::generate(&mut OsRng);
        let attacker = SigningKey::generate(&mut OsRng);
        let token = issue_contract(&key, &contract()).expect("issue");
        assert!(verify_contract(&attacker.verifying_key().to_bytes(), &token, 1500).is_err());
    }

    #[test]
    fn tampered_token_is_rejected() {
        let key = SigningKey::generate(&mut OsRng);
        let mut token = issue_contract(&key, &contract()).expect("issue");
        token.insert(4, 'A');
        assert!(verify_contract(&key.verifying_key().to_bytes(), &token, 1500).is_err());
    }
}
