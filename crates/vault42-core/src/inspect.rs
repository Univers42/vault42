/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   inspect.rs                                           :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Server-side envelope inspection that upholds zero-knowledge: verify the author
//! signature WITHOUT decrypting. The orchestrating server holds no recipient key, so
//! it can never read plaintext — but it can still prove a stored envelope is
//! well-formed and authored by the caller, rejecting forged or misattributed blobs
//! before they reach storage. This reuses the same canonical AAD the reader checks.

use crate::aad;
use crate::envelope::{recipient_pairs, reject_duplicates, Envelope};
use crate::error::{Error, Result};
use crate::recipient;
use crate::sign;
use ed25519_dalek::VerifyingKey;

/// Verify `env`'s author signature against `author_public_key` without decrypting.
/// Confirms the author fingerprint matches the pinned key and the signature covers
/// the canonical AAD + ciphertext. Returns `Err` on any mismatch — the server then
/// refuses to store the envelope.
pub fn verify_envelope_author(env: &Envelope, author_public_key: &[u8; 32]) -> Result<()> {
    if recipient::key_id(author_public_key) != env.author_pubkey_id {
        return Err(Error::AuthorMismatch);
    }
    if env.author_sig.len() != 64 {
        return Err(Error::Format("signature length"));
    }
    let verifying =
        VerifyingKey::from_bytes(author_public_key).map_err(|_| Error::Format("author key"))?;
    let pairs = recipient_pairs(&env.wrapped);
    reject_duplicates(&pairs)?;
    let canonical = aad::canonical(&env.metadata, &pairs);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&env.author_sig);
    sign::verify(&verifying, &canonical, &env.ciphertext, &signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::Metadata;
    use crate::seal::{seal, Recipients};
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn meta() -> Metadata {
        Metadata {
            version: 1,
            secret_id: "s-1".into(),
            tenant: "self".into(),
            owner: "owner-1".into(),
            rev: 1,
            content_type: "env".into(),
            recovery_optin: false,
        }
    }

    #[test]
    fn verifies_genuine_author_without_decrypting() {
        let author = SigningKey::generate(&mut OsRng);
        let recipient = PublicKey::from(&StaticSecret::random());
        let recipients = Recipients {
            users: &[recipient],
            recovery: None,
        };
        let env = seal(b"top secret", meta(), &recipients, &author).expect("seal");
        let pubkey = author.verifying_key().to_bytes();
        assert!(verify_envelope_author(&env, &pubkey).is_ok());
    }

    #[test]
    fn rejects_wrong_author_key() {
        let author = SigningKey::generate(&mut OsRng);
        let attacker = SigningKey::generate(&mut OsRng);
        let recipient = PublicKey::from(&StaticSecret::random());
        let env = seal(
            b"x",
            meta(),
            &Recipients {
                users: &[recipient],
                recovery: None,
            },
            &author,
        )
        .expect("seal");
        assert!(verify_envelope_author(&env, &attacker.verifying_key().to_bytes()).is_err());
    }
}
