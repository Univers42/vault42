/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   open.rs                                              :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Opening: verify the requested scope, recovery-consistency, the recipient set, and
//! the author signature BEFORE decrypting, then unwrap this recipient's DEK and
//! decrypt. A malicious server can change none of these without detection.

use crate::aad;
use crate::aead;
use crate::envelope::{recipient_pairs, reject_duplicates, Envelope};
use crate::error::{Error, Result};
use crate::metadata::{Metadata, ReadScope};
use crate::recipient::{self, RecipientKind};
use crate::sign;
use ed25519_dalek::VerifyingKey;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Reject an envelope that does not match the requested secret / minimum rev — this
/// is what binds the response to the request (anti-substitution, anti-rollback).
fn check_scope(meta: &Metadata, scope: &ReadScope) -> Result<()> {
    if meta.secret_id != scope.secret_id || meta.rev < scope.min_rev {
        return Err(Error::ScopeMismatch);
    }
    Ok(())
}

/// Reject a recovery-kind wrap when the metadata says recovery is off — catches a
/// client that attached operator recovery while claiming it didn't ("not retroactive").
fn reject_unexpected_recovery(env: &Envelope) -> Result<()> {
    let has_recovery = env
        .wrapped
        .iter()
        .any(|w| w.kind == RecipientKind::Recovery);
    if !env.metadata.recovery_optin && has_recovery {
        return Err(Error::RecoveryNotAllowed);
    }
    Ok(())
}

/// Pin the author key, then strict-verify the signature over the canonical AAD plus
/// ciphertext. Always runs before any decryption.
fn verify_author(env: &Envelope, author: &VerifyingKey, canonical: &[u8]) -> Result<()> {
    if env.author_sig.len() != 64 {
        return Err(Error::Format("signature length"));
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&env.author_sig);
    if recipient::key_id(author.as_bytes()) != env.author_pubkey_id {
        return Err(Error::AuthorMismatch);
    }
    sign::verify(author, canonical, &env.ciphertext, &signature)
}

/// Find this recipient's wrap by id and unwrap the DEK with the recipient secret.
fn unwrap_for(env: &Envelope, recipient_secret: &StaticSecret) -> Result<Zeroizing<[u8; 32]>> {
    let my_id = recipient::key_id(PublicKey::from(recipient_secret).as_bytes());
    let mine = env
        .wrapped
        .iter()
        .find(|w| w.recipient_id == my_id)
        .ok_or(Error::NotARecipient)?;
    recipient::unwrap(mine, recipient_secret)
}

/// Open `env` for `recipient_secret`, authored by the pinned `author`, for `scope`.
/// Returns the plaintext in a zeroizing buffer; any check failure returns `Err`.
pub fn open(
    env: &Envelope,
    recipient_secret: &StaticSecret,
    author: &VerifyingKey,
    scope: &ReadScope,
) -> Result<Zeroizing<Vec<u8>>> {
    check_scope(&env.metadata, scope)?;
    reject_unexpected_recovery(env)?;
    let pairs = recipient_pairs(&env.wrapped);
    reject_duplicates(&pairs)?;
    let canonical = aad::canonical(&env.metadata, &pairs);
    verify_author(env, author, &canonical)?;
    let dek = unwrap_for(env, recipient_secret)?;
    aead::decrypt(&dek, &env.nonce, &env.ciphertext, &canonical)
}
