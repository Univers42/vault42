/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   seal.rs                                              :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Sealing: encipher a plaintext into an `Envelope` for a recipient set (plus an
//! optional recovery recipient), authored and signed locally. A fresh random DEK +
//! nonce are used and the DEK is zeroized after wrapping, so the server never sees it.

use crate::aad;
use crate::aead;
use crate::envelope::{reject_duplicates, Envelope};
use crate::error::Result;
use crate::metadata::Metadata;
use crate::recipient::{self, RecipientKind, WrappedDek};
use crate::sign;
use ed25519_dalek::SigningKey;
use x25519_dalek::PublicKey;
use zeroize::Zeroizing;

/// The recipients a secret is sealed for: the user keys plus an optional recovery key.
pub struct Recipients<'a> {
    pub users: &'a [PublicKey],
    pub recovery: Option<&'a PublicKey>,
}

/// Flatten the recipients into `(key, kind)`, recovery last.
fn recipient_list<'a>(recipients: &'a Recipients<'a>) -> Vec<(&'a PublicKey, RecipientKind)> {
    let mut all: Vec<(&PublicKey, RecipientKind)> = recipients
        .users
        .iter()
        .map(|key| (key, RecipientKind::User))
        .collect();
    if let Some(recovery) = recipients.recovery {
        all.push((recovery, RecipientKind::Recovery));
    }
    all
}

/// The `(id, kind_code)` pairs the AAD binds for this recipient set.
fn id_pairs(all: &[(&PublicKey, RecipientKind)]) -> Vec<([u8; 16], u8)> {
    all.iter()
        .map(|(key, kind)| (recipient::key_id(key.as_bytes()), kind.code()))
        .collect()
}

/// Wrap the DEK for every recipient, returning the wraps sorted by id (canonical).
fn wrap_all(dek: &[u8; 32], all: &[(&PublicKey, RecipientKind)]) -> Result<Vec<WrappedDek>> {
    let mut wrapped = Vec::with_capacity(all.len());
    for (key, kind) in all {
        wrapped.push(recipient::wrap(dek, key, *kind)?);
    }
    wrapped.sort_by_key(|w| w.recipient_id);
    Ok(wrapped)
}

/// Seal `plaintext` for `recipients`, authored by `author`. The recipient set must
/// have no duplicate ids; the fresh DEK is zeroized after wrapping.
pub fn seal(
    plaintext: &[u8],
    metadata: Metadata,
    recipients: &Recipients,
    author: &SigningKey,
) -> Result<Envelope> {
    let all = recipient_list(recipients);
    let pairs = id_pairs(&all);
    reject_duplicates(&pairs)?;
    let canonical = aad::canonical(&metadata, &pairs);
    let mut dek = Zeroizing::new([0u8; 32]);
    crate::fill_random(dek.as_mut())?;
    let mut nonce = [0u8; 24];
    crate::fill_random(&mut nonce)?;
    let ciphertext = aead::encrypt(&dek, &nonce, plaintext, &canonical)?;
    let wrapped = wrap_all(&dek, &all)?;
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
