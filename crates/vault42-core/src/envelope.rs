/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   envelope.rs                                          :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The zero-knowledge envelope: the single wire type the server stores opaquely. It
//! holds ciphertext + per-recipient wrapped DEKs + signed metadata + the author
//! signature. The server treats it as opaque bytes; only this crate can open it.
//! `seal`/`open` (separate modules) produce and consume it.

use crate::error::{Error, Result};
use crate::metadata::Metadata;
use crate::recipient::WrappedDek;
use bincode::Options;
use serde::{Deserialize, Serialize};

/// Upper bound on a serialized envelope, enforced by the codec so a malicious server
/// cannot drive an unbounded allocation through `from_bytes`. 64 MiB holds a large
/// secret/archive payload.
const MAX_ENVELOPE_BYTES: u64 = 64 * 1024 * 1024;

/// A stored secret: the AEAD payload, one DEK wrap per recipient (sorted by id), and
/// signed metadata. `author_sig` (64 bytes) binds metadata + recipient set + ciphertext.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 24],
    pub wrapped: Vec<WrappedDek>,
    pub metadata: Metadata,
    pub author_sig: Vec<u8>,
    pub author_pubkey_id: [u8; 16],
}

/// The bincode configuration used both directions: fixed-int encoding (stable across
/// versions), a hard size limit (DoS bound), and reject-trailing (decode-safe).
fn codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_ENVELOPE_BYTES)
}

impl Envelope {
    /// Serialize to opaque bytes for storage. The server cannot decrypt the result.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        codec().serialize(self).map_err(|_| Error::Codec)
    }

    /// Deserialize from stored bytes; malformed/oversized input returns `Codec`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        codec().deserialize(bytes).map_err(|_| Error::Codec)
    }
}

/// The `(id, kind_code)` pairs the canonical AAD binds, taken from an envelope's wraps.
pub(crate) fn recipient_pairs(wrapped: &[WrappedDek]) -> Vec<([u8; 16], u8)> {
    wrapped
        .iter()
        .map(|w| (w.recipient_id, w.kind.code()))
        .collect()
}

/// Reject a recipient set that is not a set (duplicate ids), enforcing the AAD
/// injectivity contract in code rather than by signature luck.
pub(crate) fn reject_duplicates(pairs: &[([u8; 16], u8)]) -> Result<()> {
    let mut ids: Vec<[u8; 16]> = pairs.iter().map(|(id, _)| *id).collect();
    ids.sort_unstable();
    if ids.windows(2).any(|w| w[0] == w[1]) {
        return Err(Error::DuplicateRecipient);
    }
    Ok(())
}
