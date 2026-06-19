/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   address.rs                                           :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The shareable vault42 address: `v42:<base64url(ed25519_pub ‖ x25519_pub)>`. It
//! carries both public keys a sharer needs — the Ed25519 key fixes the recipient's
//! principal (their owner space) and the X25519 key is the wrap target. No private
//! material is ever in an address.

use base64::Engine as _;
use vault42_core::{Identity, RecipientPublicKey};

/// Encode an identity's public keys into a shareable address.
pub fn encode(identity: &Identity) -> String {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&identity.author_public().to_bytes());
    buf.extend_from_slice(&identity.encryption_public().to_bytes());
    format!(
        "v42:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
    )
}

/// Decode an address into the recipient's principal id and X25519 wrap key.
pub fn decode(addr: &str) -> anyhow::Result<(String, RecipientPublicKey)> {
    let b64 = addr
        .strip_prefix("v42:")
        .ok_or_else(|| anyhow::anyhow!("address must start with v42:"))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64)?;
    if bytes.len() != 64 {
        anyhow::bail!("address must decode to 64 bytes");
    }
    let mut author = [0u8; 32];
    author.copy_from_slice(&bytes[..32]);
    let mut enc = [0u8; 32];
    enc.copy_from_slice(&bytes[32..]);
    let principal = hex::encode(vault42_core::fingerprint(&author));
    Ok((principal, RecipientPublicKey::from(enc)))
}

/// A short, human-readable prefix of an address for log/print output.
pub fn short(addr: &str) -> String {
    addr.chars().take(20).collect()
}
