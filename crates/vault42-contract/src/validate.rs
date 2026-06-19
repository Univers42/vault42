/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   validate.rs                                          :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Input validation for registration — reject junk before it becomes a signed contract.
//! An author key must be a real Ed25519 point (not just 32 bytes), and a tenant name
//! must be a safe slug (it ends up in a signed contract and an audit label).

use ed25519_dalek::VerifyingKey;
use vault42_core::fingerprint;

/// Decode a hex Ed25519 public key, reject non-points, and return its author fingerprint.
pub(crate) fn parse_fp(pubkey_hex: &str) -> Result<[u8; 16], String> {
    let bytes =
        hex::decode(pubkey_hex.trim()).map_err(|_| "author_pubkey must be hex".to_string())?;
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "author_pubkey must be 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&key).map_err(|_| "author_pubkey is not a valid key".to_string())?;
    Ok(fingerprint(&key))
}

/// True if `tenant` is a safe slug: 1..=64 of `[A-Za-z0-9_-]`.
pub(crate) fn valid_tenant(tenant: &str) -> bool {
    !tenant.is_empty()
        && tenant.len() <= 64
        && tenant
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}
