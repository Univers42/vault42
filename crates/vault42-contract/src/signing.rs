/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   signing.rs                                           :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Contract signing-key persistence. The key is the root of trust the whole duo hangs
//! on — vault42 verifies every contract against its public half — so it must be stable
//! across restarts. It is loaded from a hex seed (env or file) or generated once and
//! written `0600` to the encrypted volume.

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use std::time::{SystemTime, UNIX_EPOCH};

/// Reconstruct a signing key from a 32-byte hex seed.
pub(crate) fn from_hex_seed(hex_seed: &str) -> anyhow::Result<SigningKey> {
    let bytes = hex::decode(hex_seed.trim())?;
    let seed: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("contract seed must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Load the signing key from `path`, or generate one and persist it there.
pub(crate) fn load_or_create(path: &str) -> anyhow::Result<SigningKey> {
    if let Ok(hex_seed) = std::fs::read_to_string(path) {
        return from_hex_seed(&hex_seed);
    }
    let signing = SigningKey::generate(&mut OsRng);
    persist(path, &signing.to_bytes())?;
    Ok(signing)
}

/// Write the seed hex to `path`, owner-only on Unix.
fn persist(path: &str, seed: &[u8; 32]) -> anyhow::Result<()> {
    std::fs::write(path, hex::encode(seed))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Current Unix time in seconds — the contract issue/expiry clock.
pub(crate) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
