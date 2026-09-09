/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   session.rs                                           :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Session token minting.
//!
//! The token is 32 bytes of OS randomness, so it is unguessable and carries no claims:
//! there is nothing in it for a client to tamper with, and revocation is a database
//! update rather than a waiting game on an expiry. Only its BLAKE3 hash is ever stored.

use base64::Engine;
use rand_core::{OsRng, RngCore};

/// Token entropy in bytes.
const TOKEN_BYTES: usize = 32;

/// A freshly minted session: the token to hand back, and what to store.
pub struct Issued {
    pub token: String,
    pub token_hash: String,
    pub expires_at: i64,
}

/// Mint a session valid for `ttl_secs` from `now`.
pub fn mint(now: i64, ttl_secs: i64) -> Issued {
    let mut raw = [0u8; TOKEN_BYTES];
    OsRng.fill_bytes(&mut raw);
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    Issued {
        token_hash: hash_token(&token),
        token,
        expires_at: now + ttl_secs,
    }
}

/// The stored form of a bearer token.
pub fn hash_token(token: &str) -> String {
    hex::encode(blake3::hash(token.as_bytes()).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unique_and_expire_when_told() {
        let a = mint(1_000, 60);
        let b = mint(1_000, 60);
        assert_ne!(a.token, b.token);
        assert_ne!(a.token_hash, b.token_hash);
        assert_eq!(a.expires_at, 1_060);
    }

    #[test]
    fn the_hash_is_stable_and_not_the_token() {
        let issued = mint(0, 1);
        assert_eq!(issued.token_hash, hash_token(&issued.token));
        assert_ne!(issued.token_hash, issued.token);
        assert_eq!(issued.token_hash.len(), 64);
    }
}
