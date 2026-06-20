/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   jwt.rs                                                :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/20 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/20 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Per-owner GoTrue JWT minting — the bridge that turns vault42's authenticated
//! Ed25519 principal into grobase per-user owner-scoping. The subject is a
//! `uuid5` of the principal (deterministic, derived ONLY from the authenticated
//! identity — never client input), so the data plane stamps `owner_id = user:<sub>`
//! and a principal can never forge another's scope. The JWT only owner-scopes; the
//! blob it guards stays client-encrypted, so zero-knowledge is preserved.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

/// A stable namespace so `uuid5(principal)` is deterministic per principal across
/// restarts and machines, and disjoint from any other uuid5 space.
const VAULT42_OWNER_NS: Uuid = Uuid::from_bytes([
    0x42, 0x76, 0x61, 0x75, 0x6c, 0x74, 0x34, 0x32, 0x6f, 0x77, 0x6e, 0x65, 0x72, 0x6e, 0x73, 0x21,
]);

/// JWT minting failure (HMAC key rejection is unreachable for HMAC, mapped anyway).
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("jwt sign")]
    Sign,
}

/// The GoTrue-shaped subject for `principal`: the deterministic owner uuid the data
/// plane scopes on. Derived only from the authenticated principal id.
pub fn owner_subject(principal: &str) -> String {
    Uuid::new_v5(&VAULT42_OWNER_NS, principal.as_bytes()).to_string()
}

/// Mint a short-lived HS256 GoTrue JWT for `subject`, signed with the co-deployed
/// `secret`. `now`/`ttl` are seconds; the token carries `role`/`aud=authenticated`
/// so the data plane treats it as an end-user session.
pub fn mint(secret: &[u8], subject: &str, now: i64, ttl: i64) -> Result<String, JwtError> {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let claims = serde_json::json!({
        "sub": subject,
        "role": "authenticated",
        "aud": "authenticated",
        "iat": now,
        "exp": now + ttl,
    });
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
    let signing_input = format!("{header}.{payload}");
    let signature = sign_hs256(secret, signing_input.as_bytes())?;
    Ok(format!("{signing_input}.{signature}"))
}

/// HMAC-SHA256 of `message` under `secret`, base64url (no pad) — the JWS signature.
fn sign_hs256(secret: &[u8], message: &[u8]) -> Result<String, JwtError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| JwtError::Sign)?;
    mac.update(message);
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_is_deterministic_and_principal_specific() {
        assert_eq!(owner_subject("api-key:abc"), owner_subject("api-key:abc"));
        assert_ne!(owner_subject("api-key:abc"), owner_subject("api-key:xyz"));
    }

    #[test]
    fn mint_has_three_segments() {
        let token = mint(b"secret", "sub-1", 1_750_000_000, 3600).expect("mint");
        assert_eq!(token.split('.').count(), 3);
    }
}
