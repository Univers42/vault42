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

/// Decode a hex Ed25519 public key, reject unusable ones, and return its fingerprint.
///
/// Rejecting weak keys is load-bearing, not defensive tidiness. `from_bytes` accepts any
/// encoding that decompresses to a curve point, which includes the small-order points —
/// all-zeros among them. `verify_strict`, which every vault42 request path uses, rejects
/// small-order public keys outright. So a key that passes `from_bytes` but is weak would
/// register successfully and then fail every subsequent signature check: the tenant name
/// is consumed and the identity can never authenticate. Refuse it at the boundary
/// instead, where the caller can still fix it.
pub fn parse_fp(pubkey_hex: &str) -> Result<[u8; 16], String> {
    let bytes =
        hex::decode(pubkey_hex.trim()).map_err(|_| "author_pubkey must be hex".to_string())?;
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "author_pubkey must be 32 bytes".to_string())?;
    let parsed = VerifyingKey::from_bytes(&key)
        .map_err(|_| "author_pubkey is not a valid key".to_string())?;
    if parsed.is_weak() {
        return Err("author_pubkey is a small-order key and could never authenticate".to_string());
    }
    Ok(fingerprint(&key))
}

/// True if `tenant` is a safe slug: 1..=64 of `[A-Za-z0-9_-]`.
pub fn valid_tenant(tenant: &str) -> bool {
    !tenant.is_empty()
        && tenant.len() <= 64
        && tenant
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_real_key_parses_to_its_fingerprint() {
        let identity = vault42_core::Identity::generate();
        let key = identity.author_public().to_bytes();
        assert_eq!(parse_fp(&hex::encode(key)).unwrap(), fingerprint(&key));
    }

    #[test]
    fn malformed_author_keys_are_refused() {
        assert!(parse_fp("").is_err());
        assert!(parse_fp("nothex").is_err());
        assert!(parse_fp(&"aa".repeat(31)).is_err());
        assert!(parse_fp(&"aa".repeat(33)).is_err());
    }

    #[test]
    fn small_order_keys_are_refused_before_they_consume_a_tenant_name() {
        for weak in [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ] {
            let refused = parse_fp(weak);
            assert!(
                refused.is_err(),
                "{weak} decompresses to a small-order point and must be refused"
            );
        }
    }

    #[test]
    fn tenant_slugs_follow_the_documented_rule() {
        assert!(valid_tenant("alice"));
        assert!(valid_tenant("a-b_C9"));
        assert!(valid_tenant(&"x".repeat(64)));
        assert!(!valid_tenant(""));
        assert!(!valid_tenant(&"x".repeat(65)));
        assert!(!valid_tenant("has space"));
        assert!(!valid_tenant("has/slash"));
    }
}
