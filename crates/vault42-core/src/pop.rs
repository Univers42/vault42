/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   pop.rs                                               :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The canonical proof-of-possession message.
//!
//! A member registers an X25519 encryption public key so an administrator can wrap an
//! environment's scope key to them. Nothing stops a member submitting somebody else's public
//! key, so the registration carries an Ed25519 signature over this message, binding the key
//! to the account and organization registering it.
//!
//! It lives in the crypto core because BOTH sides must build byte-identical bytes: the
//! authority verifies what 42ctl signed. A copy on each side would drift silently, each half
//! internally consistent while no longer agreeing, and the symptom would be every proof
//! failing at once.
//!
//! The framing is the security property. A bare concatenation of the three values is not
//! injective: account "alice" in org "acme" and account "alicea" in org "cme" produce
//! identical bytes, so one member's proof would verify as another's. Organization slugs are
//! user-chosen, which makes that reachable rather than theoretical.

use crate::framing::frame;

/// Domain tag: a proof of possession must never verify as any other kind of signature.
const DOMAIN: &[u8] = b"vault42/pop/v1";

/// Build the canonical proof-of-possession message.
///
/// `x25519_pub` is the encoded public key exactly as it appears on the wire; it is framed as
/// the caller presents it so verification never has to re-encode and risk a mismatch.
pub fn pop_message(account_id: &str, org_id: &str, x25519_pub: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + account_id.len() + org_id.len() + x25519_pub.len());
    frame(&mut out, DOMAIN);
    frame(&mut out, account_id.as_bytes());
    frame(&mut out, org_id.as_bytes());
    frame(&mut out, x25519_pub.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_domain_tag_leads_the_message() {
        assert!(pop_message("u", "o", "K").starts_with(b"14:vault42/pop/v1\n"));
    }

    #[test]
    fn the_message_is_injective_over_every_field_boundary() {
        assert_ne!(
            pop_message("alice", "acme", "K"),
            pop_message("alicea", "cme", "K")
        );
        assert_ne!(pop_message("a", "bc", "K"), pop_message("ab", "c", "K"));
        assert_ne!(pop_message("", "abc", "K"), pop_message("abc", "", "K"));
        assert_ne!(pop_message("u", "o", "KK"), pop_message("u", "oK", "K"));
    }

    /// A golden digest pins the wire format, exactly as the canonical AAD is pinned.
    ///
    /// A failing digest is the alarm working: every proof of possession ever issued was
    /// signed over these bytes, so changing them invalidates all of them. Bump the domain tag
    /// and migrate deliberately rather than updating this value.
    #[test]
    fn the_frozen_format_matches_its_golden_digest() {
        let message = pop_message("acct-1", "org-1", "AAAA");
        let digest = blake3::hash(&message);
        assert_eq!(
            digest.to_hex().as_str(),
            "228fc54881e0e21303a03a2af1d537e6e3c09b0aa8a0407bbcd2f2857d658317",
            "the proof-of-possession framing is FROZEN; see this test's doc comment"
        );
    }
}
