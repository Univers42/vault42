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

//! Proof of possession for a member's public keys.
//!
//! A member registers an X25519 encryption key so administrators can wrap an environment's
//! scope key to them. Nothing stops a member from submitting somebody else's public key, so
//! the registration carries an Ed25519 signature binding the key to the registering account
//! and organization. That signature is this module's whole subject.
//!
//! **The framing is the security property.** The message is length-framed field by field,
//! exactly as `vault42-core`'s canonical AAD is framed. A bare concatenation of user id,
//! organization id and key would not be injective: user "alice" in org "acme" and user
//! "alicea" in org "cme" produce identical bytes, so one member's proof would verify as
//! another's. Organization slugs are user-chosen, which makes that reachable rather than
//! theoretical. A leading domain tag additionally stops a proof of possession from ever
//! verifying as an envelope-author signature.
//!
//! The message binds the organization's canonical **id**, never a slug or any other alias a
//! user typed. Two aliases for one organization would otherwise produce two different valid
//! proofs for the same key, and only one of them would verify against a stored signature.
//! `GET /v1/orgs/:org` exists so a client can resolve an alias to the id before signing.
//!
//! The message itself is built by `vault42_core::pop_message`, not here. Both this verifier
//! and 42ctl's signer call that one definition, so the two halves cannot drift apart — which
//! is the failure mode a local copy on each side would eventually produce, silently.

use base64::Engine;
use vault42_core::pop_message;

/// What a member presents when registering keys.
pub struct Claim<'a> {
    pub account_id: &'a str,
    pub org_id: &'a str,
    pub x25519_pub: &'a str,
    pub ed25519_pub: &'a str,
    pub pubkey_sig: &'a str,
}

/// True when the claim's signature proves possession of its Ed25519 key over its own
/// account, organization and X25519 key.
///
/// Returns false for any malformed field rather than erroring, so a bad registration is
/// refused rather than becoming a server error. Verification is `verify_strict`, via
/// `vault42_core::verify_request`, so a small-order key cannot pass.
pub fn verify(claim: &Claim<'_>) -> bool {
    let standard = base64::engine::general_purpose::STANDARD;
    let (Ok(ed), Ok(sig)) = (
        standard.decode(claim.ed25519_pub),
        standard.decode(claim.pubkey_sig),
    ) else {
        return false;
    };
    let (Ok(ed), Ok(sig)): (Result<[u8; 32], _>, Result<[u8; 64], _>) =
        (ed.try_into(), sig.try_into())
    else {
        return false;
    };
    if standard.decode(claim.x25519_pub).map(|raw| raw.len()) != Ok(32) {
        return false;
    }
    let expected = pop_message(claim.account_id, claim.org_id, claim.x25519_pub);
    vault42_core::verify_request(&ed, &expected, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault42_core::Identity;

    /// Build a genuine claim for `identity` over `(account, org)`.
    fn signed(identity: &Identity, account: &str, org: &str) -> (String, String, String) {
        let standard = base64::engine::general_purpose::STANDARD;
        let x25519 = standard.encode(identity.encryption_public().to_bytes());
        let ed25519 = standard.encode(identity.author_public().to_bytes());
        let sig =
            vault42_core::sign_request(identity.signing_key(), &pop_message(account, org, &x25519));
        (x25519, ed25519, standard.encode(sig))
    }

    #[test]
    fn a_genuine_proof_verifies() {
        let identity = Identity::generate();
        let (x25519, ed25519, sig) = signed(&identity, "acct-1", "org-1");
        assert!(verify(&Claim {
            account_id: "acct-1",
            org_id: "org-1",
            x25519_pub: &x25519,
            ed25519_pub: &ed25519,
            pubkey_sig: &sig,
        }));
    }

    #[test]
    fn a_proof_cannot_be_replayed_across_a_colliding_pair() {
        let identity = Identity::generate();
        let (x25519, ed25519, sig) = signed(&identity, "alice", "acme");
        assert!(
            !verify(&Claim {
                account_id: "alicea",
                org_id: "cme",
                x25519_pub: &x25519,
                ed25519_pub: &ed25519,
                pubkey_sig: &sig,
            }),
            "\"alice\"+\"acme\" and \"alicea\"+\"cme\" concatenate identically; framing must \
             keep the proof bound to its own pairing"
        );
    }

    #[test]
    fn a_wrong_account_org_or_key_is_refused() {
        let identity = Identity::generate();
        let other = Identity::generate();
        let (x25519, ed25519, sig) = signed(&identity, "acct-1", "org-1");
        let standard = base64::engine::general_purpose::STANDARD;
        let foreign = standard.encode(other.encryption_public().to_bytes());
        for claim in [
            Claim {
                account_id: "acct-2",
                org_id: "org-1",
                x25519_pub: &x25519,
                ed25519_pub: &ed25519,
                pubkey_sig: &sig,
            },
            Claim {
                account_id: "acct-1",
                org_id: "org-2",
                x25519_pub: &x25519,
                ed25519_pub: &ed25519,
                pubkey_sig: &sig,
            },
            Claim {
                account_id: "acct-1",
                org_id: "org-1",
                x25519_pub: &foreign,
                ed25519_pub: &ed25519,
                pubkey_sig: &sig,
            },
        ] {
            assert!(
                !verify(&claim),
                "a substituted field must invalidate the proof"
            );
        }
    }

    #[test]
    fn malformed_fields_are_refused_rather_than_erroring() {
        let identity = Identity::generate();
        let (x25519, ed25519, sig) = signed(&identity, "acct-1", "org-1");
        let cases = [
            ("not-base64!!", ed25519.as_str(), sig.as_str()),
            (x25519.as_str(), "not-base64!!", sig.as_str()),
            (x25519.as_str(), ed25519.as_str(), "not-base64!!"),
            ("", ed25519.as_str(), sig.as_str()),
            (x25519.as_str(), "", sig.as_str()),
        ];
        for (x, ed, s) in cases {
            assert!(!verify(&Claim {
                account_id: "acct-1",
                org_id: "org-1",
                x25519_pub: x,
                ed25519_pub: ed,
                pubkey_sig: s,
            }));
        }
    }

    #[test]
    fn a_small_order_ed25519_key_cannot_prove_possession() {
        let standard = base64::engine::general_purpose::STANDARD;
        let identity = Identity::generate();
        let (x25519, _, sig) = signed(&identity, "acct-1", "org-1");
        assert!(!verify(&Claim {
            account_id: "acct-1",
            org_id: "org-1",
            x25519_pub: &x25519,
            ed25519_pub: &standard.encode([0u8; 32]),
            pubkey_sig: &sig,
        }));
    }
}
