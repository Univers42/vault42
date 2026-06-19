/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   principal.rs                                         :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The authenticated caller. The principal id is the hex of the caller's Ed25519
//! author-key fingerprint — the SAME identity that authors envelopes — so storage
//! owner-scoping and envelope authorship resolve to one value with no extra
//! credential. `tenant` is a grobase tenant binding when grobase is wired, else "self".

/// An authenticated caller, resolved from the signed transport metadata.
#[derive(Clone)]
pub struct Principal {
    pub id: String,
    pub pubkey: [u8; 32],
    pub tenant: String,
}

impl Principal {
    /// Build a principal from a verified Ed25519 author public key. The tenant defaults
    /// to "self"; a verified contract replaces it with the registered tenant.
    pub fn from_pubkey(pubkey: [u8; 32]) -> Self {
        Self {
            id: hex::encode(vault42_core::fingerprint(&pubkey)),
            pubkey,
            tenant: "self".to_string(),
        }
    }

    /// Bind this principal to the tenant named in a verified contract.
    pub fn with_tenant(mut self, tenant: String) -> Self {
        self.tenant = tenant;
        self
    }
}
