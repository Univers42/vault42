/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   metadata.rs                                          :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Envelope metadata and the read-scope an `open` is bound to. Pure data, no
//! behaviour: `Metadata` is the non-secret, signature-bound description of a secret;
//! `ReadScope` is the caller's request expectation that `open` checks against.

use serde::{Deserialize, Serialize};

/// Authenticated, non-secret metadata. Bound into the canonical AAD, so the server
/// cannot alter any field without invalidating the author signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Metadata {
    pub version: u32,
    pub secret_id: String,
    pub tenant: String,
    pub owner: String,
    pub rev: u64,
    pub content_type: String,
    pub recovery_optin: bool,
}

/// The caller's expectation for an `open`: which secret was requested and the
/// minimum acceptable revision. `open` rejects a mismatch, so a malicious server
/// cannot substitute a different validly-signed envelope or replay a stale rev.
pub struct ReadScope<'a> {
    pub secret_id: &'a str,
    pub min_rev: u64,
}
