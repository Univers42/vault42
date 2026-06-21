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

/// The path-aware kind of an envelope. `Manifest` is the per-project encrypted
/// index; the rest are leaf blobs. `#[repr(u8)]` with explicit discriminants pins
/// the single byte the canonical AAD frames, so the value is stable forever.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Kind {
    Generic = 0,
    EnvFile = 1,
    Note = 2,
    Manifest = 3,
}

/// The default file mode applied to a materialized secret — owner read/write only.
pub const DEFAULT_MODE: u32 = 0o600;

/// Authenticated, non-secret metadata. Bound into the canonical AAD, so the server
/// cannot alter any field without invalidating the author signature.
///
/// `version` is the FROZEN-format era (`2` since the path-aware fields were added);
/// `project_id` is an opaque per-project handle (safe to expose); `relative_path`
/// MUST stay empty on a leaf blob on the wire — the real path lives only inside the
/// encrypted manifest, so the server never learns plaintext paths.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Metadata {
    pub version: u32,
    pub secret_id: String,
    pub tenant: String,
    pub owner: String,
    pub rev: u64,
    pub content_type: String,
    pub recovery_optin: bool,
    pub project_id: String,
    pub relative_path: String,
    pub kind: Kind,
    pub mode: u32,
}

/// The caller's expectation for an `open`: which secret was requested and the
/// minimum acceptable revision. `open` rejects a mismatch, so a malicious server
/// cannot substitute a different validly-signed envelope or replay a stale rev.
pub struct ReadScope<'a> {
    pub secret_id: &'a str,
    pub min_rev: u64,
}
