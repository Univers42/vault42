/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   keyset_sig.rs                                        :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/21 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/21 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The canonical byte framing a scope-key grant is signed over. Mirrors `aad.rs`:
//! every field is `<decimal-len> ':' <bytes> '\n'` in a FIXED order, so the framing
//! is injective — no value choice can shift bytes between `scope_id`/`epoch`/
//! `member_id`/`wrapped` to forge a grant that verifies under a different tuple. The
//! `GRANT_DOMAIN` tag keeps these bytes from ever colliding with the envelope AAD.

use crate::recipient::WrappedDek;

/// Domain separator for grant signatures, distinct from `vault42/aad/v2`.
const GRANT_DOMAIN: &[u8] = b"vault42/grant/v1";

/// Append one length-prefixed field `<len> ':' <value> '\n'`.
fn frame(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(value.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(value);
    out.push(b'\n');
}

/// Build the canonical grant message: the domain tag, then `scope_id`, `epoch`,
/// `member_id`, and the full wrapped-key material (id, ephemeral pub, nonce, kind,
/// ciphertext), each length-prefixed in a FIXED order. Binding the whole `WrappedDek`
/// means a server cannot swap the wrapped bytes while keeping the granter signature.
pub(crate) fn canonical_grant(
    scope_id: &[u8; 16],
    epoch: u32,
    member_id: &[u8; 16],
    w: &WrappedDek,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(160 + w.wrapped.len());
    frame(&mut out, GRANT_DOMAIN);
    frame(&mut out, scope_id);
    frame(&mut out, &epoch.to_le_bytes());
    frame(&mut out, member_id);
    frame(&mut out, &w.recipient_id);
    frame(&mut out, &w.ephemeral_pub);
    frame(&mut out, &w.wrap_nonce);
    frame(&mut out, &[w.kind.code()]);
    frame(&mut out, &w.wrapped);
    out
}
