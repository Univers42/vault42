/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   aad.rs                                               :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The canonical Additional-Authenticated-Data (AAD) framing. This is the FROZEN,
//! injective serialization the AEAD and the author signature are bound to —
//! changing it changes every signature, so it must stay byte-stable forever
//! (mirrors grobase's `audit/chain.go` length-prefixed canonical form).
//!
//! Injectivity: each field is emitted as `<decimal-len> ':' <bytes> '\n'`. Every
//! field — and every recipient `(id, kind)` pair — carries its own length prefix,
//! the fields are in a FIXED positional order, and the recipient count is framed
//! before the pairs. So no choice of values can produce the same byte stream as a
//! different tuple: an attacker cannot shift bytes between owner/tenant/secret_id,
//! add/remove/reorder a recipient, or relabel its kind (User↔Recovery) without
//! changing the canonical bytes — and thus the signature. Callers must pass a
//! de-duplicated recipient set (enforced in `envelope`).

use crate::metadata::Metadata;

/// Domain separator so AAD bytes can never collide with any other signed context.
const DOMAIN: &[u8] = b"vault42/aad/v1";

/// Append one length-prefixed field: `<len> ':' <value> '\n'`.
fn frame(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(value.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(value);
    out.push(b'\n');
}

/// Build the canonical AAD: the domain tag, the metadata in a FIXED order, then the
/// recipient set sorted by id and framed as `(id, kind)` pairs (count-prefixed).
pub fn canonical(meta: &Metadata, recipients: &[([u8; 16], u8)]) -> Vec<u8> {
    let mut sorted = recipients.to_vec();
    sorted.sort_unstable_by_key(|pair| pair.0);
    let mut out = Vec::with_capacity(160 + sorted.len() * 24);
    frame(&mut out, DOMAIN);
    frame(&mut out, &meta.version.to_le_bytes());
    frame(&mut out, meta.secret_id.as_bytes());
    frame(&mut out, meta.tenant.as_bytes());
    frame(&mut out, meta.owner.as_bytes());
    frame(&mut out, &meta.rev.to_le_bytes());
    frame(&mut out, meta.content_type.as_bytes());
    frame(&mut out, &[meta.recovery_optin as u8]);
    frame(&mut out, &(sorted.len() as u64).to_le_bytes());
    for (id, kind) in &sorted {
        frame(&mut out, id);
        frame(&mut out, &[*kind]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::Metadata;

    fn meta() -> Metadata {
        Metadata {
            version: 1,
            secret_id: "s-1".into(),
            tenant: "t-1".into(),
            owner: "api-key:abc".into(),
            rev: 3,
            content_type: "env".into(),
            recovery_optin: true,
        }
    }

    #[test]
    fn order_independent_in_recipient_set() {
        let a = canonical(&meta(), &[([1u8; 16], 0), ([2u8; 16], 1)]);
        let b = canonical(&meta(), &[([2u8; 16], 1), ([1u8; 16], 0)]);
        assert_eq!(a, b, "recipient order must not change the AAD (sorted set)");
    }

    #[test]
    fn distinct_metadata_distinct_aad() {
        let mut changed = meta();
        changed.rev = 4;
        assert_ne!(
            canonical(&meta(), &[([1u8; 16], 0)]),
            canonical(&changed, &[([1u8; 16], 0)])
        );
    }

    #[test]
    fn recipient_set_change_changes_aad() {
        let one = canonical(&meta(), &[([1u8; 16], 0)]);
        let two = canonical(&meta(), &[([1u8; 16], 0), ([2u8; 16], 0)]);
        assert_ne!(one, two, "adding a recipient must change the AAD");
    }

    #[test]
    fn relabeling_kind_changes_aad() {
        let user = canonical(&meta(), &[([1u8; 16], 0)]);
        let recovery = canonical(&meta(), &[([1u8; 16], 1)]);
        assert_ne!(user, recovery, "kind is bound: relabel must change the AAD");
    }
}
