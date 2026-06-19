//! The canonical Additional-Authenticated-Data (AAD) framing. This is the FROZEN,
//! injective serialization that the AEAD and the author signature are bound to —
//! changing it changes every signature, so it must stay byte-stable forever
//! (mirrors grobase's `audit/chain.go` length-prefixed canonical form).
//!
//! Injectivity argument: each field is emitted as `<decimal-len> ':' <bytes> '\n'`.
//! Because every field carries its own length prefix, no choice of field values
//! can produce the same byte stream as a different tuple — an attacker cannot
//! shift bytes between owner/tenant/secret_id, nor add/remove a recipient, without
//! changing the canonical bytes (and thus breaking the signature). THREAT-MODEL R8.

use crate::envelope::Metadata;

/// Domain separator so AAD bytes can never collide with any other signed context.
const DOMAIN: &[u8] = b"vault42/aad/v1";

/// Append one length-prefixed field: `<len> ':' <value> '\n'`.
fn frame(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(value.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(value);
    out.push(b'\n');
}

/// Build the canonical AAD for an envelope: the domain tag, then the metadata in a
/// FIXED order, then the recipient set (sorted, length-prefixed by count and per
/// id). The recipient set is bound so stripping or splicing a `WrappedDek`
/// invalidates the author signature.
pub fn canonical(meta: &Metadata, recipient_ids: &[[u8; 16]]) -> Vec<u8> {
    let mut sorted = recipient_ids.to_vec();
    sorted.sort_unstable();
    let mut out = Vec::with_capacity(160 + sorted.len() * 20);
    frame(&mut out, DOMAIN);
    frame(&mut out, &meta.version.to_le_bytes());
    frame(&mut out, meta.secret_id.as_bytes());
    frame(&mut out, meta.tenant.as_bytes());
    frame(&mut out, meta.owner.as_bytes());
    frame(&mut out, &meta.rev.to_le_bytes());
    frame(&mut out, meta.content_type.as_bytes());
    frame(&mut out, &[meta.recovery_optin as u8]);
    frame(&mut out, &(sorted.len() as u64).to_le_bytes());
    for id in &sorted {
        frame(&mut out, id);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::Metadata;

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
    fn deterministic_and_order_independent_in_recipient_set() {
        let a = canonical(&meta(), &[[1u8; 16], [2u8; 16]]);
        let b = canonical(&meta(), &[[2u8; 16], [1u8; 16]]);
        assert_eq!(a, b, "recipient order must not change the AAD (sorted set)");
    }

    #[test]
    fn distinct_metadata_distinct_aad() {
        let mut m2 = meta();
        m2.rev = 4;
        assert_ne!(
            canonical(&meta(), &[[1u8; 16]]),
            canonical(&m2, &[[1u8; 16]])
        );
    }

    #[test]
    fn recipient_set_change_changes_aad() {
        let one = canonical(&meta(), &[[1u8; 16]]);
        let two = canonical(&meta(), &[[1u8; 16], [2u8; 16]]);
        assert_ne!(one, two, "adding a recipient must change the AAD");
    }
}
