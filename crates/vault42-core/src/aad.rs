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
/// Bumped v1→v2 when the path-aware metadata fields joined the framing: a v1
/// envelope can never be mistaken for a v2 one (the domain tag itself differs).
const DOMAIN: &[u8] = b"vault42/aad/v2";

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
    // sec: path-aware fields are length-prefixed and bound into the author signature
    frame(&mut out, meta.project_id.as_bytes());
    frame(&mut out, meta.relative_path.as_bytes());
    frame(&mut out, &[meta.kind as u8]);
    frame(&mut out, &meta.mode.to_le_bytes());
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
            version: 2,
            secret_id: "s-1".into(),
            tenant: "t-1".into(),
            owner: "api-key:abc".into(),
            rev: 3,
            content_type: "env".into(),
            recovery_optin: true,
            project_id: "p-1".into(),
            relative_path: String::new(),
            kind: crate::metadata::Kind::Generic,
            mode: crate::metadata::DEFAULT_MODE,
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

    fn full_v2_meta() -> Metadata {
        Metadata {
            version: 2,
            secret_id: "sec-golden".into(),
            tenant: "tenant-golden".into(),
            owner: "user:11111111-1111-5111-8111-111111111111".into(),
            rev: 7,
            content_type: "env".into(),
            recovery_optin: true,
            project_id: "p-golden".into(),
            relative_path: "config/db.env".into(),
            kind: crate::metadata::Kind::EnvFile,
            mode: 0o600,
        }
    }

    /// Golden vector: pins the FROZEN v2 canonical-AAD bytes. If this digest ever
    /// changes, the wire format changed and every prior signature is invalidated —
    /// the failure is the intended alarm, not a value to blindly update.
    #[test]
    fn format_v2_aad_is_stable() {
        let bytes = canonical(&full_v2_meta(), &[([7u8; 16], 1), ([3u8; 16], 0)]);
        let digest = blake3::hash(&bytes).to_hex().to_string();
        assert_eq!(
            digest,
            "efe69d84f5bd4baff7c60252de86bdd868632fc9aa7a4d7c4acef7314bf0cbba",
            "v2 canonical AAD changed — frozen format break"
        );
    }

    #[test]
    fn path_fields_each_change_aad() {
        let base = canonical(&meta(), &[([1u8; 16], 0)]);
        let mut project = meta();
        project.project_id = "p-2".into();
        let mut path = meta();
        path.relative_path = "config/db.env".into();
        let mut kind = meta();
        kind.kind = crate::metadata::Kind::Manifest;
        let mut mode = meta();
        mode.mode = 0o644;
        for changed in [&project, &path, &kind, &mode] {
            assert_ne!(
                base,
                canonical(changed, &[([1u8; 16], 0)]),
                "every path-aware field must be bound into the AAD"
            );
        }
    }
}
