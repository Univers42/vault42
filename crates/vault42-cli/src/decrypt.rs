/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   decrypt.rs                                           :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Local envelope opening, shared by `get` and `share`. It pins the author key the
//! server returned by checking its fingerprint against the signature-bound id in the
//! envelope (so a malicious server cannot substitute a different author), then opens
//! the envelope with the caller's X25519 secret under the expected read scope.

use vault42_core::{open, AuthorPublicKey, Envelope, Identity, ReadScope};
use vault42_proto::vault::v1::GetResponse;
use zeroize::Zeroizing;

/// Verify authorship and decrypt `resp` for `identity`, binding the read to
/// `expected_secret_id` and `min_rev` (anti-substitution / anti-rollback).
pub fn open_envelope(
    identity: &Identity,
    resp: &GetResponse,
    expected_secret_id: &str,
    min_rev: u64,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let env = Envelope::from_bytes(&resp.envelope)?;
    let author = author_key(&resp.author_pubkey, &env)?;
    let scope = ReadScope {
        secret_id: expected_secret_id,
        min_rev,
    };
    Ok(open(&env, identity.encryption_secret(), &author, &scope)?)
}

/// Reconstruct the author public key the server returned, rejecting it unless its
/// fingerprint matches the envelope's signature-bound author id.
fn author_key(author_pubkey: &[u8], env: &Envelope) -> anyhow::Result<AuthorPublicKey> {
    if author_pubkey.len() != 32 {
        anyhow::bail!("author key must be 32 bytes");
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(author_pubkey);
    if vault42_core::fingerprint(&bytes) != env.author_pubkey_id {
        anyhow::bail!("author key does not match the envelope");
    }
    AuthorPublicKey::from_bytes(&bytes).map_err(|_| anyhow::anyhow!("invalid author key"))
}
