/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   open.rs                                              :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Opening: verify the requested scope, recovery-consistency, the recipient set, and
//! the author signature BEFORE decrypting, then unwrap this recipient's DEK and
//! decrypt. A server cannot alter any of these without detection — but it can still
//! hand over a *different, validly signed* envelope authored by a key it chose, which
//! is why `open` is given the author key the caller is willing to trust (THREAT-MODEL
//! R9): the signature proves authorship against that key, not that the key is right.

use crate::aad;
use crate::aead;
use crate::envelope::{recipient_pairs, reject_duplicates, Envelope};
use crate::error::{Error, Result};
use crate::metadata::{Metadata, ReadScope};
use crate::recipient::{self, RecipientKind};
use crate::sign;
use ed25519_dalek::VerifyingKey;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Reject an envelope that does not match the requested secret / minimum rev — this
/// is what binds the response to the request (anti-substitution, and anti-rollback when
/// the caller names a revision; a `min_rev` of 0 has no floor to compare against).
fn check_scope(meta: &Metadata, scope: &ReadScope) -> Result<()> {
    if meta.secret_id != scope.secret_id || meta.rev < scope.min_rev {
        return Err(Error::ScopeMismatch);
    }
    Ok(())
}

/// Reject a recovery-kind wrap when the metadata says recovery is off — catches a
/// client that attached operator recovery while claiming it didn't ("not retroactive").
fn reject_unexpected_recovery(env: &Envelope) -> Result<()> {
    let has_recovery = env
        .wrapped
        .iter()
        .any(|w| w.kind == RecipientKind::Recovery);
    if !env.metadata.recovery_optin && has_recovery {
        return Err(Error::RecoveryNotAllowed);
    }
    Ok(())
}

/// Pin the author key, then strict-verify the signature over the canonical AAD plus
/// ciphertext. Always runs before any decryption.
fn verify_author(env: &Envelope, author: &VerifyingKey, canonical: &[u8]) -> Result<()> {
    if env.author_sig.len() != 64 {
        return Err(Error::Format("signature length"));
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&env.author_sig);
    if recipient::key_id(author.as_bytes()) != env.author_pubkey_id {
        return Err(Error::AuthorMismatch);
    }
    sign::verify(author, canonical, &env.ciphertext, &signature)
}

/// Find this recipient's wrap by id and unwrap the DEK with the recipient secret.
fn unwrap_for(env: &Envelope, recipient_secret: &StaticSecret) -> Result<Zeroizing<[u8; 32]>> {
    let my_id = recipient::key_id(PublicKey::from(recipient_secret).as_bytes());
    let mine = env
        .wrapped
        .iter()
        .find(|w| w.recipient_id == my_id)
        .ok_or(Error::NotARecipient)?;
    recipient::unwrap(mine, recipient_secret)
}

/// Open `env` for `recipient_secret`, authored by the pinned `author`, for `scope`.
/// Returns the plaintext in a zeroizing buffer; any check failure returns `Err`.
pub fn open(
    env: &Envelope,
    recipient_secret: &StaticSecret,
    author: &VerifyingKey,
    scope: &ReadScope,
) -> Result<Zeroizing<Vec<u8>>> {
    check_scope(&env.metadata, scope)?;
    reject_unexpected_recovery(env)?;
    let pairs = recipient_pairs(&env.wrapped);
    reject_duplicates(&pairs)?;
    let canonical = aad::canonical(&env.metadata, &pairs);
    verify_author(env, author, &canonical)?;
    let dek = unwrap_for(env, recipient_secret)?;
    aead::decrypt(&dek, &env.nonce, &env.ciphertext, &canonical)
}

/// Open `env` for `recipient_secret`, requiring the server's version label to agree with
/// the revision the envelope is signed at.
///
/// `open` cannot see the transport, so a server is free to label a rev-2 envelope as rev 5,
/// or to serve an old envelope while calling it current. Every fetched response should go
/// through this function instead: the label and the signed bytes must agree. That is the
/// half of anti-rollback a client can check with no local state. The other half is
/// [`ReadScope::min_rev`]: a caller that knows the revision it expects passes it, and an
/// older envelope is refused there.
///
/// A bare "latest" read has no revision to expect, so it has no floor to compare against;
/// the label equality is still checked, which is all a stateless client can honestly claim.
pub fn open_at_version(
    env: &Envelope,
    recipient_secret: &StaticSecret,
    author: &VerifyingKey,
    scope: &ReadScope,
    server_version: u64,
) -> Result<Zeroizing<Vec<u8>>> {
    if env.metadata.rev != server_version {
        return Err(Error::ScopeMismatch);
    }
    open(env, recipient_secret, author, scope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::metadata::{Kind, DEFAULT_MODE};
    use crate::seal::{seal, Recipients};

    /// Seal `payload` at `rev`, authored and received by one identity.
    fn sealed(rev: u64) -> (Envelope, Identity) {
        let id = Identity::generate();
        let users = [id.encryption_public()];
        let meta = Metadata {
            version: 2,
            secret_id: "s-1".into(),
            tenant: "t".into(),
            owner: "o".into(),
            rev,
            content_type: "opaque".into(),
            recovery_optin: false,
            project_id: String::new(),
            relative_path: String::new(),
            kind: Kind::Generic,
            mode: DEFAULT_MODE,
        };
        let env = seal(
            b"payload",
            meta,
            &Recipients {
                users: &users,
                recovery: None,
            },
            id.signing_key(),
        )
        .expect("seal");
        (env, id)
    }

    /// The label the server attached must equal the revision inside the signed envelope.
    ///
    /// This is what a server cannot fake: it may change its label, or serve an old
    /// envelope, but not make the two agree. `2` is the positive control — without it the
    /// refusals below would hold for a checker that refused everything.
    #[test]
    fn the_server_version_must_match_the_signed_revision() {
        let (env, id) = sealed(2);
        let scope = ReadScope {
            secret_id: "s-1",
            min_rev: 0,
        };
        assert!(
            open_at_version(&env, id.encryption_secret(), &id.author_public(), &scope, 2).is_ok(),
            "the honest label must be accepted"
        );
        for wrong in [1u64, 3, 0] {
            assert!(
                matches!(
                    open_at_version(
                        &env,
                        id.encryption_secret(),
                        &id.author_public(),
                        &scope,
                        wrong
                    ),
                    Err(Error::ScopeMismatch)
                ),
                "a label of {wrong} must be refused for a rev-2 envelope"
            );
        }
    }
}
