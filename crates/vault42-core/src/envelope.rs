//! The zero-knowledge envelope: the single wire type the server stores opaquely.
//! WRITE enciphers locally under a fresh DEK, wraps the DEK per recipient (plus the
//! recovery recipient when opted in), and signs the canonical AAD. READ verifies
//! the author signature and the requested scope BEFORE decrypting. The server never
//! sees the DEK or plaintext — THREAT-MODEL: the one guarantee.

use crate::aad;
use crate::aead;
use crate::error::{Error, Result};
use crate::recipient::{self, RecipientKind, WrappedDek};
use crate::sign;
use bincode::Options;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Upper bound on a serialized envelope, enforced by the codec so a malicious
/// server cannot drive an unbounded allocation through `from_bytes` (THREAT-MODEL
/// R-DoS). 64 MiB comfortably holds a large secret/archive payload.
const MAX_ENVELOPE_BYTES: u64 = 64 * 1024 * 1024;

/// Authenticated, non-secret metadata. Bound into the AAD, so the server cannot
/// alter any field without invalidating the author signature.
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

/// A stored secret. `ciphertext`/`nonce` are the AEAD payload; `wrapped` carries one
/// DEK wrap per recipient (sorted by id); `author_sig` (64 bytes) binds metadata +
/// recipient set + ciphertext.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 24],
    pub wrapped: Vec<WrappedDek>,
    pub metadata: Metadata,
    pub author_sig: Vec<u8>,
    pub author_pubkey_id: [u8; 16],
}

/// The caller's expectation for an `open`: which secret was requested and the
/// minimum acceptable revision. `open` rejects an envelope whose metadata
/// disagrees, so a malicious server cannot substitute a different validly-signed
/// envelope or replay a stale revision (THREAT-MODEL R3).
pub struct ReadScope<'a> {
    pub secret_id: &'a str,
    pub min_rev: u64,
}

/// The bincode configuration used for both directions: fixed-int encoding (stable
/// across bincode versions), a hard size limit (DoS bound), and reject-trailing.
fn codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_ENVELOPE_BYTES)
}

impl Envelope {
    /// Serialize to opaque bytes for the grobase `vault42_secrets.envelope` column.
    /// The server treats the result as opaque — it cannot decrypt it. `wrapped` is
    /// kept sorted by id at seal time so the encoding is canonical per envelope.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        codec().serialize(self).map_err(|_| Error::Codec)
    }

    /// Deserialize from stored bytes; malformed/oversized input returns `Codec`,
    /// never panics or allocates unboundedly.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        codec().deserialize(bytes).map_err(|_| Error::Codec)
    }
}

/// Collect recipient public keys (users first, then the optional recovery
/// recipient) so seal wraps and binds exactly this set.
fn recipient_list<'a>(
    users: &'a [PublicKey],
    recovery: Option<&'a PublicKey>,
) -> Vec<(&'a PublicKey, RecipientKind)> {
    let mut all: Vec<(&PublicKey, RecipientKind)> =
        users.iter().map(|p| (p, RecipientKind::User)).collect();
    if let Some(recovery_key) = recovery {
        all.push((recovery_key, RecipientKind::Recovery));
    }
    all
}

/// The `(id, kind_code)` pairs the AAD binds, taken from an envelope's wraps.
fn recipient_pairs(wrapped: &[WrappedDek]) -> Vec<([u8; 16], u8)> {
    wrapped
        .iter()
        .map(|w| (w.recipient_id, w.kind.code()))
        .collect()
}

/// Reject a recipient set that is not actually a set (duplicate ids), so the
/// injectivity contract the AAD relies on is enforced in code, not by luck.
fn reject_duplicates(pairs: &[([u8; 16], u8)]) -> Result<()> {
    let mut ids: Vec<[u8; 16]> = pairs.iter().map(|(id, _)| *id).collect();
    ids.sort_unstable();
    if ids.windows(2).any(|w| w[0] == w[1]) {
        return Err(Error::DuplicateRecipient);
    }
    Ok(())
}

/// Seal `plaintext` for `users` (and `recovery` when opted in), authored by
/// `author`. A fresh random DEK + nonce are used; the DEK is zeroized after
/// wrapping; `wrapped` is sorted by id for a canonical encoding.
pub fn seal(
    plaintext: &[u8],
    metadata: Metadata,
    users: &[PublicKey],
    author: &SigningKey,
    recovery: Option<&PublicKey>,
) -> Result<Envelope> {
    let all = recipient_list(users, recovery);
    let pairs: Vec<([u8; 16], u8)> = all
        .iter()
        .map(|(pubkey, kind)| (recipient::key_id(pubkey.as_bytes()), kind.code()))
        .collect();
    reject_duplicates(&pairs)?;
    let canonical = aad::canonical(&metadata, &pairs);
    let mut dek = Zeroizing::new([0u8; 32]); // sec: DEK zeroized on drop
    crate::fill_random(dek.as_mut())?;
    let mut nonce = [0u8; 24];
    crate::fill_random(&mut nonce)?;
    let ciphertext = aead::encrypt(&dek, &nonce, plaintext, &canonical)?;
    let mut wrapped = Vec::with_capacity(all.len());
    for (pubkey, kind) in &all {
        wrapped.push(recipient::wrap(&dek, pubkey, *kind)?);
    }
    wrapped.sort_by_key(|w| w.recipient_id);
    let author_sig = sign::sign(author, &canonical, &ciphertext).to_vec();
    let author_pubkey_id = recipient::key_id(author.verifying_key().as_bytes());
    Ok(Envelope {
        ciphertext,
        nonce,
        wrapped,
        metadata,
        author_sig,
        author_pubkey_id,
    })
}

/// Reject an envelope that does not match the requested secret / minimum rev.
fn check_scope(meta: &Metadata, expected: &ReadScope) -> Result<()> {
    if meta.secret_id != expected.secret_id || meta.rev < expected.min_rev {
        return Err(Error::ScopeMismatch); // sec: bind response to the requested secret + min rev
    }
    Ok(())
}

/// Reject a recovery-kind wrap when the metadata says recovery is off — catches a
/// client that tried to attach operator recovery while claiming it didn't.
fn reject_unexpected_recovery(env: &Envelope) -> Result<()> {
    let has_recovery = env
        .wrapped
        .iter()
        .any(|w| w.kind == RecipientKind::Recovery);
    if !env.metadata.recovery_optin && has_recovery {
        return Err(Error::RecoveryNotAllowed); // sec: "not retroactive" enforced on read
    }
    Ok(())
}

/// Verify the author signature: length-check, pin the author key, then strict
/// verify over the canonical AAD + ciphertext. Runs BEFORE any decryption.
fn verify_author(env: &Envelope, author: &VerifyingKey, canonical: &[u8]) -> Result<()> {
    if env.author_sig.len() != 64 {
        return Err(Error::Format("signature length"));
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&env.author_sig);
    if recipient::key_id(author.as_bytes()) != env.author_pubkey_id {
        return Err(Error::AuthorMismatch); // sec: pin the author key before trusting the signature
    }
    sign::verify(author, canonical, &env.ciphertext, &signature)
}

/// Find this recipient's wrap and unwrap the DEK with the recipient secret.
fn unwrap_for(env: &Envelope, recipient_secret: &StaticSecret) -> Result<Zeroizing<[u8; 32]>> {
    let my_id = recipient::key_id(PublicKey::from(recipient_secret).as_bytes());
    let mine = env
        .wrapped
        .iter()
        .find(|w| w.recipient_id == my_id)
        .ok_or(Error::NotARecipient)?;
    recipient::unwrap(mine, recipient_secret)
}

/// Open an envelope addressed to `recipient_secret`, authored by the pinned
/// `author`, for the requested `scope`. Scope, recovery-consistency, duplicate, and
/// signature checks all run BEFORE decryption. Returns plaintext in a zeroizing buf.
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
    let canonical = aad::canonical(&env.metadata, &pairs); // sec: rebuilt set is signature-bound
    verify_author(env, author, &canonical)?; // sec: verify before decrypt
    let dek = unwrap_for(env, recipient_secret)?;
    aead::decrypt(&dek, &env.nonce, &env.ciphertext, &canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::Identity;

    fn metadata(rev: u64, recovery_optin: bool) -> Metadata {
        Metadata {
            version: 1,
            secret_id: "secret-1".into(),
            tenant: "tenant-1".into(),
            owner: "api-key:abc".into(),
            rev,
            content_type: "env".into(),
            recovery_optin,
        }
    }

    fn scope() -> ReadScope<'static> {
        ReadScope {
            secret_id: "secret-1",
            min_rev: 0,
        }
    }

    fn seal_for(
        users: &[PublicKey],
        author: &SigningKey,
        recovery: Option<&PublicKey>,
        optin: bool,
    ) -> Envelope {
        seal(b"pw=hunter2", metadata(1, optin), users, author, recovery).expect("seal")
    }

    #[test]
    fn seal_open_roundtrip() {
        let alice = Identity::generate();
        let author = Identity::generate();
        let env = seal_for(
            &[alice.encryption_public()],
            author.signing_key(),
            None,
            false,
        );
        let pt = open(
            &env,
            alice.encryption_secret(),
            &author.author_public(),
            &scope(),
        )
        .expect("open");
        assert_eq!(&pt[..], b"pw=hunter2");
    }

    #[test]
    fn non_recipient_cannot_open() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let author = Identity::generate();
        let env = seal_for(
            &[alice.encryption_public()],
            author.signing_key(),
            None,
            false,
        );
        assert!(matches!(
            open(
                &env,
                bob.encryption_secret(),
                &author.author_public(),
                &scope()
            ),
            Err(Error::NotARecipient)
        ));
    }

    #[test]
    fn recovery_recipient_can_open_when_opted_in() {
        let alice = Identity::generate();
        let recovery = Identity::generate();
        let author = Identity::generate();
        let env = seal_for(
            &[alice.encryption_public()],
            author.signing_key(),
            Some(&recovery.encryption_public()),
            true,
        );
        let pt = open(
            &env,
            recovery.encryption_secret(),
            &author.author_public(),
            &scope(),
        )
        .expect("recover");
        assert_eq!(&pt[..], b"pw=hunter2");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let alice = Identity::generate();
        let author = Identity::generate();
        let mut env = seal_for(
            &[alice.encryption_public()],
            author.signing_key(),
            None,
            false,
        );
        env.ciphertext[0] ^= 0x01;
        assert!(open(
            &env,
            alice.encryption_secret(),
            &author.author_public(),
            &scope()
        )
        .is_err());
    }

    #[test]
    fn stripping_recovery_recipient_breaks_signature() {
        let alice = Identity::generate();
        let recovery = Identity::generate();
        let author = Identity::generate();
        let mut env = seal_for(
            &[alice.encryption_public()],
            author.signing_key(),
            Some(&recovery.encryption_public()),
            true,
        );
        env.wrapped.retain(|w| w.kind == RecipientKind::User);
        assert!(matches!(
            open(
                &env,
                alice.encryption_secret(),
                &author.author_public(),
                &scope()
            ),
            Err(Error::Signature)
        ));
    }

    #[test]
    fn relabeling_recovery_as_user_breaks_signature() {
        let alice = Identity::generate();
        let recovery = Identity::generate();
        let author = Identity::generate();
        let mut env = seal_for(
            &[alice.encryption_public()],
            author.signing_key(),
            Some(&recovery.encryption_public()),
            true,
        );
        for w in env.wrapped.iter_mut() {
            w.kind = RecipientKind::User;
        }
        assert!(matches!(
            open(
                &env,
                alice.encryption_secret(),
                &author.author_public(),
                &scope()
            ),
            Err(Error::Signature)
        ));
    }

    #[test]
    fn recovery_wrap_with_optin_false_is_rejected() {
        let alice = Identity::generate();
        let recovery = Identity::generate();
        let author = Identity::generate();
        let env = seal_for(
            &[alice.encryption_public()],
            author.signing_key(),
            Some(&recovery.encryption_public()),
            false,
        );
        assert!(matches!(
            open(
                &env,
                alice.encryption_secret(),
                &author.author_public(),
                &scope()
            ),
            Err(Error::RecoveryNotAllowed)
        ));
    }

    #[test]
    fn wrong_secret_id_is_scope_mismatch() {
        let alice = Identity::generate();
        let author = Identity::generate();
        let env = seal_for(
            &[alice.encryption_public()],
            author.signing_key(),
            None,
            false,
        );
        let other = ReadScope {
            secret_id: "secret-2",
            min_rev: 0,
        };
        assert!(matches!(
            open(
                &env,
                alice.encryption_secret(),
                &author.author_public(),
                &other
            ),
            Err(Error::ScopeMismatch)
        ));
    }

    #[test]
    fn stale_revision_is_scope_mismatch() {
        let alice = Identity::generate();
        let author = Identity::generate();
        let env = seal_for(
            &[alice.encryption_public()],
            author.signing_key(),
            None,
            false,
        );
        let newer = ReadScope {
            secret_id: "secret-1",
            min_rev: 2,
        };
        assert!(matches!(
            open(
                &env,
                alice.encryption_secret(),
                &author.author_public(),
                &newer
            ),
            Err(Error::ScopeMismatch)
        ));
    }

    #[test]
    fn duplicate_recipient_is_rejected() {
        let alice = Identity::generate();
        let author = Identity::generate();
        let mut env = seal_for(
            &[alice.encryption_public()],
            author.signing_key(),
            None,
            false,
        );
        let dup = env.wrapped[0].clone();
        env.wrapped.push(dup);
        assert!(matches!(
            open(
                &env,
                alice.encryption_secret(),
                &author.author_public(),
                &scope()
            ),
            Err(Error::DuplicateRecipient)
        ));
    }

    #[test]
    fn wrong_author_rejected() {
        let alice = Identity::generate();
        let author = Identity::generate();
        let attacker = Identity::generate();
        let env = seal_for(
            &[alice.encryption_public()],
            author.signing_key(),
            None,
            false,
        );
        assert!(matches!(
            open(
                &env,
                alice.encryption_secret(),
                &attacker.author_public(),
                &scope()
            ),
            Err(Error::AuthorMismatch)
        ));
    }

    #[test]
    fn serialization_roundtrip_preserves_decryptability() {
        let alice = Identity::generate();
        let author = Identity::generate();
        let env = seal_for(
            &[alice.encryption_public()],
            author.signing_key(),
            None,
            false,
        );
        let bytes = env.to_bytes().expect("to_bytes");
        let restored = Envelope::from_bytes(&bytes).expect("from_bytes");
        let pt = open(
            &restored,
            alice.encryption_secret(),
            &author.author_public(),
            &scope(),
        )
        .expect("open");
        assert_eq!(&pt[..], b"pw=hunter2");
    }

    #[test]
    fn from_bytes_rejects_trailing_garbage() {
        let alice = Identity::generate();
        let author = Identity::generate();
        let env = seal_for(
            &[alice.encryption_public()],
            author.signing_key(),
            None,
            false,
        );
        let mut bytes = env.to_bytes().expect("to_bytes");
        bytes.push(0xFF);
        assert!(matches!(Envelope::from_bytes(&bytes), Err(Error::Codec)));
    }
}
