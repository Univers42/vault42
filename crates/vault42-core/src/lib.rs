//! vault42-core — the pure, I/O-free cryptographic heart of vault42.
//!
//! The client enciphers locally (XChaCha20-Poly1305 over a random DEK, the DEK
//! wrapped per recipient via X25519, an Ed25519 author signature over a frozen
//! canonical AAD), and the server only ever sees ciphertext + wrapped DEKs +
//! metadata via the opaque [`Envelope`]. This crate has no network, no filesystem,
//! and no async runtime, so the property and fuzz battery exercises it in
//! isolation. Plaintext and key material are radioactive: every key/plaintext
//! buffer is `Zeroizing`, and no value is ever logged or placed in an error string.

mod aad;
mod aead;
mod envelope;
mod error;
mod keystore;
mod recipient;
mod sign;

pub use envelope::{open, seal, Envelope, Metadata, ReadScope};
pub use error::{Error, Result};
pub use keystore::{open_keystore, seal_keystore, Identity, KdfParams, KeystoreBlob};
pub use recipient::{RecipientKind, WrappedDek};

// The cryptographic key types, re-exported under domain names so the server/CLI
// construct recipients and authors without depending on the dalek crates directly.
pub use ed25519_dalek::{SigningKey as AuthorSecretKey, VerifyingKey as AuthorPublicKey};
pub use x25519_dalek::{PublicKey as RecipientPublicKey, StaticSecret as RecipientSecretKey};

/// The crate's semantic version, surfaced by the `Whoami` / `--version` paths.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Fill `buf` with cryptographically secure random bytes from the OS CSPRNG. The
/// single randomness seam for the crate (DEKs, nonces, salts), so every key/nonce
/// comes from one audited source (THREAT-MODEL R10).
pub(crate) fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|_| Error::Rng)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_non_empty() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn fill_random_is_not_all_zero() {
        let mut buf = [0u8; 32];
        fill_random(&mut buf).expect("rng");
        assert!(buf.iter().any(|&b| b != 0));
    }
}
