//! Errors raised by the crypto core. Every fallible primitive returns one of
//! these — never a panic, never plaintext or key bytes in the message (kernel
//! rule: plaintext/keys are radioactive; error strings are safe to log).

/// The crypto-core error type. `#[non_exhaustive]` lets new variants be added in
/// later phases without breaking downstream `match`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// AEAD open/seal failed — wrong key, tampered ciphertext/nonce/AAD, or a bad tag.
    #[error("vault42-core: AEAD authentication failed")]
    Aead,
    /// A key-derivation step (Argon2id or HKDF) failed.
    #[error("vault42-core: key derivation failed")]
    Kdf,
    /// The author's Ed25519 signature did not verify over the canonical AAD.
    #[error("vault42-core: author signature verification failed")]
    Signature,
    /// The envelope's author fingerprint does not match the pinned author key.
    #[error("vault42-core: author public key does not match the pinned key")]
    AuthorMismatch,
    /// The caller holds no wrapped DEK for this envelope (not a recipient).
    #[error("vault42-core: caller is not a recipient of this envelope")]
    NotARecipient,
    /// Keystore open failed — wrong passphrase or a corrupt blob.
    #[error("vault42-core: wrong passphrase or corrupt keystore")]
    Passphrase,
    /// A decoded value had an unexpected shape/length.
    #[error("vault42-core: malformed value: {0}")]
    Format(&'static str),
    /// The OS CSPRNG failed to produce randomness.
    #[error("vault42-core: RNG failure")]
    Rng,
    /// (De)serialization of an envelope or keystore blob failed.
    #[error("vault42-core: codec error")]
    Codec,
}

/// The crate-wide result alias (kernel rule: `Result<T, E>` everywhere).
pub type Result<T> = core::result::Result<T, Error>;
