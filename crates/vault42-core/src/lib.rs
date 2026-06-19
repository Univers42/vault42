//! vault42-core — the pure, I/O-free cryptographic heart of vault42.
//!
//! This crate produces and consumes the zero-knowledge `Envelope` wire type: the
//! client enciphers locally (XChaCha20-Poly1305 over a random DEK, the DEK wrapped
//! per recipient via X25519, an Ed25519 author signature over a frozen canonical
//! AAD), and the server only ever sees ciphertext + wrapped DEKs + metadata. It
//! depends on no network, no filesystem, and no async runtime, so the property and
//! fuzz battery exercises it in isolation. The real primitives land in P2; this is
//! the P0 skeleton that establishes the crate, its error type, and the test harness.

/// The crate's semantic version, surfaced by the `Whoami` / `--version` paths.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Errors raised by the crypto core. Variants are added per primitive in P2; the
/// `#[non_exhaustive]` marker lets callers match without breaking on new variants.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A placeholder until P2 wires the envelope / AEAD / signature primitives.
    #[error("vault42-core: not yet implemented: {0}")]
    NotImplemented(&'static str),
}

/// The crate-wide result alias (kernel rule: `Result<T, E>` everywhere).
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_non_empty() {
        assert!(!VERSION.is_empty());
    }
}
