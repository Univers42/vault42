/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   chunk.rs                                             :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Deterministic chunk sealing, so one environment stores identical bytes once.
//!
//! Every other seal in this crate uses a fresh random nonce, which makes identical plaintext
//! produce different ciphertext every time — the property that denies the server any knowledge
//! of what it holds. This module deliberately gives that up for chunks: identical plaintext
//! under the same scope secret produces byte-identical ciphertext, so two members of one
//! environment pushing the same certificate bundle store it once instead of twice.
//!
//! WHAT THAT COSTS is a real loss, not a technicality, and it is bounded on purpose. The store
//! learns which chunks are equal and therefore how much its tenants share. It does NOT learn
//! equality across environments, because every key here descends from the environment's scope
//! secret, so the same bytes in two environments seal to two unrelated names. See
//! THREAT-MODEL R19.
//!
//! The nonce is derived rather than drawn at random, which is the one thing here that could be
//! catastrophic rather than merely leaky: a nonce repeated under one key breaks XChaCha20
//! completely. Identical plaintext repeating its nonce is the intent. Two DIFFERENT plaintexts
//! would have to collide in a 256-bit keyed BLAKE3 first.
//!
//! It is derived from the NAME, not from the plaintext directly, and that is forced rather than
//! stylistic. A reader has the name before it has any plaintext, so a nonce derived from the
//! plaintext could not be recomputed to decrypt — the first draft of this module could seal and
//! could not open. Since the name is itself a keyed digest of the plaintext, deriving the nonce
//! from the name inherits exactly the same collision bound.

use crate::aead;
use crate::error::{Error, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

/// Bound into every chunk's AAD so a chunk can never be opened as any other kind of object.
const CHUNK_AAD: &[u8] = b"vault42/chunk/v1";

/// One deterministically sealed chunk: its content-addressed name and its ciphertext.
pub struct SealedChunk {
    /// Keyed BLAKE3 of the plaintext under a naming subkey derived from the scope secret. Two
    /// members of one environment holding identical bytes compute the same name; nobody outside
    /// the scope can compute it at all, so the name is not a plaintext oracle for the store.
    pub name: [u8; 32],
    /// XChaCha20-Poly1305 ciphertext with the 16-byte Poly1305 tag appended.
    pub ciphertext: Vec<u8>,
}

/// The three independent subkeys a chunk needs, wiped on drop.
struct ChunkKeys {
    name: [u8; 32],
    nonce: [u8; 32],
    enc: [u8; 32],
}

impl Drop for ChunkKeys {
    fn drop(&mut self) {
        self.name.zeroize();
        self.nonce.zeroize();
        self.enc.zeroize();
    }
}

/// Derive the naming, nonce and encryption subkeys from the environment's scope secret.
///
/// One extract, three expands with distinct info strings, so recovering any one subkey says
/// nothing about the others. `domain` is the salt, which lets a caller partition the
/// convergence set further without needing a second secret.
fn derive(scope_secret: &[u8; 32], domain: &str) -> Result<ChunkKeys> {
    let hkdf = Hkdf::<Sha256>::new(Some(domain.as_bytes()), scope_secret);
    let mut keys = ChunkKeys {
        name: [0u8; 32],
        nonce: [0u8; 32],
        enc: [0u8; 32],
    };
    hkdf.expand(b"vault42/chunk/name/v1", &mut keys.name)
        .map_err(|_| Error::Kdf)?;
    hkdf.expand(b"vault42/chunk/nonce/v1", &mut keys.nonce)
        .map_err(|_| Error::Kdf)?;
    hkdf.expand(b"vault42/chunk/enc/v1", &mut keys.enc)
        .map_err(|_| Error::Kdf)?;
    Ok(keys)
}

/// The chunk's name: keyed BLAKE3 of the plaintext under the naming subkey.
fn name_of(keys: &ChunkKeys, plaintext: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(&keys.name, plaintext).as_bytes()
}

/// The chunk's 24-byte nonce, derived from its NAME under its own subkey.
///
/// From the name rather than the plaintext because `open_chunk` holds the name and not yet the
/// plaintext. A nonce is public in an AEAD; what it must never do is repeat under one key, and
/// the name is a 256-bit keyed digest of the plaintext, so it does not.
fn nonce_of(keys: &ChunkKeys, name: &[u8; 32]) -> [u8; 24] {
    let digest = blake3::keyed_hash(&keys.nonce, name);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&digest.as_bytes()[..24]);
    nonce
}

/// Bind the name into the AAD.
///
/// This is defence in depth, and saying so is the honest description: substituting another
/// chunk's ciphertext under this name already fails, because the nonce derives from the name and
/// so changes with it. Removing this binding was tried, and every assertion in this module still
/// passed — which is why `an_unbound_seal_never_opens` reaches past `seal_chunk` to isolate it
/// rather than leaving the claim resting on a test the nonce satisfies.
fn aad_for(name: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CHUNK_AAD.len() + name.len());
    aad.extend_from_slice(CHUNK_AAD);
    aad.extend_from_slice(name);
    aad
}

/// Seal one chunk deterministically: identical plaintext under the same scope secret gives
/// byte-identical ciphertext, so the environment stores it once.
pub fn seal_chunk(scope_secret: &[u8; 32], domain: &str, plaintext: &[u8]) -> Result<SealedChunk> {
    let keys = derive(scope_secret, domain)?;
    let name = name_of(&keys, plaintext);
    let nonce = nonce_of(&keys, &name);
    let ciphertext = aead::encrypt(&keys.enc, &nonce, plaintext, &aad_for(&name))?;
    Ok(SealedChunk { name, ciphertext })
}

/// Open a chunk, requiring the name it was fetched under to be the name of the bytes returned.
///
/// The AAD binding already refuses a ciphertext served under the wrong name, so that check
/// catches a hostile STORE. Recomputing the name catches a different attacker: a member of the
/// environment who seals plaintext under a name that is not its digest, to make everyone else's
/// deduplicated fetch of that name return bytes of their choosing.
pub fn open_chunk(
    scope_secret: &[u8; 32],
    domain: &str,
    name: &[u8; 32],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let keys = derive(scope_secret, domain)?;
    let nonce = nonce_of(&keys, name);
    let plaintext = aead::decrypt(&keys.enc, &nonce, ciphertext, &aad_for(name))?;
    if name_of(&keys, &plaintext) != *name {
        return Err(Error::ScopeMismatch);
    }
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_A: [u8; 32] = [7u8; 32];
    const SECRET_B: [u8; 32] = [9u8; 32];
    const DOMAIN: &str = "vault42/env/prod";

    /// The property the whole module exists for: same bytes, same scope, one stored object.
    #[test]
    fn identical_bytes_in_one_scope_seal_identically() {
        let first = seal_chunk(&SECRET_A, DOMAIN, b"a certificate bundle").expect("seal");
        let second = seal_chunk(&SECRET_A, DOMAIN, b"a certificate bundle").expect("seal");
        assert_eq!(first.name, second.name, "the name must converge");
        assert_eq!(
            first.ciphertext, second.ciphertext,
            "the ciphertext must converge, or nothing is deduplicated"
        );
    }

    /// The bound on the leak, and the reason our user chose per-environment scope. Equality is
    /// visible inside one environment and invisible across two.
    #[test]
    fn identical_bytes_in_two_scopes_do_not_converge() {
        let here = seal_chunk(&SECRET_A, DOMAIN, b"shared bytes").expect("seal");
        let there = seal_chunk(&SECRET_B, DOMAIN, b"shared bytes").expect("seal");
        assert_ne!(
            here.name, there.name,
            "equality must not leak across scopes"
        );
        assert_ne!(here.ciphertext, there.ciphertext);
        let other_domain =
            seal_chunk(&SECRET_A, "vault42/env/staging", b"shared bytes").expect("seal");
        assert_ne!(
            here.name, other_domain.name,
            "the domain must partition the convergence set too"
        );
    }

    /// Different plaintexts must not share a nonce. Same key, so a repeat would be fatal rather
    /// than merely revealing.
    #[test]
    fn different_plaintexts_never_share_a_nonce() {
        let keys = derive(&SECRET_A, DOMAIN).expect("derive");
        let mut seen = std::collections::HashSet::new();
        for i in 0..512u32 {
            let plaintext = i.to_le_bytes();
            let nonce = nonce_of(&keys, &name_of(&keys, &plaintext));
            assert!(seen.insert(nonce), "nonce repeated for input {i}");
        }
        let repeat = nonce_of(&keys, &name_of(&keys, &0u32.to_le_bytes()));
        assert!(
            seen.contains(&repeat),
            "positive control: the SAME plaintext must reproduce its nonce, \
             or this test is measuring randomness rather than determinism"
        );
    }

    /// A round trip returns exactly the bytes that went in.
    #[test]
    fn a_sealed_chunk_opens_to_its_plaintext() {
        let plaintext = b"-----BEGIN PRIVATE KEY-----".to_vec();
        let sealed = seal_chunk(&SECRET_A, DOMAIN, &plaintext).expect("seal");
        let opened = open_chunk(&SECRET_A, DOMAIN, &sealed.name, &sealed.ciphertext).expect("open");
        assert_eq!(opened.as_slice(), plaintext.as_slice());
    }

    /// A store that serves one chunk's ciphertext under another chunk's name is refused.
    #[test]
    fn a_substituted_ciphertext_never_opens() {
        let mine = seal_chunk(&SECRET_A, DOMAIN, b"my bytes").expect("seal");
        let theirs = seal_chunk(&SECRET_A, DOMAIN, b"their bytes").expect("seal");
        assert!(
            open_chunk(&SECRET_A, DOMAIN, &mine.name, &theirs.ciphertext).is_err(),
            "a swapped ciphertext must fail; the nonce changes with the name, so it does"
        );
        assert!(
            open_chunk(&SECRET_A, DOMAIN, &mine.name, &mine.ciphertext).is_ok(),
            "positive control: the matching pair must open, or the check above proves nothing"
        );
    }

    /// A member of the environment who seals bytes under a name that is not their digest is
    /// refused. The AAD cannot catch this one: the writer bound the same lie into it.
    #[test]
    fn a_chunk_stored_under_a_lying_name_is_refused() {
        let keys = derive(&SECRET_A, DOMAIN).expect("derive");
        let lie = name_of(&keys, b"what the victim will ask for");
        let nonce = nonce_of(&keys, &lie);
        let poisoned = aead::encrypt(&keys.enc, &nonce, b"attacker's bytes", &aad_for(&lie))
            .expect("the attacker can seal");
        assert!(
            open_chunk(&SECRET_A, DOMAIN, &lie, &poisoned).is_err(),
            "a name that is not the digest of the bytes must be refused"
        );
        let honest = seal_chunk(&SECRET_A, DOMAIN, b"what the victim will ask for").expect("seal");
        assert!(
            open_chunk(&SECRET_A, DOMAIN, &honest.name, &honest.ciphertext).is_ok(),
            "positive control: an honestly named chunk must still open"
        );
    }

    /// The AAD binding is checked, isolated from the nonce that would otherwise satisfy this.
    ///
    /// Sealing with the correct nonce but WITHOUT the name in the AAD is exactly what a build
    /// missing the binding produces. Every other test here passed with the binding removed, so
    /// this is the only one that holds it in place.
    #[test]
    fn an_unbound_seal_never_opens() {
        let keys = derive(&SECRET_A, DOMAIN).expect("derive");
        let plaintext = b"bytes sealed by a build without the binding";
        let name = name_of(&keys, plaintext);
        let nonce = nonce_of(&keys, &name);
        let unbound = aead::encrypt(&keys.enc, &nonce, plaintext, CHUNK_AAD).expect("seal");
        assert!(
            open_chunk(&SECRET_A, DOMAIN, &name, &unbound).is_err(),
            "a chunk whose AAD omits its name must be refused"
        );
        let bound = aead::encrypt(&keys.enc, &nonce, plaintext, &aad_for(&name)).expect("seal");
        assert!(
            open_chunk(&SECRET_A, DOMAIN, &name, &bound).is_ok(),
            "positive control: the same bytes WITH the binding must open,              or this test would pass against a broken decrypt"
        );
    }

    /// Tampering with a single ciphertext byte fails the open rather than returning bytes.
    #[test]
    fn a_tampered_chunk_never_opens() {
        let sealed = seal_chunk(&SECRET_A, DOMAIN, b"integrity matters").expect("seal");
        let mut tampered = sealed.ciphertext.clone();
        tampered[0] ^= 1;
        assert!(open_chunk(&SECRET_A, DOMAIN, &sealed.name, &tampered).is_err());
    }

    /// An empty chunk is still a chunk: it seals, names and opens rather than panicking.
    #[test]
    fn an_empty_chunk_round_trips() {
        let sealed = seal_chunk(&SECRET_A, DOMAIN, b"").expect("seal");
        let opened = open_chunk(&SECRET_A, DOMAIN, &sealed.name, &sealed.ciphertext).expect("open");
        assert!(opened.is_empty());
    }
}
