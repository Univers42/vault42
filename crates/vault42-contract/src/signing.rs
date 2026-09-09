/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   signing.rs                                           :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Contract signing-key persistence. The key is the root of trust the whole duo hangs
//! on — vault42 verifies every contract against its public half — so it must be stable
//! across restarts. It is loaded from a hex seed (env or file) or generated once and
//! written `0600` to the encrypted volume.

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use std::time::{SystemTime, UNIX_EPOCH};

/// Reconstruct a signing key from a 32-byte hex seed.
pub fn from_hex_seed(hex_seed: &str) -> anyhow::Result<SigningKey> {
    let bytes = hex::decode(hex_seed.trim())?;
    let seed: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("contract seed must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Load the signing key from `path`, generating one only when there is no prior state.
///
/// This key is the root of trust every contract is signed with, so a missing file has two very
/// different meanings and the wrong guess is silent. On a genuine first run, generating one is
/// exactly right. When a volume fails to mount, generating one boots normally, logs nothing
/// unusual, and rejects every contract ever issued — locking every user out of data that is
/// completely intact. That is the worse failure, and it used to be the one this function chose.
///
/// `state_path` is what tells them apart: a database beside the key means contracts were issued
/// by a key we no longer have, so the only safe action is to refuse. `None` means the caller has
/// no prior state to check and accepts a fresh key.
pub fn load_or_create(path: &str, state_path: Option<&str>) -> anyhow::Result<SigningKey> {
    if let Ok(hex_seed) = std::fs::read_to_string(path) {
        return from_hex_seed(&hex_seed);
    }
    if let Some(state) = state_path.filter(|state| std::path::Path::new(state).exists()) {
        anyhow::bail!(
            "signing key {path} is missing but {state} exists: refusing to mint a new root of \
             trust, which would invalidate every contract already issued. Restore the key, or \
             set the seed in the environment. If this really is a fresh start, remove {state}."
        );
    }
    let signing = SigningKey::generate(&mut OsRng);
    persist(path, &signing.to_bytes())?;
    Ok(signing)
}

/// Write the seed hex to `path`, owner-only on Unix.
fn persist(path: &str, seed: &[u8; 32]) -> anyhow::Result<()> {
    std::fs::write(path, hex::encode(seed))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Current Unix time in seconds — the contract issue/expiry clock.
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key already on disk is loaded rather than replaced.
    #[test]
    fn an_existing_key_is_loaded() {
        let dir = std::env::temp_dir().join(format!("v42-key-load-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let key = dir.join("contract.key");
        let first = load_or_create(key.to_str().expect("path"), None).expect("create");
        let again = load_or_create(key.to_str().expect("path"), None).expect("load");
        assert_eq!(
            first.to_bytes(),
            again.to_bytes(),
            "a second open must reuse the persisted key"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With no key and no prior state, generating one is correct: this is a first run.
    #[test]
    fn a_first_run_generates_a_key() {
        let dir = std::env::temp_dir().join(format!("v42-key-first-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let key = dir.join("contract.key");
        let state = dir.join("contract.db");
        load_or_create(
            key.to_str().expect("path"),
            Some(state.to_str().expect("path")),
        )
        .expect("a fresh start may mint a key");
        assert!(key.exists(), "and it is persisted");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With no key but a database beside it, minting a new root of trust is refused.
    ///
    /// This is the lost-volume case. Generating a key here boots cleanly and rejects every
    /// contract ever issued, locking every user out of data that is completely intact — a worse
    /// outcome than refusing to start, and one nothing in the logs would explain.
    #[test]
    fn a_missing_key_beside_existing_state_refuses() {
        let dir = std::env::temp_dir().join(format!("v42-key-lost-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let key = dir.join("contract.key");
        let state = dir.join("contract.db");
        std::fs::write(&state, b"pretend this holds issued contracts").expect("state");
        let refused = load_or_create(
            key.to_str().expect("path"),
            Some(state.to_str().expect("path")),
        )
        .expect_err("a lost key must not be replaced silently");
        let message = format!("{refused}");
        assert!(
            message.contains("refusing to mint a new root of trust"),
            "the refusal must say why: {message}"
        );
        assert!(!key.exists(), "and it must not have written one anyway");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
