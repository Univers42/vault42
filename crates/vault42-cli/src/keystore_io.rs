/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   keystore_io.rs                                       :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Keystore file I/O. The passphrase-wrapped identity blob lives at
//! `$VAULT42_KEYSTORE` or `~/.config/vault42/keystore.v42`, stored as JSON of the
//! already-encrypted `KeystoreBlob` (only ciphertext + public KDF params — safe at
//! rest) and written `0600`. Loading never decrypts; unlocking lives in `passphrase`.

use std::path::{Path, PathBuf};
use vault42_core::KeystoreBlob;

/// The keystore path: `$VAULT42_KEYSTORE` or the per-user config default.
pub fn keystore_path() -> anyhow::Result<PathBuf> {
    if let Ok(custom) = std::env::var("VAULT42_KEYSTORE") {
        return Ok(PathBuf::from(custom));
    }
    let base = dirs::config_dir().ok_or_else(|| anyhow::anyhow!("no config directory"))?;
    Ok(base.join("vault42").join("keystore.v42"))
}

/// Write the wrapped keystore blob to `path`, creating parents, `0600`.
pub fn save(path: &Path, blob: &KeystoreBlob) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_vec(blob)?)?;
    restrict(path)
}

/// Read the wrapped keystore blob from `path` (still encrypted).
pub fn load(path: &Path) -> anyhow::Result<KeystoreBlob> {
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

/// Restrict the keystore file to owner-only access on Unix.
fn restrict(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
