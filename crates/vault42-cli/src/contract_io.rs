/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   contract_io.rs                                       :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The local contract token file — the credential the authority issued at registration.
//! It sits next to the keystore (`$VAULT42_CONTRACT` or `~/.config/vault42/contract.tok`)
//! and is sent as `x-v42-contract` on every request when present. It carries no secret
//! (a signed, public claim), so it is stored in the clear.

use std::path::PathBuf;

/// The contract file path: `$VAULT42_CONTRACT` or the per-user default.
pub fn contract_path() -> PathBuf {
    std::env::var("VAULT42_CONTRACT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_path())
}

/// The default contract path under the user config dir.
fn default_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("vault42")
        .join("contract.tok")
}

/// Load the saved contract token, if any.
pub fn load_contract() -> Option<String> {
    std::fs::read_to_string(contract_path())
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Persist a contract token, creating parent directories.
pub fn save_contract(token: &str) -> anyhow::Result<()> {
    let path = contract_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, token)?;
    Ok(())
}
