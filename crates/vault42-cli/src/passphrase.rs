/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   passphrase.rs                                        :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Passphrase prompting and keystore unlocking. The passphrase is read without echo
//! and held in a `Zeroizing` buffer; `unlock` derives the KSK and reconstructs the
//! identity entirely locally — the passphrase and the unwrapped keys never leave the
//! process and never touch the server.

use vault42_core::{open_keystore, Identity};
use zeroize::Zeroizing;

/// Prompt once for an existing passphrase (no echo). `VAULT42_PASSPHRASE`, when set,
/// supplies it non-interactively for automation/CI.
pub fn prompt_passphrase() -> anyhow::Result<Zeroizing<String>> {
    if let Ok(passphrase) = std::env::var("VAULT42_PASSPHRASE") {
        return Ok(Zeroizing::new(passphrase));
    }
    Ok(Zeroizing::new(rpassword::prompt_password("passphrase: ")?))
}

/// Prompt twice for a new passphrase and require them to match. `VAULT42_PASSPHRASE`,
/// when set, supplies it non-interactively (no confirmation prompt).
pub fn prompt_new_passphrase() -> anyhow::Result<Zeroizing<String>> {
    if let Ok(passphrase) = std::env::var("VAULT42_PASSPHRASE") {
        return Ok(Zeroizing::new(passphrase));
    }
    let first = rpassword::prompt_password("new passphrase: ")?;
    let second = rpassword::prompt_password("confirm passphrase: ")?;
    if first != second {
        anyhow::bail!("passphrases do not match");
    }
    Ok(Zeroizing::new(first))
}

/// Load the keystore and unlock it into an in-memory identity.
pub fn unlock() -> anyhow::Result<Identity> {
    let path = crate::keystore_io::keystore_path()?;
    if !path.exists() {
        anyhow::bail!(
            "no keystore at {} — run `vault42 init` first",
            path.display()
        );
    }
    let blob = crate::keystore_io::load(&path)?;
    let passphrase = prompt_passphrase()?;
    open_keystore(&blob, passphrase.as_bytes())
        .map_err(|_| anyhow::anyhow!("could not unlock keystore"))
}
