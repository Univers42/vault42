/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   verbs_init.rs                                        :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! `vault42 init` — generate a fresh identity, wrap it under a new passphrase, and
//! write the keystore. The private keys exist only in memory during sealing; only the
//! encrypted blob is persisted. Prints the principal and shareable address.

use crate::{address, keystore_io, passphrase};
use vault42_core::{seal_keystore, Identity, KdfParams};

/// Create a new local identity and keystore, refusing to clobber an existing one
/// unless `force` is set.
pub fn cmd_init(force: bool) -> anyhow::Result<()> {
    let path = keystore_io::keystore_path()?;
    if path.exists() && !force {
        anyhow::bail!(
            "keystore already exists at {} (use --force)",
            path.display()
        );
    }
    let identity = Identity::generate();
    let passphrase = passphrase::prompt_new_passphrase()?;
    let blob = seal_keystore(&identity, passphrase.as_bytes(), KdfParams::default())?;
    keystore_io::save(&path, &blob)?;
    let principal = hex::encode(vault42_core::fingerprint(
        &identity.author_public().to_bytes(),
    ));
    println!("identity created");
    println!("principal: {principal}");
    println!("address:   {}", address::encode(&identity));
    Ok(())
}
