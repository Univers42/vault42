/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   server.rs                                            :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Server bootstrap: an Ed25519 host key, publickey-only auth, and the run loop. Host
//! and user keys are Ed25519 only; there is no password method. The host key is
//! ephemeral per process unless `VAULT42_SSH_HOST_KEY` points at a stored OpenSSH key.

use crate::config::SshConfig;
use crate::factory::EdgeFactory;
use russh::server::{Config, Server as _};
use russh::MethodSet;
use russh_keys::key::KeyPair;
use std::sync::Arc;

/// Run the SSH edge until terminated.
pub async fn run(cfg: SshConfig) -> anyhow::Result<()> {
    let config = Config {
        methods: MethodSet::PUBLICKEY,
        keys: vec![host_key()?],
        ..Default::default()
    };
    let bind = cfg.bind.clone();
    let mut factory = EdgeFactory::new(cfg.authorized);
    tracing::info!(%bind, "vault42-ssh edge listening (publickey-only)");
    factory
        .run_on_address(Arc::new(config), bind.as_str())
        .await?;
    Ok(())
}

/// Load the Ed25519 host key from `VAULT42_SSH_HOST_KEY`, or generate an ephemeral one.
fn host_key() -> anyhow::Result<KeyPair> {
    match std::env::var("VAULT42_SSH_HOST_KEY") {
        Ok(path) => Ok(russh_keys::load_secret_key(path, None)?),
        Err(_) => {
            KeyPair::generate_ed25519().ok_or_else(|| anyhow::anyhow!("host key generation failed"))
        }
    }
}
