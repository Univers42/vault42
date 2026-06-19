/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   main.rs                                              :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! vault42-ssh — the hardened SSH edge (russh). It authenticates a registered Ed25519
//! public key as a login identity and provides authenticated transport only: the client
//! keystore unlock still happens locally, so plaintext reveal never occurs server-side
//! even if this host is fully compromised. Publickey-only; Ed25519 host/user keys.

mod config;
mod factory;
mod handler;
mod server;

use config::SshConfig;
use std::process::ExitCode;

/// Entry point: initialise tracing, read config, and run the SSH edge.
fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("vault42-ssh: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Build the runtime and serve the SSH edge.
fn run() -> anyhow::Result<()> {
    let cfg = SshConfig::from_env()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(server::run(cfg))
}
