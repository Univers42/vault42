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

//! vault42-contract — the contract authority (the nano grobase peer). It registers
//! tenants and issues Ed25519-signed contracts, then idles: vault42 verifies contracts
//! offline, so this service does no per-request work and scales to zero (~free). It owns
//! only tenant metadata + the signing key; it never sees a secret or a plaintext.

mod authority;
mod config;
mod routes;
mod signing;
mod store;

use config::Config;
use routes::{router, App};
use std::process::ExitCode;
use std::sync::Arc;

/// Entry point: init tracing, then run the authority.
fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("vault42-contract: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Build the runtime and serve until terminated.
fn run() -> anyhow::Result<()> {
    let cfg = Config::from_env();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(serve(cfg))
}

/// Open the registry, load the signing key, and serve the HTTP authority.
async fn serve(cfg: Config) -> anyhow::Result<()> {
    let store = store::Store::open(&cfg.db_path)?;
    let authority = authority::Authority::load(&cfg)?;
    tracing::info!(
        public_key = %authority.public_hex(),
        bind = %cfg.bind,
        "vault42-contract authority up — set public_key as vault42 VAULT42_CONTRACT_PUBKEY"
    );
    let app = Arc::new(App { authority, store });
    let listener = tokio::net::TcpListener::bind(&cfg.bind).await?;
    axum::serve(listener, router(app)).await?;
    Ok(())
}
