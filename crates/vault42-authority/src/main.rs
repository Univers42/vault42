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

//! vault42-authority — accounts, organizations, teams, RBAC, and contract issuance.
//!
//! This is the standalone replacement for the grobase control plane. vault42 must own its
//! own business model: the grobase stack cannot run inside the fly.io budget it is meant
//! to protect, so every identity and permission decision moves here, behind one small
//! binary over embedded SQLite that scales to zero.
//!
//! It holds accounts, sessions, and the contract signing key. It never holds a secret's
//! plaintext, and it is off vault42's per-request path: a contract is signed once and
//! verified offline thereafter.

mod app;
mod auth;
mod config;
mod contract;
#[cfg(test)]
mod e2e;
#[cfg(test)]
mod e2e_orgs;
mod error;
mod handlers;
mod rbac;
mod routes;
mod store;
mod validate;

use app::App;
use config::Config;
use std::process::ExitCode;
use std::sync::Arc;
use vault42_contract::authority::Authority;
use vault42_contract::signing::now_unix;

/// Entry point: init tracing, then run the authority.
fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("vault42-authority: {error}");
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

/// Open the database, load the signing key, and serve HTTP.
async fn serve(cfg: Config) -> anyhow::Result<()> {
    let store = store::Store::open(&cfg.db_path, now_unix())?;
    let authority = Authority::open(
        cfg.seed_hex.as_deref(),
        &cfg.key_path,
        cfg.contract_ttl_days,
    )?;
    tracing::info!(
        public_key = %authority.public_hex(),
        bind = %cfg.bind,
        invite_gate = cfg.register_token.is_some(),
        "vault42-authority up — set public_key as vault42 VAULT42_CONTRACT_PUBKEY"
    );
    let app = Arc::new(App {
        store,
        authority,
        session_ttl_secs: cfg.session_ttl_secs,
        register_token: cfg.register_token,
    });
    let listener = tokio::net::TcpListener::bind(&cfg.bind).await?;
    axum::serve(listener, routes::router(app)).await?;
    Ok(())
}
