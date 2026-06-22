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

//! vault42-server — the public gRPC edge (tonic). A STATELESS orchestrator: it
//! authenticates the caller (Ed25519 challenge), authorizes by owner-scope, stores and
//! serves opaque envelopes, and audits — it never holds plaintext or an unwrapped DEK.
//! TLS is terminated at the fly edge, so the server speaks plaintext HTTP/2 internally.

// tonic's `Status` IS the framework error type: every handler and helper returns
// `Result<_, Status>`, and the generated `Vault` trait signatures cannot box it — so the
// large-Err-variant lint is inapplicable here, like a generated-code allow.
#![allow(clippy::result_large_err)]

mod audit_rpc;
mod audit_store;
mod authn;
mod config;
#[cfg(test)]
mod e2e;
mod grobase_store;
mod grpc;
mod jwt;
mod ops_read;
mod ops_rotate;
mod ops_scope;
mod ops_write;
mod principal;
mod scope_store;
mod secret_read;
mod secret_write;
mod store;
mod store_trait;
mod svc;

use config::Config;
use grobase_store::GrobaseStore;
use std::process::ExitCode;
use std::sync::Arc;
use store::Store;
use store_trait::SecretStore;
use svc::{connect_grobase, VaultSvc};
use vault42_proto::vault::v1::vault_server::VaultServer;

/// Entry point. `--healthcheck` probes the listener for the container health check;
/// otherwise it builds the runtime and serves until terminated.
fn main() -> ExitCode {
    if std::env::args().any(|arg| arg == "--healthcheck") {
        return healthcheck();
    }
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("vault42-server: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Initialise tracing, read config, and drive the async server on a multi-thread runtime.
fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let cfg = Config::from_env();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(serve(cfg))
}

/// Build the service from config and serve gRPC until the process is terminated.
async fn serve(cfg: Config) -> anyhow::Result<()> {
    let store = select_store(&cfg)?;
    let grobase = match &cfg.grobase {
        Some(grobase_cfg) => Some(connect_grobase(grobase_cfg)?),
        None => None,
    };
    let svc = VaultSvc::new(store, cfg.skew_secs, grobase, cfg.contract_pub)
        .with_scope_keys(cfg.scope_keys_enabled);
    let addr = cfg.bind.parse()?;
    tracing::info!(%addr, "vault42-server listening");
    tonic::transport::Server::builder()
        .add_service(VaultServer::new(svc))
        .serve(addr)
        .await?;
    Ok(())
}

/// Select the storage backend: grobase over `/query/v1` when its config is present
/// (the connected default), else the embedded SQLite store (offline `nano`).
fn select_store(cfg: &Config) -> anyhow::Result<Arc<dyn SecretStore>> {
    if let Some(gs) = &cfg.grobase_store {
        tracing::info!("vault42-server storage backend: grobase (/query/v1)");
        let store = GrobaseStore::new(
            gs.kong.clone(),
            gs.anon_key.clone(),
            gs.app_key.clone(),
            gs.db_id.clone(),
            gs.jwt_secret.clone(),
            gs.jwt_ttl,
        )?;
        return Ok(Arc::new(store));
    }
    tracing::info!("vault42-server storage backend: embedded sqlite");
    Ok(Arc::new(Store::open(&cfg.db_path, cfg.max_secrets)?))
}

/// TCP-probe the configured listener for the container/fly health check.
fn healthcheck() -> ExitCode {
    let host = std::env::var("VAULT42_HEALTH_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = std::env::var("VAULT42_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8443);
    match std::net::TcpStream::connect((host.as_str(), port)) {
        Ok(_) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
