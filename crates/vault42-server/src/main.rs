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
mod grpc;
mod ops_read;
mod ops_write;
mod principal;
mod secret_read;
mod secret_write;
mod store;
mod svc;

use config::Config;
use std::process::ExitCode;
use store::Store;
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
    let store = Store::open(&cfg.db_path)?;
    let grobase = match &cfg.grobase {
        Some(grobase_cfg) => Some(connect_grobase(grobase_cfg)?),
        None => None,
    };
    let svc = VaultSvc::new(store, cfg.skew_secs, grobase);
    let addr = cfg.bind.parse()?;
    tracing::info!(%addr, "vault42-server listening");
    tonic::transport::Server::builder()
        .add_service(VaultServer::new(svc))
        .serve(addr)
        .await?;
    Ok(())
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
