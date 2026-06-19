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

//! vault42 — the zero-knowledge CLI (the primary surface). ALL plaintext crypto
//! happens here, on the client; only ciphertext ever leaves the machine. `init` runs
//! offline; every other verb unlocks the local keystore, opens a signed gRPC session,
//! and dispatches. Plaintext is read into a `Zeroizing` buffer and never logged.

mod address;
mod cli;
mod client;
mod decrypt;
mod derive;
mod keystore_io;
mod passphrase;
mod verbs_audit;
mod verbs_init;
mod verbs_manage;
mod verbs_secret;
mod verbs_share;

use clap::Parser;
use cli::{Cli, Command};
use client::Session;
use std::process::ExitCode;
use zeroize::Zeroizing;

/// Entry point: print errors with their cause chain and map to an exit code.
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("vault42: {error:#}");
            ExitCode::FAILURE
        }
    }
}

/// Parse args; run `init` synchronously, otherwise drive the async dispatch.
fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if let Command::Init { force } = &cli.command {
        return verbs_init::cmd_init(*force);
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(dispatch(cli))
}

/// Unlock the keystore, open a session, and run the requested verb.
async fn dispatch(cli: Cli) -> anyhow::Result<()> {
    let identity = passphrase::unlock()?;
    let mut session = Session::connect(&cli.server, identity).await?;
    match cli.command {
        Command::Whoami => session.cmd_whoami().await,
        Command::Set { path, file } => session.cmd_set(&path, read_input(file)?).await,
        Command::Get { path, version } => session.cmd_get(&path, version).await,
        Command::Ls { prefix } => session.cmd_ls(&prefix).await,
        Command::Rm { path } => session.cmd_rm(&path).await,
        Command::Rotate { path } => session.cmd_rotate(&path).await,
        Command::Share { path, to } => session.cmd_share(&path, &to).await,
        Command::Audit { since } => session.cmd_audit(since).await,
        Command::Init { .. } => unreachable!("init handled before the runtime"),
    }
}

/// Read secret input from a file or stdin into a zeroizing buffer.
fn read_input(file: Option<String>) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    match file {
        Some(path) => Ok(Zeroizing::new(std::fs::read(path)?)),
        None => {
            use std::io::Read;
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            Ok(Zeroizing::new(buf))
        }
    }
}
