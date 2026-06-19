/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   cli.rs                                               :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The clap command surface for the `vault42` binary. Each subcommand maps to one
//! gRPC verb; all plaintext crypto happens locally in the verb handlers, never here.

use clap::{Parser, Subcommand};

/// vault42 — a zero-knowledge secrets vault client.
#[derive(Parser)]
#[command(name = "vault42", version, about = "zero-knowledge secrets vault CLI")]
pub struct Cli {
    /// The vault42-server URL (https enables TLS to the fly edge).
    #[arg(long, env = "VAULT42_SERVER", default_value = "http://127.0.0.1:8443")]
    pub server: String,
    #[command(subcommand)]
    pub command: Command,
}

/// The vault42 verbs.
#[derive(Subcommand)]
pub enum Command {
    /// Generate a local identity and passphrase-wrapped keystore.
    Init {
        #[arg(long)]
        force: bool,
    },
    /// Print this identity's principal and shareable address.
    Whoami,
    /// Register this identity with a contract authority and save the contract.
    Register {
        #[arg(long, env = "VAULT42_AUTHORITY")]
        authority: String,
        #[arg(long)]
        tenant: String,
    },
    /// Seal a secret (stdin or --file) and push it.
    Set {
        path: String,
        #[arg(long)]
        file: Option<String>,
    },
    /// Fetch and locally decrypt a secret to stdout.
    Get {
        path: String,
        #[arg(long, default_value_t = 0)]
        version: u64,
    },
    /// List secrets under an optional prefix.
    Ls {
        #[arg(default_value = "")]
        prefix: String,
    },
    /// Remove a secret.
    Rm { path: String },
    /// Re-seal a secret under a fresh data key (key rotation).
    Rotate { path: String },
    /// Re-seal a secret for another identity's address.
    Share {
        path: String,
        #[arg(long)]
        to: String,
    },
    /// Stream this identity's tamper-evident audit chain.
    Audit {
        #[arg(long, default_value_t = 0)]
        since: i64,
    },
}
