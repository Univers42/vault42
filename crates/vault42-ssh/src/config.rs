/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   config.rs                                            :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! SSH edge configuration from the environment. The authorized-key allowlist
//! (`VAULT42_SSH_AUTHORIZED_KEYS`, newline/comma separated OpenSSH public keys) is the
//! only thing that grants transport; there is no password auth. No private key or
//! secret material is configured here — the edge never decrypts anything.

use russh_keys::key::PublicKey;

/// The resolved SSH edge configuration.
pub struct SshConfig {
    pub bind: String,
    pub authorized: Vec<PublicKey>,
}

impl SshConfig {
    /// Read host/port and the authorized-key allowlist from the environment.
    pub fn from_env() -> anyhow::Result<Self> {
        let host = std::env::var("VAULT42_SSH_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port = std::env::var("VAULT42_SSH_PORT").unwrap_or_else(|_| "2222".to_string());
        Ok(Self {
            bind: format!("{host}:{port}"),
            authorized: load_authorized()?,
        })
    }
}

/// Parse the authorized-key allowlist from `VAULT42_SSH_AUTHORIZED_KEYS`.
fn load_authorized() -> anyhow::Result<Vec<PublicKey>> {
    let raw = std::env::var("VAULT42_SSH_AUTHORIZED_KEYS").unwrap_or_default();
    let mut keys = Vec::new();
    for line in raw
        .split(['\n', ','])
        .map(str::trim)
        .filter(|l| !l.is_empty())
    {
        keys.push(parse_key(line)?);
    }
    Ok(keys)
}

/// Parse one OpenSSH public key line (`ssh-ed25519 AAAA... comment`) into a key.
fn parse_key(line: &str) -> anyhow::Result<PublicKey> {
    let b64 = line.split_whitespace().nth(1).unwrap_or(line);
    russh_keys::parse_public_key_base64(b64).map_err(|e| anyhow::anyhow!("bad authorized key: {e}"))
}
