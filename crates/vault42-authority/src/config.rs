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

//! Authority configuration from the environment.
//!
//! The contract signing key is the root of trust vault42 verifies against, so it is
//! resolved exactly as `vault42-contract` resolves it: a hex seed from the environment
//! when set, otherwise generated once and persisted `0600` on the encrypted volume.
//! Sharing that logic is why this crate depends on `vault42-contract` rather than
//! reimplementing it.

/// The resolved authority configuration.
pub struct Config {
    pub bind: String,
    pub db_path: String,
    pub key_path: String,
    pub seed_hex: Option<String>,
    pub contract_ttl_days: i64,
    pub session_ttl_secs: i64,
    pub register_token: Option<String>,
}

impl Config {
    /// Read the configuration from the environment, applying defaults.
    ///
    /// Never fails: a malformed integer falls back to its default rather than refusing
    /// to boot, matching the other vault42 binaries. The chosen values are logged at
    /// startup so a typo is visible.
    pub fn from_env() -> Self {
        let host = env("VAULT42_AUTHORITY_HOST", "0.0.0.0");
        let port = env("VAULT42_AUTHORITY_PORT", "8444");
        Self {
            bind: format!("{host}:{port}"),
            db_path: env("VAULT42_AUTHORITY_DB", "/data/authority.db"),
            key_path: env("VAULT42_AUTHORITY_KEY", "/data/contract.key"),
            seed_hex: std::env::var("VAULT42_CONTRACT_SEED").ok(),
            contract_ttl_days: parse_or("VAULT42_CONTRACT_TTL_DAYS", 365),
            session_ttl_secs: parse_or("VAULT42_AUTHORITY_SESSION_TTL_SECS", 86_400),
            register_token: std::env::var("VAULT42_REGISTER_TOKEN").ok(),
        }
    }
}

/// Read an environment variable with a default.
fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Read an integer environment variable, falling back to `default` when absent or junk.
fn parse_or(key: &str, default: i64) -> i64 {
    std::env::var(key)
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(default)
}
