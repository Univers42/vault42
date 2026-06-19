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

//! Authority configuration from the environment. The contract signing key comes from
//! `VAULT42_CONTRACT_SEED` (hex of 32 bytes) when set, else it is generated once and
//! persisted to `key_path` on the encrypted volume so the public key is stable across
//! restarts (vault42 verifies contracts against it).

/// The resolved authority configuration.
pub struct Config {
    pub bind: String,
    pub db_path: String,
    pub key_path: String,
    pub seed_hex: Option<String>,
    pub ttl_days: i64,
}

impl Config {
    /// Read the configuration from the environment, applying defaults.
    pub fn from_env() -> Self {
        let host = env("VAULT42_CONTRACT_HOST", "0.0.0.0");
        let port = env("VAULT42_CONTRACT_PORT", "8443");
        Self {
            bind: format!("{host}:{port}"),
            db_path: env("VAULT42_CONTRACT_DB", "/data/contract.db"),
            key_path: env("VAULT42_CONTRACT_KEY", "/data/contract.key"),
            seed_hex: std::env::var("VAULT42_CONTRACT_SEED").ok(),
            ttl_days: env("VAULT42_CONTRACT_TTL_DAYS", "365")
                .parse()
                .unwrap_or(365),
        }
    }
}

/// Read an environment variable with a default.
fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
