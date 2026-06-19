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

//! Server configuration, read once from the environment at startup and injected
//! (no globals). The grobase seam is optional: with `GROBASE_URL` +
//! `INTERNAL_SERVICE_TOKEN` set, the server binds callers to a grobase tenant and
//! mirrors audit there; without them it runs standalone on its own Ed25519 identity.

/// Optional private-grobase connection.
pub struct GrobaseCfg {
    pub url: String,
    pub token: Vec<u8>,
}

/// The resolved server configuration.
pub struct Config {
    pub bind: String,
    pub db_path: String,
    pub skew_secs: i64,
    pub grobase: Option<GrobaseCfg>,
}

impl Config {
    /// Read the configuration from the environment, applying defaults.
    pub fn from_env() -> Self {
        let host = env("VAULT42_HOST", "0.0.0.0");
        let port = env("VAULT42_PORT", "8443");
        Self {
            bind: format!("{host}:{port}"),
            db_path: env("VAULT42_DB", "/data/vault42.db"),
            skew_secs: env("VAULT42_AUTH_SKEW_SECS", "120").parse().unwrap_or(120),
            grobase: grobase_cfg(),
        }
    }
}

/// Read an environment variable with a default.
fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Build the grobase config iff both the URL and the service token are present.
fn grobase_cfg() -> Option<GrobaseCfg> {
    let url = std::env::var("GROBASE_URL").ok()?;
    let token = std::env::var("INTERNAL_SERVICE_TOKEN").ok()?;
    Some(GrobaseCfg {
        url,
        token: token.into_bytes(),
    })
}
