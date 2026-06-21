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

/// Optional private-grobase connection (the control-plane audit/decide hop).
pub struct GrobaseCfg {
    pub url: String,
    pub token: Vec<u8>,
}

/// The grobase-backed storage connection: the Kong front door, the public + app API
/// keys, the `vault42_secrets` mount id, and the JWT secret used to mint per-owner
/// sessions. Present (and selected) only when storage is delegated to grobase.
pub struct GrobaseStoreCfg {
    pub kong: String,
    pub anon_key: String,
    pub app_key: String,
    pub db_id: String,
    pub jwt_secret: Vec<u8>,
    pub jwt_ttl: i64,
}

/// The resolved server configuration.
pub struct Config {
    pub bind: String,
    pub db_path: String,
    pub skew_secs: i64,
    pub grobase: Option<GrobaseCfg>,
    pub grobase_store: Option<GrobaseStoreCfg>,
    pub contract_pub: Option<[u8; 32]>,
    pub max_secrets: i64,
}

impl Config {
    /// Read the configuration from the environment, applying defaults. Storage is the
    /// grobase backend when its env is complete and `VAULT42_STORE != sqlite`; otherwise
    /// the embedded SQLite store (the offline `nano` default).
    pub fn from_env() -> Self {
        let host = env("VAULT42_HOST", "0.0.0.0");
        let port = env("VAULT42_PORT", "8443");
        let grobase_store = match env("VAULT42_STORE", "").as_str() {
            "sqlite" => None,
            _ => grobase_store_cfg(),
        };
        Self {
            bind: format!("{host}:{port}"),
            db_path: env("VAULT42_DB", "/data/vault42.db"),
            skew_secs: env("VAULT42_AUTH_SKEW_SECS", "120").parse().unwrap_or(120),
            grobase: grobase_cfg(),
            grobase_store,
            contract_pub: contract_pub(),
            max_secrets: env("VAULT42_MAX_SECRETS", "0").parse().unwrap_or(0),
        }
    }
}

/// Read an environment variable with a default.
fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Parse the authority contract public key (hex, 32 bytes) from
/// `VAULT42_CONTRACT_PUBKEY`. When set, the server requires a valid contract per request
/// (managed multi-tenancy); when absent, it runs standalone (tenant "self").
fn contract_pub() -> Option<[u8; 32]> {
    let hex_key = std::env::var("VAULT42_CONTRACT_PUBKEY").ok()?;
    let bytes = hex::decode(hex_key.trim()).ok()?;
    bytes.as_slice().try_into().ok()
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

/// Build the grobase storage config iff every required var is present: the Kong URL,
/// the public + app API keys, the mount id, and the JWT secret (`JWT_TTL_SECS`
/// defaults to one hour).
fn grobase_store_cfg() -> Option<GrobaseStoreCfg> {
    let kong = std::env::var("GROBASE_QUERY_URL").ok()?;
    let anon_key = std::env::var("GROBASE_ANON_KEY").ok()?;
    let app_key = std::env::var("GROBASE_APP_KEY").ok()?;
    let db_id = std::env::var("GROBASE_DB_ID").ok()?;
    let jwt_secret = std::env::var("JWT_SECRET").ok()?;
    Some(GrobaseStoreCfg {
        kong,
        anon_key,
        app_key,
        db_id,
        jwt_secret: jwt_secret.into_bytes(),
        jwt_ttl: env("JWT_TTL_SECS", "3600").parse().unwrap_or(3600),
    })
}
