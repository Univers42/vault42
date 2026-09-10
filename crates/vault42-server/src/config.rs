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
    pub scope_keys_enabled: bool,
}

impl Config {
    /// Read the configuration from the environment, applying defaults. Storage is SQLite
    /// unless `VAULT42_STORE=grobase` asks for the grobase backend explicitly.
    ///
    /// The choice used to be inferred: grobase won whenever five environment variables
    /// happened to be set together and nobody had said `VAULT42_STORE=sqlite`. That made a
    /// leftover deployment variable enough to move the vault's data plane onto a backend this
    /// product has rejected, silently, with only a `tracing::info!` line naming the winner.
    /// The two backends are not equivalent: SQLite serialises read-then-write through a
    /// one-connection pool so audit-chain links are atomic, while the grobase store does
    /// read-head-then-insert over HTTP, which is a real TOCTOU on the audit chain.
    ///
    /// Opting in has to be deliberate now. `VAULT42_STORE=sqlite` still works and is the
    /// default, so nothing that was explicit before changes meaning.
    ///
    /// Fails rather than defaulting when `VAULT42_CONTRACT_PUBKEY` is present but unusable.
    /// Every other setting has a safe default; that one decides whether requests are gated by
    /// a contract at all, and guessing "standalone" for a malformed value silently opens the
    /// server. Refusing to boot is the only answer that cannot be mistaken for working.
    pub fn from_env() -> anyhow::Result<Self> {
        let host = env("VAULT42_HOST", "0.0.0.0");
        let port = env("VAULT42_PORT", "8443");
        let grobase_store = wants_grobase_store(&env("VAULT42_STORE", ""))
            .then(grobase_store_cfg)
            .flatten();
        let contract_pub = contract_pub().map_err(|why| anyhow::anyhow!(why))?;
        require_a_deliberate_gate_decision(contract_pub.is_some(), flag("VAULT42_ALLOW_UNGATED"))
            .map_err(|why| anyhow::anyhow!(why))?;
        Ok(Self {
            bind: format!("{host}:{port}"),
            db_path: env("VAULT42_DB", "/data/vault42.db"),
            skew_secs: env("VAULT42_AUTH_SKEW_SECS", "120").parse().unwrap_or(120),
            grobase: grobase_cfg(),
            grobase_store,
            contract_pub,
            max_secrets: env("VAULT42_MAX_SECRETS", "0").parse().unwrap_or(0),
            scope_keys_enabled: flag("VAULT42_SCOPE_KEYS_ENABLED"),
        })
    }
}

/// Refuse to start ungated unless somebody said so.
///
/// Without `VAULT42_CONTRACT_PUBKEY` the server accepts any self-generated keypair: no authority
/// vouches for anybody, and the only remaining limit is the per-owner secret cap. That is a
/// legitimate way to run — it is how every local harness runs — and it is the opposite security
/// posture from the deployed one.
///
/// It used to be what you got by FORGETTING the variable. A missing value chose the open posture
/// silently, so a deployment that lost its secret, or a config file with a typo in the name, came
/// up looking healthy and gated nobody. Refusing a malformed key was already the rule for exactly
/// this reason; an absent one is the same question with a quieter failure.
///
/// So the open posture now needs a word: `VAULT42_ALLOW_UNGATED=1`. Nothing that was explicit
/// before changes meaning, and the two ways to be wrong — forgetting the key, and meaning to run
/// open — stop looking identical.
fn require_a_deliberate_gate_decision(gated: bool, allow_ungated: bool) -> Result<(), String> {
    if gated || allow_ungated {
        return Ok(());
    }
    Err(
        "VAULT42_CONTRACT_PUBKEY is unset, so no authority would vouch for any caller. Set it to \
         the authority's public key, or set VAULT42_ALLOW_UNGATED=1 to say you meant to run \
         without a contract gate."
            .to_string(),
    )
}

/// Read a boolean feature flag (OFF unless explicitly "1" or "true"). Default OFF keeps
/// the wire byte-parity with the OSS edition.
fn flag(key: &str) -> bool {
    matches!(env(key, "").as_str(), "1" | "true")
}

/// Read an environment variable with a default.
fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Parse the authority contract public key (hex, 32 bytes) from `VAULT42_CONTRACT_PUBKEY`.
///
/// Unset means standalone (tenant "self"); set means every request must carry a contract this
/// key signed. Those are opposite security postures, so a value that is present but unusable is
/// an error rather than a third meaning. It used to fall back to standalone, which accepted any
/// self-generated keypair with an unlimited quota — and looked entirely healthy doing it.
///
/// The reachable way to hit that is documented in our own runbook, which pipes `curl` into
/// `fly secrets set`: if the authority is unreachable at that moment the secret becomes an empty
/// string, and an empty string used to parse as "standalone".
fn contract_pub() -> Result<Option<[u8; 32]>, String> {
    parse_contract_pub(std::env::var("VAULT42_CONTRACT_PUBKEY").ok().as_deref())
}

/// The parsing half, separated so the rule can be tested without touching the environment.
///
/// `None` is unset and means standalone. `Some` must be usable: every other outcome is an error,
/// because the two postures are opposite and there is no safe third reading.
fn parse_contract_pub(raw: Option<&str>) -> Result<Option<[u8; 32]>, String> {
    let Some(hex_key) = raw else {
        return Ok(None);
    };
    let trimmed = hex_key.trim();
    if trimmed.is_empty() {
        return Err("VAULT42_CONTRACT_PUBKEY is set but empty; unset it to run standalone".into());
    }
    let bytes =
        hex::decode(trimmed).map_err(|_| "VAULT42_CONTRACT_PUBKEY is not valid hex".to_string())?;
    let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        format!(
            "VAULT42_CONTRACT_PUBKEY must be 32 bytes of hex, got {}",
            bytes.len()
        )
    })?;
    Ok(Some(key))
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
/// Whether `asked` selects the grobase store. Only the exact opt-in does.
///
/// Separated from reading the environment so the rule is tested without env races, which is the
/// same reason `parse_contract_pub` is separate: a decision that changes where the vault's data
/// lives should be provable without a process-wide variable.
fn wants_grobase_store(asked: &str) -> bool {
    asked == "grobase"
}

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Only the exact opt-in selects grobase; everything else, unset included, stays on SQLite.
    ///
    /// This is the whole point of requiring an opt-in: five leftover variables from an old
    /// deployment used to be enough to move the data plane, and the only notice was a log line.
    #[test]
    fn only_an_explicit_opt_in_selects_the_grobase_store() {
        assert!(wants_grobase_store("grobase"));
        for other in [
            "", "sqlite", "SQLITE", "Grobase", "GROBASE", " grobase", "grobase ", "postgres", "1",
            "true", "yes", "none",
        ] {
            assert!(
                !wants_grobase_store(other),
                "{other:?} must not move the vault's data plane onto grobase"
            );
        }
    }

    /// Forgetting the key and meaning to run open must not look the same.
    ///
    /// The open posture accepts any self-generated keypair, so arriving at it by omission is the
    /// failure that comes up healthy and gates nobody.
    #[test]
    fn running_ungated_requires_saying_so() {
        assert!(
            require_a_deliberate_gate_decision(false, false).is_err(),
            "an absent contract key with no opt-in must refuse to start"
        );
        assert!(
            require_a_deliberate_gate_decision(false, true).is_ok(),
            "positive control: the explicit opt-in must still work, or local harnesses cannot run"
        );
        assert!(
            require_a_deliberate_gate_decision(true, false).is_ok(),
            "positive control: a gated server must start without any opt-in"
        );
        let why = require_a_deliberate_gate_decision(false, false).expect_err("refuses");
        assert!(
            why.contains("VAULT42_ALLOW_UNGATED"),
            "the refusal must name the way out, or an operator debugs the wrong layer: {why}"
        );
    }

    /// Unset means standalone, and that is the only way to get standalone.
    #[test]
    fn only_an_absent_key_means_standalone() {
        assert_eq!(parse_contract_pub(None), Ok(None));
    }

    /// A syntactically valid 32-byte key, deliberately patterned rather than random-looking.
    ///
    /// A contract public key is not secret, but a high-entropy hex literal in a `config.rs` is
    /// indistinguishable from one to a scanner, and the honest fix is a fixture that is visibly
    /// synthetic rather than an allowlist entry that would blind gitleaks to this whole file — which
    /// is precisely where a real credential would appear. It still carries letters, so the
    /// case-insensitivity assertion below is unaffected.
    const PATTERNED_KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    /// A well-formed key is parsed, whitespace and case included.
    #[test]
    fn a_valid_key_is_accepted() {
        let parsed = parse_contract_pub(Some(PATTERNED_KEY))
            .expect("valid")
            .expect("some");
        assert_eq!(hex::encode(parsed), PATTERNED_KEY);
        assert!(parse_contract_pub(Some(&format!("  {PATTERNED_KEY}\n"))).is_ok());
        assert!(parse_contract_pub(Some(&PATTERNED_KEY.to_uppercase())).is_ok());
    }

    /// A key that is present but unusable is an error, never a quiet fall back to standalone.
    ///
    /// The empty string is the case our own runbook can produce: it pipes `curl` into
    /// `fly secrets set`, so an unreachable authority sets the secret to nothing. That used to
    /// parse as standalone, which accepts any self-generated keypair with an unlimited quota.
    #[test]
    fn a_present_but_unusable_key_refuses_to_boot() {
        let too_long = format!("{PATTERNED_KEY}ff");
        let quoted = format!("\"{PATTERNED_KEY}\"");
        for bad in [
            "",
            "   ",
            "not hex at all",
            "d75a98",
            too_long.as_str(),
            quoted.as_str(),
        ] {
            assert!(
                parse_contract_pub(Some(bad)).is_err(),
                "{bad:?} must refuse rather than fall back to standalone"
            );
        }
    }
}
