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
    pub otp: OtpConfig,
    pub mail: MailConfig,
    pub github: GithubConfig,
}

/// GitHub device-flow settings.
///
/// The two base URLs are configurable for the same reason the mail transport is: a battery has to
/// be able to attack this route without github.com, and an external service's answer feeding
/// session minting is exactly the path worth attacking. They default to the real hosts, so an
/// unset variable can never point sign-in somewhere unexpected.
pub struct GithubConfig {
    pub client_id: Option<String>,
    pub oauth_base: String,
    pub api_base: String,
}

/// One-time-code settings.
///
/// `proof_secret` is shared with `vault42-contract`, which verifies the proof this authority
/// mints. Without it there is no second factor at all, so `second_factors_enabled` is derived
/// from its presence rather than from a separate switch somebody could set inconsistently.
pub struct OtpConfig {
    pub proof_secret: Option<Vec<u8>>,
    pub ttl_secs: i64,
    pub proof_ttl_secs: i64,
}

/// How a one-time code reaches the person it is for.
///
/// `Smtp` is the only production transport. `File` renders exactly the same message and writes
/// it into a directory instead, which is what lets a test read a code without a mailbox. There
/// is deliberately no transport that writes a code to the log: "a code never appears in a log
/// line" is a property worth keeping true, and a logging transport would make it false on
/// purpose.
pub enum MailTransport {
    Smtp,
    File(String),
}

/// The mail envelope and the transport that carries it.
///
/// `from` and `password` have no defaults on purpose. A compiled-in sender address means anybody
/// self-hosting this binary sends as whoever built it, and a guessed credential name means a
/// misconfiguration that looks like a working setup. Both are named explicitly by the operator, and
/// second factors refuse to start without them.
pub struct MailConfig {
    pub transport: MailTransport,
    pub from: String,
    pub host: String,
    pub port: u16,
    pub password: Option<String>,
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
            otp: OtpConfig {
                proof_secret: otp_proof_secret(),
                ttl_secs: parse_or("VAULT42_OTP_TTL_SECS", 300),
                proof_ttl_secs: parse_or("VAULT42_OTP_PROOF_TTL_SECS", 600),
            },
            github: GithubConfig {
                client_id: std::env::var("GITHUB_CLIENT_ID")
                    .ok()
                    .filter(|v| !v.is_empty()),
                oauth_base: env("GITHUB_OAUTH_BASE", "https://github.com"),
                api_base: env("GITHUB_API_BASE", "https://api.github.com"),
            },
            mail: MailConfig {
                transport: mail_transport(),
                from: env("MAIL_FROM", ""),
                host: env("MAIL_HOST", "smtp.titan.email"),
                port: parse_or("MAIL_PORT", 465) as u16,
                password: std::env::var("MAIL_PASSWORD")
                    .ok()
                    .filter(|p| !p.is_empty()),
            },
        }
    }

    /// Whether second factors are available at all: they need a proof secret to sign with.
    pub fn second_factors_enabled(&self) -> bool {
        self.otp.proof_secret.is_some()
    }

    /// Refuse to start with second factors enabled but no way to deliver a code.
    ///
    /// Failing closed matters more here than anywhere else in the configuration. A running
    /// authority that accepts a code request it cannot deliver looks healthy and locks every
    /// account out of its second factor, and the operator finds out from users rather than from
    /// the process.
    pub fn check_mail_usable(&self) -> Result<(), String> {
        if !self.second_factors_enabled() {
            return Ok(());
        }
        if self.mail.from.is_empty() {
            return Err("second factors need MAIL_FROM to name the sending address".into());
        }
        match &self.mail.transport {
            MailTransport::File(dir) if dir.is_empty() => {
                Err("MAIL_TRANSPORT=file needs MAIL_OUTBOX to name a directory".into())
            }
            MailTransport::File(_) => Ok(()),
            MailTransport::Smtp if self.mail.password.is_none() => {
                Err("second factors need MAIL_PASSWORD to authenticate SMTP".into())
            }
            MailTransport::Smtp => Ok(()),
        }
    }
}

/// The shared secret the one-time-code proof is signed with.
///
/// `VAULT42_OTP_PROOF_SECRET` is the name to use. `GOTRUE_JWT_SECRET` is honoured after it
/// because that is what deployments set while grobase minted these proofs; the authority mints
/// them now, so the grobase-shaped name is legacy and kept only so an existing deployment does
/// not break on upgrade.
fn otp_proof_secret() -> Option<Vec<u8>> {
    std::env::var("VAULT42_OTP_PROOF_SECRET")
        .or_else(|_| std::env::var("GOTRUE_JWT_SECRET"))
        .ok()
        .map(String::into_bytes)
}

/// Resolve the mail transport, defaulting to SMTP so a missing variable never silently
/// diverts real mail into a directory.
fn mail_transport() -> MailTransport {
    match env("MAIL_TRANSPORT", "smtp").as_str() {
        "file" => MailTransport::File(env("MAIL_OUTBOX", "")),
        _ => MailTransport::Smtp,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A config with second factors on and a usable transport starts.
    fn usable(transport: MailTransport, password: Option<&str>) -> Config {
        Config {
            bind: "127.0.0.1:0".into(),
            db_path: ":memory:".into(),
            key_path: "/tmp/k".into(),
            seed_hex: None,
            contract_ttl_days: 365,
            session_ttl_secs: 3600,
            register_token: None,
            otp: OtpConfig {
                proof_secret: Some(b"secret".to_vec()),
                ttl_secs: 300,
                proof_ttl_secs: 600,
            },
            mail: MailConfig {
                transport,
                from: "devfast@archicode.codes".into(),
                host: "smtp.titan.email".into(),
                port: 465,
                password: password.map(str::to_string),
            },
            github: GithubConfig {
                client_id: None,
                oauth_base: "https://github.com".into(),
                api_base: "https://api.github.com".into(),
            },
        }
    }

    /// Second factors with a credential, or with an outbox, are both usable.
    #[test]
    fn a_usable_transport_starts() {
        usable(MailTransport::Smtp, Some("pw"))
            .check_mail_usable()
            .expect("smtp with a credential");
        usable(MailTransport::File("/tmp/outbox".into()), None)
            .check_mail_usable()
            .expect("file with a directory");
    }

    /// Second factors with no way to deliver refuse to start, rather than accepting code
    /// requests they will drop.
    #[test]
    fn an_unusable_transport_refuses_to_start() {
        assert!(usable(MailTransport::Smtp, None)
            .check_mail_usable()
            .is_err());
        assert!(usable(MailTransport::File(String::new()), None)
            .check_mail_usable()
            .is_err());
    }

    /// An unnamed sender refuses too. There is no default, because a compiled-in address makes
    /// every self-hosted deployment send as whoever built the binary.
    #[test]
    fn an_unnamed_sender_refuses_to_start() {
        let mut cfg = usable(MailTransport::File("/tmp/outbox".into()), None);
        cfg.mail.from = String::new();
        assert!(cfg.check_mail_usable().is_err());
    }

    /// With no proof secret there is no second factor, so no transport is required and the
    /// authority starts normally.
    #[test]
    fn without_second_factors_no_transport_is_needed() {
        let mut cfg = usable(MailTransport::Smtp, None);
        cfg.otp.proof_secret = None;
        assert!(!cfg.second_factors_enabled());
        cfg.check_mail_usable().expect("nothing to deliver");
    }
}
