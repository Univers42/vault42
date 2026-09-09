/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   validate.rs                                          :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Input validation at the trust boundary.
//!
//! Every value here reaches a database row, a signed contract, or an email transport, so
//! it is checked before it is stored rather than sanitized afterwards. Tenant names and
//! author public keys reuse `vault42_contract::validate` so the rules cannot drift
//! between the two services.

/// The shortest password accepted. Argon2id makes offline guessing expensive, but a
/// short password is guessable online, so length is enforced independently.
const MIN_PASSWORD_LEN: usize = 12;

/// An upper bound so a huge body cannot turn one signup into a long Argon2id run.
const MAX_PASSWORD_LEN: usize = 1024;

/// The longest address an SMTP implementation must accept (RFC 5321).
const MAX_EMAIL_LEN: usize = 254;

/// Normalize an email for storage and comparison, or say why it is unacceptable.
///
/// Deliberately not a full RFC 5322 parser: it rejects what would break a database
/// unique constraint or an SMTP envelope, and lowercases so one address cannot be
/// registered twice in different cases.
pub fn normalize_email(email: &str) -> Result<String, String> {
    let trimmed = email.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_EMAIL_LEN {
        return Err(format!("email must be 1..={MAX_EMAIL_LEN} characters"));
    }
    if trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("email must not contain whitespace or control characters".into());
    }
    let (local, domain) = trimmed
        .split_once('@')
        .ok_or_else(|| "email must contain '@'".to_string())?;
    if local.is_empty() || domain.is_empty() || domain.contains('@') || !domain.contains('.') {
        return Err("email must look like local@domain.tld".into());
    }
    Ok(trimmed.to_lowercase())
}

/// Accept a password of a credible length, or say why not.
///
/// The password itself is never logged or echoed, so the error names only the rule.
pub fn check_password(password: &str) -> Result<(), String> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        ));
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err(format!(
            "password must be at most {MAX_PASSWORD_LEN} characters"
        ));
    }
    Ok(())
}

/// Refuse a value marked secret that is not actually a sealed envelope.
///
/// `is_secret` is a promise, not a label. In a vault whose whole claim is that the server cannot
/// read what it stores, a flag by that name on a value the server CAN read is the one piece of
/// the product an operator would trust without checking. Storing `hunter2` and marking it secret
/// used to succeed and hand the plaintext straight back.
///
/// So the flag is enforced rather than renamed: a secret value must be base64 of a `vault42-core`
/// envelope. Parsing the envelope proves it was sealed without opening it — the authority holds
/// no key that could — and the value stays opaque exactly as before. The alternative was to
/// rename the field to something that promises nothing, which would leave the product with no
/// way to say "this is sealed" at all.
pub fn check_sealed(value: &str) -> Result<(), String> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value)
        .map_err(|_| "a secret value must be base64 of a sealed envelope".to_string())?;
    vault42_core::Envelope::from_bytes(&bytes)
        .map(|_| ())
        .map_err(|_| {
            "a secret value must be a sealed envelope; seal it client-side before storing it"
                .to_string()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_is_normalized_and_bounded() {
        assert_eq!(
            normalize_email("  Dev@Archicode.Codes ").unwrap(),
            "dev@archicode.codes"
        );
        assert!(normalize_email("no-at-sign").is_err());
        assert!(normalize_email("@domain.tld").is_err());
        assert!(normalize_email("local@").is_err());
        assert!(normalize_email("local@nodot").is_err());
        assert!(normalize_email("a@b.c\u{7f}").is_err());
        assert!(normalize_email("two@at@signs.tld").is_err());
        assert!(normalize_email(&format!("{}@x.tld", "a".repeat(300))).is_err());
    }

    /// A value marked secret must be a real sealed envelope. Plaintext, base64 of plaintext,
    /// and base64 of junk are all refused; only bytes that parse as an envelope are accepted.
    #[test]
    fn a_secret_value_must_actually_be_sealed() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        for plainly_not in ["hunter2", "", "not base64!!"] {
            assert!(
                check_sealed(plainly_not).is_err(),
                "{plainly_not:?} must not pass as a sealed value"
            );
        }
        assert!(
            check_sealed(&STANDARD.encode("hunter2")).is_err(),
            "base64 of plaintext is still plaintext"
        );
        let sealed = STANDARD.encode(sealed_envelope_bytes());
        check_sealed(&sealed).expect("a genuinely sealed envelope is accepted");
    }

    /// Seal a throwaway payload to a throwaway scope key, exactly as a client would, and return
    /// the opaque wire bytes.
    fn sealed_envelope_bytes() -> Vec<u8> {
        let (keyset, _secret) = vault42_core::generate_keyset([5u8; 16], 1);
        let author = vault42_core::Identity::generate();
        let recipients = vault42_core::scope_recipients(&keyset, None);
        vault42_core::seal(
            b"DATABASE_URL=postgres://prod",
            vault42_core::Metadata {
                version: 2,
                secret_id: "var".into(),
                tenant: "self".into(),
                owner: "scope:env".into(),
                rev: 1,
                content_type: "env".into(),
                recovery_optin: false,
                project_id: "p".into(),
                relative_path: String::new(),
                kind: vault42_core::Kind::Generic,
                mode: vault42_core::DEFAULT_MODE,
            },
            &recipients,
            author.signing_key(),
        )
        .expect("seal")
        .to_bytes()
        .expect("encode")
    }

    #[test]
    fn password_length_is_enforced_at_both_ends() {
        assert!(check_password("correct horse battery").is_ok());
        assert!(check_password("short").is_err());
        assert!(check_password(&"a".repeat(MAX_PASSWORD_LEN + 1)).is_err());
        assert!(check_password(&"a".repeat(MIN_PASSWORD_LEN)).is_ok());
    }
}
