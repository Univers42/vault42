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

    #[test]
    fn password_length_is_enforced_at_both_ends() {
        assert!(check_password("correct horse battery").is_ok());
        assert!(check_password("short").is_err());
        assert!(check_password(&"a".repeat(MAX_PASSWORD_LEN + 1)).is_err());
        assert!(check_password(&"a".repeat(MIN_PASSWORD_LEN)).is_ok());
    }
}
