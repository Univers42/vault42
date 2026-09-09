/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   password.rs                                          :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Account password hashing with Argon2id.
//!
//! Parameters are set explicitly rather than taken from `Argon2::default()` so a
//! dependency bump cannot silently change the cost of every stored hash.
//!
//! These are deliberately lighter than `vault42-core`'s keystore KDF (64 MiB, 3 passes).
//! The keystore runs once on a user's own machine, where 64 MiB is free; this runs
//! server-side on a 256 MB scale-to-zero VM, where one login per concurrent request at
//! 64 MiB is a memory-exhaustion vector. 19 MiB with 2 passes is the OWASP Argon2id
//! recommendation and keeps offline guessing expensive without handing anyone a cheap
//! denial of service.

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

/// Memory cost in KiB.
const M_COST: u32 = 19_456;

/// Number of passes.
const T_COST: u32 = 2;

/// Degree of parallelism.
const P_COST: u32 = 1;

/// Build the configured hasher.
fn hasher() -> anyhow::Result<Argon2<'static>> {
    let params = Params::new(M_COST, T_COST, P_COST, None)
        .map_err(|e| anyhow::anyhow!("argon2 params: {e}"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Hash `password` into a PHC string with a fresh random salt.
pub fn hash(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let phc = hasher()?
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 hash: {e}"))?;
    Ok(phc.to_string())
}

/// True when `password` matches the PHC string `stored`.
///
/// Returns false for a malformed `stored` rather than erroring, so a corrupted row
/// denies access instead of leaking a parse failure to the caller.
pub fn verify(password: &str, stored: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Do the same Argon2id work a real verification costs, then fail.
///
/// Called when no account exists for the submitted email, so that path takes as long as
/// a wrong-password path and response time does not reveal whether an email is
/// registered. It hashes rather than verifying against a fixed dummy PHC string on
/// purpose: a hardcoded dummy that failed to parse would return early, doing no work at
/// all, and the defence would be silently absent.
pub fn verify_absent(password: &str) -> bool {
    let _ = hash(password);
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hash_verifies_only_against_its_own_password() {
        let phc = hash("correct horse battery").unwrap();
        assert!(verify("correct horse battery", &phc));
        assert!(!verify("Correct horse battery", &phc));
        assert!(!verify("", &phc));
    }

    #[test]
    fn the_same_password_hashes_differently_each_time() {
        let a = hash("correct horse battery").unwrap();
        let b = hash("correct horse battery").unwrap();
        assert_ne!(a, b, "salt must be fresh per hash");
        assert!(verify("correct horse battery", &a));
        assert!(verify("correct horse battery", &b));
    }

    #[test]
    fn the_declared_parameters_land_in_the_phc_string() {
        let phc = hash("correct horse battery").unwrap();
        assert!(
            phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "got {phc}"
        );
    }

    #[test]
    fn a_malformed_stored_hash_denies_rather_than_panics() {
        assert!(!verify("anything", "not-a-phc-string"));
        assert!(!verify("anything", ""));
    }

    #[test]
    fn the_absent_account_path_always_fails_and_does_real_work() {
        assert!(!verify_absent("anything at all"));
    }

    #[test]
    fn absent_and_wrong_password_paths_cost_the_same_order_of_time() {
        let phc = hash("correct horse battery").unwrap();
        let wrong = std::time::Instant::now();
        assert!(!verify("wrong password entirely", &phc));
        let wrong = wrong.elapsed();
        let absent = std::time::Instant::now();
        assert!(!verify_absent("wrong password entirely"));
        let absent = absent.elapsed();
        let (lo, hi) = if absent < wrong {
            (absent, wrong)
        } else {
            (wrong, absent)
        };
        assert!(
            hi < lo * 8 + std::time::Duration::from_millis(20),
            "absent path {absent:?} must not be trivially cheaper than wrong-password {wrong:?}"
        );
    }
}
