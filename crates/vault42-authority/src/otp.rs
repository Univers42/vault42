/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   otp.rs                                               :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Minting and checking the six-digit code itself.
//!
//! The proof format lives in `vault42_contract::otp`, which mints and verifies it, so the two
//! services cannot disagree about it. What lives here is everything about the code a person
//! actually types: generating it without modulo bias, hashing it so the database never holds it,
//! and comparing it without leaking how much of a guess was right.
//!
//! Six digits is a million possibilities, which is only safe because the number of guesses is
//! bounded. A code dies on its fifth wrong attempt, is single-use, expires, and is bound to the
//! address it was mailed to. Any one of those missing turns the second factor into a formality.

use crate::error::{Error, Result};
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// How many wrong guesses a code survives.
///
/// Five, against a million possibilities, keeps online guessing at roughly one chance in two
/// hundred thousand per code — while leaving room for a genuine typo or two.
pub const MAX_ATTEMPTS: i64 = 5;

/// Domain separation, so a stored digest means nothing anywhere else.
const DOMAIN: &[u8] = b"vault42/otp/v1";

/// Generate a uniform six-digit code.
///
/// Rejection sampling rather than `% 1_000_000`: the modulo of a `u32` is biased towards low
/// values, which would make some codes measurably likelier than others and shrink the search
/// space for anybody guessing. The code lives in a `Zeroizing` buffer because it is a
/// credential until it is delivered.
pub fn generate_code() -> Zeroizing<String> {
    let limit = 1_000_000u32;
    let ceiling = u32::MAX - (u32::MAX % limit) - 1;
    loop {
        let drawn = OsRng.next_u32();
        if drawn <= ceiling {
            return Zeroizing::new(format!("{:06}", drawn % limit));
        }
    }
}

/// Hash a code for storage, bound to the address it was sent to.
///
/// The database holds only this. Binding the address in means a digest lifted from one row can
/// never be replayed as another address's code, even though both are six digits.
pub fn hash_code(email: &str, code: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN);
    hasher.update(email.to_lowercase().as_bytes());
    hasher.update(b"\n");
    hasher.update(code.as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// Whether a submitted code matches a stored digest, compared in constant time.
///
/// Both sides are hashes of equal length, so this leaks neither the code nor how many leading
/// digits were right.
pub fn code_matches(email: &str, submitted: &str, stored_hash: &str) -> bool {
    let candidate = hash_code(email, submitted);
    bool::from(candidate.as_bytes().ct_eq(stored_hash.as_bytes()))
}

/// Refuse a submission that is not six digits, before any database work.
///
/// Cheap, and it keeps a caller from spending one of the five attempts on something that could
/// never have been a code.
pub fn check_shape(code: &str) -> Result<()> {
    let valid = code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit());
    if valid {
        return Ok(());
    }
    Err(Error::BadRequest("a code is six digits".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every generated code is exactly six digits, and the generator does not get stuck.
    #[test]
    fn a_code_is_always_six_digits() {
        for _ in 0..500 {
            let code = generate_code();
            assert_eq!(code.len(), 6, "{}", code.as_str());
            assert!(
                code.bytes().all(|b| b.is_ascii_digit()),
                "{}",
                code.as_str()
            );
        }
    }

    /// Codes are not all the same value, and low values are reachable — a sanity check that the
    /// rejection loop has not collapsed the range.
    #[test]
    fn generated_codes_vary() {
        let drawn: std::collections::HashSet<String> =
            (0..200).map(|_| generate_code().to_string()).collect();
        assert!(drawn.len() > 150, "expected variety, got {}", drawn.len());
    }

    /// A digest is bound to its address: the same code hashes differently elsewhere, so a stolen
    /// digest cannot be replayed as another account's code.
    #[test]
    fn a_digest_is_bound_to_its_address() {
        let mine = hash_code("dev@archicode.codes", "123456");
        assert_ne!(mine, hash_code("someone@else.test", "123456"));
        assert_ne!(mine, hash_code("dev@archicode.codes", "123457"));
        assert_eq!(
            mine,
            hash_code("Dev@Archicode.Codes", "123456"),
            "the address is compared case-insensitively, as it is stored"
        );
    }

    /// Matching accepts the right code and rejects a near miss.
    #[test]
    fn matching_accepts_only_the_right_code() {
        let stored = hash_code("dev@archicode.codes", "123456");
        assert!(code_matches("dev@archicode.codes", "123456", &stored));
        assert!(!code_matches("dev@archicode.codes", "123457", &stored));
        assert!(!code_matches("other@x.test", "123456", &stored));
        assert!(!code_matches("dev@archicode.codes", "", &stored));
    }

    /// Anything that is not six digits is refused before it can spend an attempt.
    #[test]
    fn only_six_digits_is_a_candidate() {
        check_shape("000000").expect("six digits");
        for junk in ["12345", "1234567", "12345a", "", "  1234", "١٢٣٤٥٦"] {
            assert!(check_shape(junk).is_err(), "{junk:?} must be refused");
        }
    }
}
