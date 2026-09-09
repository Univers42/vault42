/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   otp.rs                                                :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/21 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/21 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The email one-time-code proof: both ends of it, in one file.
//!
//! The proof is an HS256 JWT with claims `otp` (the bound address), `aud = otp-proof` and `exp`,
//! signed with the shared `VAULT42_OTP_PROOF_SECRET`. `vault42-authority` mints it when somebody
//! enters a code it mailed them; this crate verifies it before issuing a contract. So the code is
//! a real login gate enforced server-side, not a client-only step.
//!
//! Minting lives beside verification on purpose. It used to be grobase that minted these, and the
//! format was written down in two codebases; a round-trip test in one file is what stops the two
//! directions drifting.
//!
//! One note for a reader expecting the usual JWT weakness: `alg` in the header is never trusted,
//! because verification never dispatches on it. The signature is always recomputed as
//! HMAC-SHA256 over the received `header.payload`, so a proof claiming `alg: none` or `alg: RS256`
//! simply fails the comparison. The header is signed input, not instructions.

use crate::signing::now_unix;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

const SKEW_SECS: i64 = 30;

/// The audience that separates a login proof from any other token signed with this secret.
const AUDIENCE: &str = "otp-proof";

/// Mint a proof binding `email`, expiring at `expires_at`.
///
/// The address is lowercased so a proof minted for `Dev@X` verifies for `dev@x`, matching how
/// `verify_claims` compares. Nothing secret is in the claims: the proof says a code for this
/// address was entered correctly before `exp`, and the signature is what makes that credible.
pub fn mint_otp_proof(email: &str, secret: &[u8], expires_at: i64) -> Result<String, String> {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let claims = serde_json::json!({
        "otp": email.to_lowercase(),
        "aud": AUDIENCE,
        "exp": expires_at,
    })
    .to_string();
    let payload = URL_SAFE_NO_PAD.encode(claims.as_bytes());
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| "hmac key".to_string())?;
    mac.update(format!("{header}.{payload}").as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    Ok(format!("{header}.{payload}.{sig}"))
}

/// Verify `proof` (HS256) for `email` under `secret`; Err(reason) → the caller maps 401.
pub fn verify_otp_proof(proof: &str, email: &str, secret: &[u8]) -> Result<(), String> {
    let mut parts = proof.split('.');
    let (header, payload, sig) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err("malformed proof".into()),
    };
    verify_sig(secret, header, payload, sig)?;
    verify_claims(payload, email)
}

/// Recompute HMAC-SHA256 over `header.payload` and constant-time compare to `sig`.
fn verify_sig(secret: &[u8], header: &str, payload: &str, sig: &str) -> Result<(), String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| "hmac key".to_string())?;
    mac.update(format!("{header}.{payload}").as_bytes());
    let expected = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    // sec: length-then-constant-time signature comparison (no early-exit byte leak)
    if expected.len() != sig.len() || !ct_eq(expected.as_bytes(), sig.as_bytes()) {
        return Err("bad signature".into());
    }
    Ok(())
}

/// Check the proof's claims: `aud == otp-proof`, `otp == lower(email)`, and `exp`.
fn verify_claims(payload: &str, email: &str) -> Result<(), String> {
    let raw = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| "bad payload".to_string())?;
    let claims: Value = serde_json::from_slice(&raw).map_err(|_| "bad claims".to_string())?;
    if claims.get("aud").and_then(Value::as_str) != Some(AUDIENCE) {
        return Err("wrong audience".into());
    }
    if claims.get("otp").and_then(Value::as_str) != Some(email.to_lowercase().as_str()) {
        return Err("email mismatch".into());
    }
    let exp = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or("missing exp")?;
    if exp < now_unix() - SKEW_SECS {
        return Err("proof expired".into());
    }
    Ok(())
}

/// Constant-time byte comparison for equal-length inputs.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A proof minted by the shipped minter round-trips through the shipped verifier. This is
    /// the assertion that keeps the two directions from drifting apart.
    #[test]
    fn what_the_minter_produces_the_verifier_accepts() {
        let secret = b"shared-secret";
        let proof = mint_otp_proof("Dev@Archicode.Codes", secret, now_unix() + 300).expect("mint");
        verify_otp_proof(&proof, "dev@archicode.codes", secret).expect("round trip");
        verify_otp_proof(&proof, "Dev@Archicode.Codes", secret).expect("case insensitive");
        assert!(
            verify_otp_proof(&proof, "someone@else.test", secret).is_err(),
            "a proof is bound to one address"
        );
    }

    /// A header claiming a different algorithm changes nothing, because verification never
    /// dispatches on `alg` — it always recomputes HMAC-SHA256 over the received header.
    #[test]
    fn a_forged_alg_header_does_not_help() {
        let secret = b"shared-secret";
        let real = mint_otp_proof("a@x.test", secret, now_unix() + 300).expect("mint");
        let payload = real.split('.').nth(1).expect("payload");
        let sig = real.split('.').nth(2).expect("sig");
        let none_alg = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        assert!(
            verify_otp_proof(&format!("{none_alg}.{payload}.{sig}"), "a@x.test", secret).is_err(),
            "swapping the header invalidates the signature over it"
        );
        assert!(
            verify_otp_proof(&format!("{none_alg}.{payload}."), "a@x.test", secret).is_err(),
            "and an empty signature is not accepted for any alg"
        );
    }

    fn mint(secret: &[u8], otp: &str, aud: &str, exp: i64) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let claims = serde_json::json!({"otp": otp, "aud": aud, "exp": exp}).to_string();
        let payload = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(format!("{header}.{payload}").as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{header}.{payload}.{sig}")
    }

    #[test]
    fn valid_proof_accepts() {
        let s = b"shared-secret";
        let p = mint(s, "user@x.test", "otp-proof", now_unix() + 300);
        assert!(verify_otp_proof(&p, "User@X.test", s).is_ok());
    }

    #[test]
    fn wrong_secret_email_aud_expiry_reject() {
        let s = b"shared-secret";
        assert!(verify_otp_proof(
            &mint(s, "a@x.test", "otp-proof", now_unix() + 300),
            "a@x.test",
            b"other"
        )
        .is_err());
        assert!(verify_otp_proof(
            &mint(s, "a@x.test", "otp-proof", now_unix() + 300),
            "b@x.test",
            s
        )
        .is_err());
        assert!(verify_otp_proof(
            &mint(s, "a@x.test", "wrong-aud", now_unix() + 300),
            "a@x.test",
            s
        )
        .is_err());
        assert!(verify_otp_proof(
            &mint(s, "a@x.test", "otp-proof", now_unix() - 600),
            "a@x.test",
            s
        )
        .is_err());
        assert!(verify_otp_proof("not.a.jwt.extra", "a@x.test", s).is_err());
    }
}
