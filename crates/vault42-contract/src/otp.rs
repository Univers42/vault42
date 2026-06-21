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

//! Server-side verification of a grobase email-OTP proof before a contract is issued.
//! The proof is an HS256 JWT minted by grobase `/v1/auth/otp/verify` with the shared
//! `GOTRUE_JWT_SECRET` (claims `otp`/`aud=otp-proof`/`exp`). We recompute the HMAC and
//! check the audience, the bound email, and expiry — so the OTP is a REAL login gate
//! enforced by the authority, not a client-only step.

use crate::signing::now_unix;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

const SKEW_SECS: i64 = 30;

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
    if claims.get("aud").and_then(Value::as_str) != Some("otp-proof") {
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
