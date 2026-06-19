/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   serviceauth.rs                                       :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The `X-Service-Auth` HMAC signer, byte-compatible with grobase's serviceauth HMAC
//! mode. grobase signs `v1.<ts>.<hex>` where `hex = HMAC-SHA256(token, canonical)` and
//! `canonical = "<ts>\n<METHOD>\n<PATH>\n<sha256hex(body)>"` (method upper-cased). The
//! shared internal token never crosses the wire — only this per-request signature does.

use crate::error::{Error, Result};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Build the canonical string grobase signs over.
fn canonical(ts: i64, method: &str, path: &str, body: &[u8]) -> String {
    let body_hash = hex::encode(Sha256::digest(body));
    format!("{ts}\n{}\n{path}\n{body_hash}", method.to_uppercase())
}

/// Compute the `X-Service-Auth` header value for a request. The verifier (grobase)
/// recomputes the same canonical string and HMAC, so the signature binds method,
/// path, body, and timestamp (replay-bounded by the skew window).
pub fn service_auth_header(
    token: &[u8],
    ts: i64,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<String> {
    let mut mac = HmacSha256::new_from_slice(token).map_err(|_| Error::Key)?;
    mac.update(canonical(ts, method, path, body).as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());
    Ok(format!("v1.{ts}.{signature}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_has_versioned_format() {
        let header =
            service_auth_header(b"secret", 1_700_000_000, "post", "/v1/keys/verify", b"{}")
                .expect("sign");
        assert!(header.starts_with("v1.1700000000."));
        assert_eq!(header.matches('.').count(), 2);
    }

    #[test]
    fn deterministic_for_same_inputs() {
        let first = service_auth_header(b"t", 1, "GET", "/x", b"").expect("first");
        let second = service_auth_header(b"t", 1, "GET", "/x", b"").expect("second");
        assert_eq!(first, second);
    }

    #[test]
    fn body_change_changes_signature() {
        let a = service_auth_header(b"t", 1, "POST", "/x", b"a").expect("a");
        let b = service_auth_header(b"t", 1, "POST", "/x", b"b").expect("b");
        assert_ne!(a, b);
    }

    #[test]
    fn method_is_case_normalized() {
        let lower = service_auth_header(b"t", 1, "post", "/x", b"").expect("lower");
        let upper = service_auth_header(b"t", 1, "POST", "/x", b"").expect("upper");
        assert_eq!(lower, upper);
    }
}
