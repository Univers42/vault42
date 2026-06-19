/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   authn.rs                                             :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Transport authentication. Each RPC carries `x-v42-ts`, `x-v42-pub` (hex Ed25519
//! public key), and `x-v42-sig` (hex Ed25519 signature over `ts\n<grpc-method>`). The
//! signature binds the operation and a fresh timestamp, so a captured header cannot be
//! replayed onto a different method or past the skew window. The verified public key
//! becomes the principal — proof of key possession, no password, no server secret.

use crate::principal::Principal;
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::{metadata::MetadataMap, Status};

/// Authenticate a request's metadata for `method`, returning the caller principal.
/// Any missing/malformed field or a bad signature is an `unauthenticated` status.
pub fn authn(meta: &MetadataMap, method: &str, skew_secs: i64) -> Result<Principal, Status> {
    let ts: i64 = meta_str(meta, "x-v42-ts")?
        .parse()
        .map_err(|_| Status::unauthenticated("bad timestamp"))?;
    check_skew(ts, skew_secs)?;
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&meta_hex(meta, "x-v42-pub", 32)?);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&meta_hex(meta, "x-v42-sig", 64)?);
    let challenge = format!("{ts}\n{method}");
    if !vault42_core::verify_request(&pubkey, challenge.as_bytes(), &sig) {
        return Err(Status::unauthenticated("bad request signature"));
    }
    Ok(Principal::from_pubkey(pubkey))
}

/// Read a string metadata value or fail unauthenticated.
fn meta_str(meta: &MetadataMap, key: &str) -> Result<String, Status> {
    meta.get(key)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| Status::unauthenticated("missing auth metadata"))
}

/// Read a hex metadata value and assert its decoded length.
fn meta_hex(meta: &MetadataMap, key: &str, len: usize) -> Result<Vec<u8>, Status> {
    let bytes =
        hex::decode(meta_str(meta, key)?).map_err(|_| Status::unauthenticated("bad hex"))?;
    if bytes.len() != len {
        return Err(Status::unauthenticated("bad field length"));
    }
    Ok(bytes)
}

/// Reject a timestamp outside the accepted skew window.
fn check_skew(ts: i64, skew_secs: i64) -> Result<(), Status> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if (now - ts).abs() > skew_secs {
        return Err(Status::unauthenticated("stale request"));
    }
    Ok(())
}
