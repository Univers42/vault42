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
//! becomes the principal — proof of key possession, no password, no server secret. When
//! a contract authority is configured (`contract_pub`), the caller must ALSO present a
//! valid `x-v42-contract` bound to this key (managed multi-tenancy); the tenant comes
//! from the contract. The contract is verified OFFLINE — no call back to the authority.

use crate::principal::Principal;
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::{metadata::MetadataMap, Status};

/// Authenticate a request's metadata for `method`, returning the caller principal.
/// Any missing/malformed field, a bad signature, or (when required) a missing/invalid
/// contract is an authentication denial.
pub fn authn(
    meta: &MetadataMap,
    method: &str,
    skew_secs: i64,
    contract_pub: Option<&[u8; 32]>,
) -> Result<Principal, Status> {
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
    match contract_pub {
        Some(authority) => Ok(
            Principal::from_pubkey(pubkey).with_tenant(bind_contract(meta, authority, &pubkey)?)
        ),
        None => Ok(Principal::from_pubkey(pubkey)),
    }
}

/// Verify the `x-v42-contract` token against the authority key and bind it to `pubkey`,
/// returning the contract's tenant. The contract must be signed by the authority, unexpired,
/// and issued for this exact key's fingerprint.
fn bind_contract(
    meta: &MetadataMap,
    authority: &[u8; 32],
    pubkey: &[u8; 32],
) -> Result<String, Status> {
    let token = meta_str(meta, "x-v42-contract")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let contract = vault42_core::verify_contract(authority, &token, now)
        .map_err(|_| Status::unauthenticated("invalid or expired contract"))?;
    if contract.author_fp != vault42_core::fingerprint(pubkey) {
        return Err(Status::permission_denied("contract not bound to this key"));
    }
    Ok(contract.tenant)
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
