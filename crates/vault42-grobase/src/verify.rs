/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   verify.rs                                            :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! API-key verification: resolve a cleartext grobase API key to a tenant + key id
//! via `POST /v1/keys/verify`. The server uses this (when a private grobase is
//! configured) to bind the caller to a grobase tenant and enable ABAC/audit; the
//! zero-knowledge identity itself comes from the caller's Ed25519 key, not this hop.

use crate::client::GrobaseClient;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// Request body for `/v1/keys/verify`.
#[derive(Serialize)]
struct VerifyKeyRequest<'a> {
    key: &'a str,
}

/// The verification result. `valid` is false (rather than an error) when grobase
/// returns 401, so the server maps it straight to an authentication denial.
#[derive(Debug, Deserialize)]
pub struct VerifiedKey {
    pub valid: bool,
    #[serde(default)]
    pub tenant_id: String,
    #[serde(default)]
    pub key_id: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub reason: String,
}

impl GrobaseClient {
    /// Verify `cleartext_key`. A 401 is normalized to `valid: false`; other non-2xx
    /// statuses surface as `Error::Status` (grobase unavailable / misconfigured).
    pub async fn verify_key(&self, cleartext_key: &str) -> Result<VerifiedKey> {
        let body = serde_json::to_vec(&VerifyKeyRequest { key: cleartext_key })
            .map_err(|_| Error::Decode)?;
        let resp = self.signed_post("/v1/keys/verify", &body).await?;
        let status = resp.status();
        if status.as_u16() == 401 {
            return Ok(VerifiedKey {
                valid: false,
                tenant_id: String::new(),
                key_id: String::new(),
                scopes: Vec::new(),
                reason: "unauthorized".into(),
            });
        }
        if !status.is_success() {
            return Err(Error::Status(status.as_u16()));
        }
        resp.json::<VerifiedKey>().await.map_err(|_| Error::Decode)
    }
}
