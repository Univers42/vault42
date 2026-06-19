/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   audit.rs                                             :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Tamper-evident audit: append a vault42 operation to grobase's hash-chained audit
//! log via `POST /v1/audit/tenants/{id}/events`. grobase stamps the sequence,
//! timestamp, and chain hash; the entry cannot later be altered or deleted without
//! breaking the chain. Used when a private grobase is configured (else the server
//! keeps a local chain). Only non-secret operation metadata is sent — never payload.

use crate::client::GrobaseClient;
use crate::error::{Error, Result};
use serde::Serialize;

/// One audit entry: who did what to which target. No secret material — `target` is a
/// secret path/id, never a key value or plaintext.
#[derive(Serialize)]
pub struct AuditEvent<'a> {
    pub actor: &'a str,
    pub action: &'a str,
    pub target: &'a str,
}

impl GrobaseClient {
    /// Append `event` to tenant `tenant_id`'s audit chain. A non-2xx status surfaces
    /// as `Error::Status`.
    pub async fn audit_append(&self, tenant_id: &str, event: &AuditEvent<'_>) -> Result<()> {
        let body = serde_json::to_vec(event).map_err(|_| Error::Decode)?;
        let path = format!("/v1/audit/tenants/{tenant_id}/events");
        let resp = self.signed_post(&path, &body).await?;
        if !resp.status().is_success() {
            return Err(Error::Status(resp.status().as_u16()));
        }
        Ok(())
    }
}
