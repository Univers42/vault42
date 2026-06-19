/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   ops_read.rs                                          :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Read operations (get / ls / whoami). All are owner-scoped: a principal sees only
//! its own secrets. `get` returns the opaque envelope plus the author public-key
//! sidecar so the caller can verify a shared secret's authorship before decrypting.

use crate::ops_write::map_store;
use crate::principal::Principal;
use crate::svc::VaultSvc;
use tonic::Status;
use vault42_proto::vault::v1::{GetResponse, LsResponse, SecretMeta, WhoamiResponse};

impl VaultSvc {
    /// Fetch one secret version (`0` ⇒ latest) for the caller.
    pub(crate) async fn op_get(
        &self,
        caller: &Principal,
        path: &str,
        version: u64,
    ) -> Result<GetResponse, Status> {
        let row = self
            .store
            .get_secret(&caller.id, path, version as i64)
            .await
            .map_err(map_store)?
            .ok_or_else(|| Status::not_found("no such secret"))?;
        Ok(GetResponse {
            envelope: row.envelope,
            version: row.version as u64,
            author_pubkey: row.author_pubkey,
        })
    }

    /// List the caller's secrets under `prefix`.
    pub(crate) async fn op_ls(
        &self,
        caller: &Principal,
        prefix: &str,
    ) -> Result<LsResponse, Status> {
        let rows = self
            .store
            .list_secrets(&caller.id, prefix)
            .await
            .map_err(map_store)?;
        let secrets = rows.into_iter().map(to_meta).collect();
        Ok(LsResponse { secrets })
    }

    /// Report the caller's own identity.
    pub(crate) fn op_whoami(&self, caller: &Principal) -> WhoamiResponse {
        WhoamiResponse {
            principal: caller.id.clone(),
            roles: vec!["owner".to_string()],
            aal: 1,
        }
    }
}

/// Project a `(path, version, updated_at)` row into a `SecretMeta`.
fn to_meta(row: (String, i64, i64)) -> SecretMeta {
    // ponytail: recipient count not surfaced in ls — parse the envelope if a UI needs it
    SecretMeta {
        path: row.0,
        version: row.1 as u64,
        updated_at: row.2,
        recipients: 0,
    }
}
