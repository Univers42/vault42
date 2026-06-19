/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   decide.rs                                            :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! ABAC authorization: ask grobase's policy engine whether a principal may perform
//! an op on a resource, via `POST /permissions/decide`. This is defense-in-depth on
//! top of the server's owner-scoping (you can only touch your own secrets); it adds
//! RBAC/TTL-grant decisions when a private grobase is wired. Off-path by default.

use crate::client::GrobaseClient;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// The principal/resource/op tuple to authorize.
pub struct DecideInput<'a> {
    pub user_id: &'a str,
    pub tenant_id: &'a str,
    pub resource_type: &'a str,
    pub resource_name: &'a str,
    pub op: &'a str,
}

/// The decision returned by the PDP.
#[derive(Debug, Deserialize)]
pub struct Decision {
    pub allow: bool,
    #[serde(default)]
    pub reason: String,
}

#[derive(Serialize)]
struct DecideUser<'a> {
    id: &'a str,
}

#[derive(Serialize)]
struct DecideBody<'a> {
    user: DecideUser<'a>,
    tenant_id: &'a str,
    resource_type: &'a str,
    resource_name: &'a str,
    op: &'a str,
}

impl GrobaseClient {
    /// Authorize `input` against grobase's ABAC PDP. A non-2xx status surfaces as
    /// `Error::Status`; the caller decides whether to fail open or closed.
    pub async fn decide(&self, input: &DecideInput<'_>) -> Result<Decision> {
        let body = serde_json::to_vec(&DecideBody {
            user: DecideUser { id: input.user_id },
            tenant_id: input.tenant_id,
            resource_type: input.resource_type,
            resource_name: input.resource_name,
            op: input.op,
        })
        .map_err(|_| Error::Decode)?;
        let resp = self.signed_post("/permissions/decide", &body).await?;
        if !resp.status().is_success() {
            return Err(Error::Status(resp.status().as_u16()));
        }
        resp.json::<Decision>().await.map_err(|_| Error::Decode)
    }
}
