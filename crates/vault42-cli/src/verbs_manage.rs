/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   verbs_manage.rs                                      :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! `ls`, `rm`, and `whoami`. Listing and removal are owner-scoped by the server to the
//! calling identity; `whoami` is purely local (it prints this identity's principal and
//! shareable address) plus a server round-trip that confirms the identity is recognized.

use crate::address;
use crate::client::{attach_auth, Session};
use tonic::Request;
use vault42_proto::vault::v1::{LsRequest, RmRequest, WhoamiRequest};

impl Session {
    /// List the caller's secrets under `prefix`.
    pub async fn cmd_ls(&mut self, prefix: &str) -> anyhow::Result<()> {
        let mut request = Request::new(LsRequest {
            prefix: prefix.to_string(),
        });
        attach_auth(&mut request, &self.identity, "/vault.v1.Vault/Ls")?;
        for secret in self.client.ls(request).await?.into_inner().secrets {
            println!(
                "{}\tv{}\t{}",
                secret.path, secret.version, secret.updated_at
            );
        }
        Ok(())
    }

    /// Remove every version of `path`.
    pub async fn cmd_rm(&mut self, path: &str) -> anyhow::Result<()> {
        let mut request = Request::new(RmRequest {
            path: path.to_string(),
            version: 0,
        });
        attach_auth(&mut request, &self.identity, "/vault.v1.Vault/Rm")?;
        let tombstoned = self.client.rm(request).await?.into_inner().tombstoned;
        println!("{}", if tombstoned { "removed" } else { "not found" });
        Ok(())
    }

    /// Print this identity's principal and shareable address.
    pub async fn cmd_whoami(&mut self) -> anyhow::Result<()> {
        let mut request = Request::new(WhoamiRequest {});
        attach_auth(&mut request, &self.identity, "/vault.v1.Vault/Whoami")?;
        let principal = self.client.whoami(request).await?.into_inner().principal;
        println!("principal: {principal}");
        println!("address:   {}", address::encode(&self.identity));
        Ok(())
    }
}
