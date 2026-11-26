/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   verbs_manage.rs                                      :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/11/25 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! `ls`, `rm`, and `whoami`. Listing and removal are owner-scoped by the server to the
//! calling identity; `whoami` is purely local (it prints this identity's principal and
//! shareable address) plus a server round-trip that confirms the identity is recognized.
//!
//! The server only knows handles, so `ls` reads the sealed index for the labels the user
//! typed. A handle with no label keeps its handle as the label: a secret nobody can name is
//! still a secret, and hiding it would be the worse failure.

use crate::address;
use crate::client::Session;
use crate::handles;
use tonic::Request;
use vault42_proto::vault::v1::{LsRequest, RmRequest, WhoamiRequest};

impl Session {
    /// List the caller's secrets under `prefix`, by the names they were given.
    pub async fn cmd_ls(&mut self, prefix: &str) -> anyhow::Result<()> {
        let mut request = Request::new(LsRequest {
            prefix: String::new(),
        });
        self.authorize(&mut request, "/vault.v1.Vault/Ls")?;
        let listed = self.client.ls(request).await?.into_inner().secrets;
        let index = self.load_index().await.unwrap_or_default();
        let mut rows: Vec<(String, u64, i64)> = listed
            .into_iter()
            .filter(|secret| !handles::is_internal(&secret.path))
            .map(|secret| {
                (
                    index
                        .label_of(&secret.path)
                        .unwrap_or(&secret.path)
                        .to_string(),
                    secret.version,
                    secret.updated_at,
                )
            })
            .filter(|(label, _, _)| label.starts_with(prefix))
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        for (label, version, updated_at) in rows {
            println!("{label}\tv{version}\t{updated_at}");
        }
        Ok(())
    }

    /// Remove every version of `path`: the opaque handle, and any copy an older client left
    /// under the plaintext name.
    pub async fn cmd_rm(&mut self, path: &str) -> anyhow::Result<()> {
        if handles::is_internal(path) {
            anyhow::bail!(
                "this is vault42's own record (a project tree, upload manifest or the name \
                 index) — removing it loses what it holds"
            );
        }
        let wire = self.wire_path(path);
        let mut targets = vec![wire.clone()];
        if wire != path {
            targets.push(path.to_string());
        }
        let mut removed = false;
        for target in targets {
            let mut request = Request::new(RmRequest {
                path: target.clone(),
                version: 0,
            });
            self.authorize(&mut request, "/vault.v1.Vault/Rm")?;
            if self.client.rm(request).await?.into_inner().tombstoned {
                // The rows are gone, so the next write legitimately restarts at revision 1.
                self.release_handle(&target);
                removed = true;
            }
        }
        if handles::is_secret_handle(&wire) {
            self.forget(&wire).await;
        }
        println!("{}", if removed { "removed" } else { "not found" });
        Ok(())
    }

    /// Print this identity's principal and shareable address.
    pub async fn cmd_whoami(&mut self) -> anyhow::Result<()> {
        let mut request = Request::new(WhoamiRequest {});
        self.authorize(&mut request, "/vault.v1.Vault/Whoami")?;
        let principal = self.client.whoami(request).await?.into_inner().principal;
        println!("principal: {principal}");
        println!("address:   {}", address::encode(&self.identity));
        Ok(())
    }
}
