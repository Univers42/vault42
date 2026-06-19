/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   verbs_share.rs                                       :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! `share` — grant another identity read access by re-sealing the secret for their
//! address. The sharer fetches and locally decrypts their own copy, then seals a fresh
//! envelope addressed to the friend's X25519 key under the friend's owner space, at a
//! `shared/<sharer>/<path>` key so it can never collide with the friend's own secrets.
//! The friend reads it there with their own key. Re-sealing (not key-sharing) keeps it
//! zero-knowledge.

use crate::client::{attach_auth, Session};
use crate::{address, compose};
use tonic::Request;
use vault42_proto::vault::v1::ShareRequest;

impl Session {
    /// Re-seal `path` for the identity at `to`, depositing it at `shared/<self>/<path>`
    /// in the recipient's owner space.
    pub async fn cmd_share(&mut self, path: &str, to: &str) -> anyhow::Result<()> {
        let (friend_principal, friend_enc) = address::decode(to)?;
        let plaintext = self.fetch_plaintext(path).await?;
        let shared_path = format!("shared/{}/{}", self.principal, path);
        let envelope = compose::shared_envelope(
            &self.identity,
            &friend_principal,
            &shared_path,
            friend_enc,
            plaintext.as_slice(),
        )?;
        let mut request = Request::new(ShareRequest {
            path: shared_path.clone(),
            envelope,
            expected_prev_rev: 0,
        });
        attach_auth(&mut request, &self.identity, "/vault.v1.Vault/Share")?;
        self.client.share(request).await?;
        println!("shared {path} to {} at {shared_path}", address::short(to));
        Ok(())
    }
}
