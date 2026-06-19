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
//! envelope addressed to the friend's X25519 key under the friend's owner space; the
//! server stores the opaque result. Re-sealing (not key-sharing) keeps it zero-knowledge.

use crate::client::{attach_auth, Session};
use crate::{address, derive};
use tonic::Request;
use vault42_core::{seal, Metadata, Recipients};
use vault42_proto::vault::v1::ShareRequest;

impl Session {
    /// Re-seal `path` for the identity at `to` and store it in their owner space.
    pub async fn cmd_share(&mut self, path: &str, to: &str) -> anyhow::Result<()> {
        let (friend_principal, friend_enc) = address::decode(to)?;
        let plaintext = self.fetch_plaintext(path).await?;
        let metadata = Metadata {
            version: 1,
            secret_id: derive::secret_id(&friend_principal, path),
            tenant: "self".to_string(),
            owner: friend_principal,
            rev: 1,
            content_type: "opaque".to_string(),
            recovery_optin: false,
        };
        let recipients = Recipients {
            users: &[friend_enc, self.identity.encryption_public()],
            recovery: None,
        };
        let envelope = seal(
            plaintext.as_slice(),
            metadata,
            &recipients,
            self.identity.signing_key(),
        )?;
        let mut request = Request::new(ShareRequest {
            path: path.to_string(),
            envelope: envelope.to_bytes()?,
            expected_prev_rev: 0,
        });
        attach_auth(&mut request, &self.identity, "/vault.v1.Vault/Share")?;
        self.client.share(request).await?;
        println!("shared {path} to {}", address::short(to));
        Ok(())
    }
}
