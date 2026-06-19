/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   verbs_secret.rs                                      :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! `set` and `get`. `set` seals the plaintext locally for the caller and pushes the
//! opaque envelope with optimistic concurrency (expected_prev = current head). `get`
//! fetches the envelope and decrypts it locally — the server sees neither plaintext
//! nor a DEK at any point.

use crate::client::{attach_auth, Session};
use crate::{decrypt, derive};
use tonic::{Code, Request};
use vault42_core::{seal, Metadata, Recipients};
use vault42_proto::vault::v1::{GetRequest, PushRequest};
use zeroize::Zeroizing;

impl Session {
    /// Seal `plaintext` for this identity and push it at the next version.
    pub async fn cmd_set(
        &mut self,
        path: &str,
        plaintext: Zeroizing<Vec<u8>>,
    ) -> anyhow::Result<()> {
        let current = self.current_version(path).await?;
        let metadata = Metadata {
            version: 1,
            secret_id: derive::secret_id(&self.principal, path),
            tenant: "self".to_string(),
            owner: self.principal.clone(),
            rev: current + 1,
            content_type: "opaque".to_string(),
            recovery_optin: false,
        };
        let recipients = Recipients {
            users: &[self.identity.encryption_public()],
            recovery: None,
        };
        let envelope = seal(
            plaintext.as_slice(),
            metadata,
            &recipients,
            self.identity.signing_key(),
        )?;
        let mut request = Request::new(PushRequest {
            path: path.to_string(),
            envelope: envelope.to_bytes()?,
            expected_prev_rev: current,
        });
        attach_auth(&mut request, &self.identity, "/vault.v1.Vault/Push")?;
        let version = self.client.push(request).await?.into_inner().version;
        println!("pushed {path} version {version}");
        Ok(())
    }

    /// Fetch and locally decrypt a secret version (`0` ⇒ latest) to stdout.
    pub async fn cmd_get(&mut self, path: &str, version: u64) -> anyhow::Result<()> {
        let expected = derive::secret_id(&self.principal, path);
        let mut request = Request::new(GetRequest {
            path: path.to_string(),
            version,
        });
        attach_auth(&mut request, &self.identity, "/vault.v1.Vault/Get")?;
        let resp = self.client.get(request).await?.into_inner();
        let plaintext = decrypt::open_envelope(&self.identity, &resp, &expected, version)?;
        use std::io::Write;
        std::io::stdout().write_all(&plaintext)?;
        Ok(())
    }

    /// The current head version for `path`, or 0 if the secret does not exist yet.
    async fn current_version(&mut self, path: &str) -> anyhow::Result<u64> {
        let mut request = Request::new(GetRequest {
            path: path.to_string(),
            version: 0,
        });
        attach_auth(&mut request, &self.identity, "/vault.v1.Vault/Get")?;
        match self.client.get(request).await {
            Ok(resp) => Ok(resp.into_inner().version),
            Err(status) if status.code() == Code::NotFound => Ok(0),
            Err(status) => Err(status.into()),
        }
    }

    /// Fetch and locally decrypt the caller's own copy of `path` (shared with `share`).
    pub(crate) async fn fetch_plaintext(
        &mut self,
        path: &str,
    ) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let expected = derive::secret_id(&self.principal, path);
        let mut request = Request::new(GetRequest {
            path: path.to_string(),
            version: 0,
        });
        attach_auth(&mut request, &self.identity, "/vault.v1.Vault/Get")?;
        let resp = self.client.get(request).await?.into_inner();
        decrypt::open_envelope(&self.identity, &resp, &expected, 0)
    }

    /// Re-seal the secret at `path` under a fresh DEK and push it at the next version.
    pub async fn cmd_rotate(&mut self, path: &str) -> anyhow::Result<()> {
        let current = self.current_version(path).await?;
        if current == 0 {
            anyhow::bail!("no secret at {path} to rotate");
        }
        let plaintext = self.fetch_plaintext(path).await?;
        let metadata = Metadata {
            version: 1,
            secret_id: derive::secret_id(&self.principal, path),
            tenant: "self".to_string(),
            owner: self.principal.clone(),
            rev: current + 1,
            content_type: "opaque".to_string(),
            recovery_optin: false,
        };
        let recipients = Recipients {
            users: &[self.identity.encryption_public()],
            recovery: None,
        };
        let envelope = seal(
            plaintext.as_slice(),
            metadata,
            &recipients,
            self.identity.signing_key(),
        )?;
        let mut request = Request::new(PushRequest {
            path: path.to_string(),
            envelope: envelope.to_bytes()?,
            expected_prev_rev: current,
        });
        attach_auth(&mut request, &self.identity, "/vault.v1.Vault/Rotate")?;
        let version = self.client.rotate(request).await?.into_inner().version;
        println!("rotated {path} to version {version}");
        Ok(())
    }
}
