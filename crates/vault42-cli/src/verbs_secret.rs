/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   verbs_secret.rs                                      :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/11/25 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! `set` and `get`. `set` seals the plaintext locally for the caller and pushes the
//! opaque envelope with optimistic concurrency (expected_prev = current head). `get` fetches
//! the envelope and decrypts it locally — the server sees neither plaintext nor a DEK.
//!
//! Seal happens under an opaque handle, and the name is written to the sealed index
//! ([`crate::handles`]), so the server cannot read what the secret is called either. A name
//! stored by an older client is still readable once, with a note that it is still visible.

use crate::client::Session;
use crate::compose;
use crate::handles::{self, is_secret_handle};
use tonic::Request;
use vault42_proto::vault::v1::PushRequest;
use zeroize::Zeroizing;

impl Session {
    /// Seal `plaintext` for this identity and push it at the next version of `path`'s handle.
    pub async fn cmd_set(
        &mut self,
        path: &str,
        plaintext: Zeroizing<Vec<u8>>,
    ) -> anyhow::Result<()> {
        let wire = self.wire_path(path);
        let current = self.head_version(&wire).await?;
        let envelope = compose::self_envelope(
            &self.identity,
            &self.principal,
            &wire,
            current + 1,
            plaintext.as_slice(),
        )?;
        let mut request = Request::new(PushRequest {
            path: wire.clone(),
            envelope,
            expected_prev_rev: current,
        });
        self.authorize(&mut request, "/vault.v1.Vault/Push")?;
        let version = self.client.push(request).await?.into_inner().version;
        self.record_revision(&wire, version);
        self.remember(&wire, path, version).await;
        println!("pushed {path} version {version}");
        Ok(())
    }

    /// Fetch and locally decrypt a secret version (`0` ⇒ latest) to stdout.
    pub async fn cmd_get(&mut self, path: &str, version: u64) -> anyhow::Result<()> {
        let wire = self.wire_path(path);
        let plaintext = match self.fetch_open(&wire, version).await {
            Ok(plaintext) => plaintext,
            Err(error)
                if is_secret_handle(&wire) && version == 0 && handles::is_not_found(&error) =>
            {
                let plaintext = self.fetch_open(path, 0).await?;
                eprintln!(
                    "note: {path} was stored by an older client under its plaintext name, which \
                     the server can see. Re-run `vault42 set {path}` to move it to an opaque \
                     handle."
                );
                plaintext
            }
            Err(error) => return Err(error),
        };
        use std::io::Write;
        std::io::stdout().write_all(&plaintext)?;
        Ok(())
    }

    /// Fetch and locally decrypt the caller's own copy of `path` (shared with `share`).
    pub(crate) async fn fetch_plaintext(
        &mut self,
        path: &str,
    ) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let wire = self.wire_path(path);
        self.fetch_open(&wire, 0).await
    }

    /// Re-seal the secret at `path` under a fresh DEK and push it at the next version.
    pub async fn cmd_rotate(&mut self, path: &str) -> anyhow::Result<()> {
        let wire = self.wire_path(path);
        let current = self.head_version(&wire).await?;
        if current == 0 {
            anyhow::bail!(
                "no secret at {path} to rotate — if it was written by an older client under its \
                 plaintext name, re-run `vault42 set {path}` first"
            );
        }
        let plaintext = self.fetch_plaintext(path).await?;
        let envelope = compose::self_envelope(
            &self.identity,
            &self.principal,
            &wire,
            current + 1,
            plaintext.as_slice(),
        )?;
        let mut request = Request::new(PushRequest {
            path: wire.clone(),
            envelope,
            expected_prev_rev: current,
        });
        self.authorize(&mut request, "/vault.v1.Vault/Rotate")?;
        let version = self.client.rotate(request).await?.into_inner().version;
        self.record_revision(&wire, version);
        self.remember(&wire, path, version).await;
        println!("rotated {path} to version {version}");
        Ok(())
    }
}
