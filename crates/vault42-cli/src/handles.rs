/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   handles.rs                                           :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/11/25 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/11/25 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Opaque handles, and the sealed index that turns them back into names.
//!
//! The server keys a secret by a string, and when that string was the path the user typed, the
//! vault's contents were secret and its names were not — `secrets.path` held `prod/stripe` in
//! the clear. A write now addresses an opaque handle instead: a UUIDv5 of `(principal, path)`
//! under the same namespace secret ids use, so it is stable across machines and runs while
//! revealing nothing.
//!
//! The name itself lives in [`NameIndex`], sealed to this identity and pushed at
//! `__42ctl/s/index`. `get` does not need it (the handle is derived from the name); `ls` does,
//! because the server cannot be asked what a row is called.
//!
//! This module and `42ctl`'s `core::nameindex` are the same wire format on purpose: the handle
//! prefix, the index path and the JSON are identical, so one index serves both clients. Change
//! one and the other stops reading it.
//!
//! Secrets written before handles existed sit under their plaintext name. Reads fall back to
//! that name for one release — saying so on stderr — and every write migrates the path, so the
//! leak only shrinks.

use crate::client::Session;
use crate::{compose, decrypt, derive};
use serde::{Deserialize, Serialize};
use tonic::Request;
use vault42_proto::vault::v1::{GetRequest, PushRequest};
use zeroize::Zeroizing;

/// The prefix of a personal-secret handle.
pub const SECRET_HANDLES: &str = "__42ctl/s/";

/// Where the sealed name index lives, one blob per owner namespace.
pub const INDEX_PATH: &str = "__42ctl/s/index";

/// The opaque handle for `path`: stable, unique per owner, and unrelated to the name.
pub fn secret_handle(principal: &str, path: &str) -> String {
    format!("{SECRET_HANDLES}{}", derive::secret_id(principal, path))
}

/// Whether `path` is a personal-secret handle.
pub fn is_secret_handle(path: &str) -> bool {
    path.starts_with(SECRET_HANDLES)
}

/// Whether `path` is one of the client's own reserved records rather than a secret.
pub fn is_internal(path: &str) -> bool {
    if path == INDEX_PATH {
        return true;
    }
    path.starts_with("__42ctl/") && !is_secret_handle(path)
}

/// One labelled handle: the name the user typed, and the revision last seen.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Label {
    pub handle: String,
    pub label: String,
    pub rev: u64,
}

/// The sealed index: every handle this identity wrote, with the name it was given.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameIndex {
    pub entries: Vec<Label>,
}

impl NameIndex {
    /// Record `handle` as `label`, replacing an earlier entry for the same handle.
    pub fn upsert(&mut self, handle: &str, label: &str, rev: u64) {
        self.entries.retain(|entry| entry.handle != handle);
        self.entries.push(Label {
            handle: handle.to_string(),
            label: label.to_string(),
            rev,
        });
        self.sort();
    }

    /// Drop `handle`, when it is there.
    pub fn remove(&mut self, handle: &str) {
        self.entries.retain(|entry| entry.handle != handle);
    }

    /// The label recorded for `handle`.
    pub fn label_of(&self, handle: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|entry| entry.handle == handle)
            .map(|entry| entry.label.as_str())
    }

    /// Keep this index's entries and add any of `other`'s it does not have.
    pub fn absorb(&mut self, other: &NameIndex) {
        for entry in &other.entries {
            if self.label_of(&entry.handle).is_none() {
                self.entries.push(entry.clone());
            }
        }
        self.sort();
    }

    /// Serialize for sealing.
    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Parse a decrypted index.
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }

    /// A deterministic order, so equal content seals to equal plaintext.
    fn sort(&mut self) {
        self.entries.sort_by(|a, b| a.label.cmp(&b.label));
    }
}

impl Session {
    /// The server-side path for a user-named secret.
    ///
    /// A plain name becomes an opaque handle. A path that is already a location — a share in
    /// another owner's namespace, or one of this client's own records — is used verbatim.
    pub(crate) fn wire_path(&self, path: &str) -> String {
        if path.starts_with("shared/") || path.starts_with("__42ctl/") {
            path.to_string()
        } else {
            secret_handle(&self.principal, path)
        }
    }

    /// The current head version for a server-side `path`, or 0 when it does not exist yet.
    pub(crate) async fn head_version(&mut self, path: &str) -> anyhow::Result<u64> {
        let mut request = Request::new(GetRequest {
            path: path.to_string(),
            version: 0,
        });
        self.authorize(&mut request, "/vault.v1.Vault/Get")?;
        match self.client.get(request).await {
            Ok(resp) => {
                let head = resp.into_inner().version;
                // A write is built on the head the server reports, so a rewound head would let
                // this machine append an old revision over a newer one. Same floor as a read.
                self.check_latest(path, head)?;
                Ok(head)
            }
            Err(status) if status.code() == tonic::Code::NotFound => Ok(0),
            Err(status) => Err(status.into()),
        }
    }

    /// Fetch and open one revision of a server-side path, binding the read to that secret id.
    pub(crate) async fn fetch_open(
        &mut self,
        path: &str,
        version: u64,
    ) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let expected = derive::secret_id(&self.principal, path);
        let mut request = Request::new(GetRequest {
            path: path.to_string(),
            version,
        });
        self.authorize(&mut request, "/vault.v1.Vault/Get")?;
        let resp = self.client.get(request).await?.into_inner();
        // Local state, applied before decryption: the author must be who this namespace says,
        // and a bare latest answer must not be older than what this machine has read.
        self.check_author(path, &resp.author_pubkey)?;
        if version == 0 {
            self.check_latest(path, resp.version)?;
        } else {
            self.record_revision(path, resp.version);
        }
        decrypt::open_envelope(&self.identity, &resp, &expected, version)
    }

    /// Load the name index; an absent blob means an empty index.
    pub(crate) async fn load_index(&mut self) -> anyhow::Result<NameIndex> {
        match self.fetch_open(INDEX_PATH, 0).await {
            Ok(bytes) => NameIndex::from_bytes(&bytes),
            Err(error) if is_not_found(&error) => Ok(NameIndex::default()),
            Err(error) => Err(error),
        }
    }

    /// Push `index`, absorbing a concurrent writer's entries on a conflict and retrying.
    pub(crate) async fn save_index(&mut self, index: &NameIndex) -> anyhow::Result<()> {
        let mut merged = index.clone();
        for _ in 0..5 {
            let rev = self.head_version(INDEX_PATH).await?;
            let envelope = compose::self_envelope(
                &self.identity,
                &self.principal,
                INDEX_PATH,
                rev + 1,
                &merged.to_bytes()?,
            )?;
            let mut request = Request::new(PushRequest {
                path: INDEX_PATH.to_string(),
                envelope,
                expected_prev_rev: rev,
            });
            self.authorize(&mut request, "/vault.v1.Vault/Push")?;
            match self.client.push(request).await {
                Ok(_) => return Ok(()),
                Err(status)
                    if status.code() == tonic::Code::FailedPrecondition
                        && status.message().contains("conflict") =>
                {
                    merged.absorb(&self.load_index().await?);
                }
                Err(status) => return Err(status.into()),
            }
        }
        anyhow::bail!("the name index changed under us five times; try again")
    }

    /// Record `handle` as `label`, warning (not failing) when the index cannot be written: the
    /// secret is readable without it, and failing would report a lost secret that is there.
    pub(crate) async fn remember(&mut self, handle: &str, label: &str, rev: u64) {
        match self.load_index().await {
            Ok(mut index) => {
                index.upsert(handle, label, rev);
                if let Err(error) = self.save_index(&index).await {
                    eprintln!(
                        "note: {label} is stored, but its name could not be indexed: {error}"
                    );
                }
            }
            Err(error) => {
                eprintln!("note: {label} is stored, but its name could not be indexed: {error}");
            }
        }
    }

    /// Drop `handle` from the index, warning rather than failing.
    pub(crate) async fn forget(&mut self, handle: &str) {
        match self.load_index().await {
            Ok(mut index) => {
                index.remove(handle);
                if let Err(error) = self.save_index(&index).await {
                    eprintln!(
                        "note: the secret is gone, but its name could not be unindexed: {error}"
                    );
                }
            }
            Err(error) => {
                eprintln!("note: the secret is gone, but its name could not be unindexed: {error}");
            }
        }
    }
}

/// Whether `error` is the server's `NotFound` (no row for that path/version).
pub(crate) fn is_not_found(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<tonic::Status>())
        .any(|status| status.code() == tonic::Code::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_handle_is_stable_opaque_and_per_owner() {
        let handle = secret_handle("principal", "prod/stripe");
        assert_eq!(handle, secret_handle("principal", "prod/stripe"));
        assert!(is_secret_handle(&handle));
        assert!(!handle.contains("stripe"));
        assert_ne!(handle, secret_handle("principal", "prod/other"));
        assert_ne!(handle, secret_handle("other", "prod/stripe"));
    }

    #[test]
    fn the_index_and_its_handles_are_classified_apart() {
        assert!(is_internal(INDEX_PATH), "the index is this client's record");
        assert!(!is_internal(&secret_handle("p", "a")));
        assert!(!is_internal("app/DB_URL"));
    }

    #[test]
    fn the_index_round_trips() {
        let mut index = NameIndex::default();
        index.upsert("h1", "prod/stripe", 1);
        index.upsert("h1", "prod/stripe", 2);
        assert_eq!(index.entries.len(), 1);
        assert_eq!(index.label_of("h1"), Some("prod/stripe"));
        let back = NameIndex::from_bytes(&index.to_bytes().expect("bytes")).expect("parse");
        assert_eq!(back, index);
    }

    /// The two clients must agree on the bytes, or one cannot read the other's index.
    #[test]
    fn the_index_json_shape_is_the_shared_contract() {
        let mut index = NameIndex::default();
        index.upsert("h", "lab", 7);
        let text = String::from_utf8(index.to_bytes().expect("bytes")).expect("utf8");
        assert_eq!(
            text,
            r#"{"entries":[{"handle":"h","label":"lab","rev":7}]}"#
        );
    }
}
