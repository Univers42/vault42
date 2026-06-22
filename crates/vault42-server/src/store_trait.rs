/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   store_trait.rs                                       :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/20 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/20 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The storage port. The gRPC service depends on this owner-scoped surface, not on
//! a concrete backend, so the same `op_*` logic persists to the embedded SQLite store
//! (the `nano` offline default) or to grobase over `/query/v1` (the connected default)
//! without knowing which. Ports live in the domain; adapters implement it. The store
//! only ever holds opaque envelopes — it never decrypts.

use crate::audit_store::{AuditRow, Event};
use crate::env_store::{EnvSecretPut, EnvSecretRow};
use crate::scope_store::{ScopeKeyPut, ScopeKeyRow};
use crate::secret_read::SecretRow;
use crate::secret_write::PutSecret;
use crate::store::{Store, StoreError};

/// The owner-scoped persistence operations the service orchestrates. Every method is
/// scoped to one `owner`; an implementation MUST never return another owner's rows.
#[async_trait::async_trait]
pub trait SecretStore: Send + Sync {
    /// Fetch one secret version for `owner`/`path` (`version == 0` ⇒ latest), or `None`.
    async fn get_secret(
        &self,
        owner: &str,
        path: &str,
        version: i64,
    ) -> Result<Option<SecretRow>, StoreError>;

    /// List `(path, latest_version, updated_at)` for each of `owner`'s secrets under `prefix`.
    async fn list_secrets(
        &self,
        owner: &str,
        prefix: &str,
    ) -> Result<Vec<(String, i64, i64)>, StoreError>;

    /// Append the next version for `(owner, path)`; returns the new version.
    async fn put_secret(&self, put: PutSecret) -> Result<i64, StoreError>;

    /// Delete `(owner, path)`: all versions when `version == 0`, else one. Returns removal.
    async fn remove_secret(
        &self,
        owner: &str,
        path: &str,
        version: i64,
    ) -> Result<bool, StoreError>;

    /// Append one tamper-evident audit event to `owner`'s chain.
    async fn audit_append(&self, owner: &str, event: Event<'_>) -> Result<(), StoreError>;

    /// Read `owner`'s audit events with `ts >= since`, sequence-ordered.
    async fn audit_list(&self, owner: &str, since: i64) -> Result<Vec<AuditRow>, StoreError>;

    /// Deposit a scope-key grant under `put.owner` (a foreign-owner write, like share).
    async fn put_scope_key(&self, put: ScopeKeyPut) -> Result<(), StoreError>;

    /// Fetch `owner`'s own grant for `(scope_id, epoch)`, or `None` (owner-scoped).
    async fn get_scope_key(
        &self,
        owner: &str,
        scope_id: &str,
        epoch: i64,
    ) -> Result<Option<ScopeKeyRow>, StoreError>;

    /// List `(member_id, wrapped_at)` the caller may see for `(scope_id, epoch)`.
    async fn list_scope_members(
        &self,
        owner: &str,
        scope_id: &str,
        epoch: i64,
    ) -> Result<Vec<(String, i64)>, StoreError>;

    /// Append the next env-secret version for `(scope_id, epoch, path)`; returns the new
    /// version. NOT owner-scoped — the seal to the scope public key is the access control.
    async fn put_env_secret(&self, put: EnvSecretPut) -> Result<i64, StoreError>;

    /// Fetch one env-secret version for `(scope_id, epoch, path)` (`version == 0` ⇒
    /// latest), or `None`. Readable by ANY authenticated caller.
    async fn get_env_secret(
        &self,
        scope_id: &str,
        epoch: i64,
        path: &str,
        version: i64,
    ) -> Result<Option<EnvSecretRow>, StoreError>;
}

/// The embedded SQLite store IS a `SecretStore`; each method forwards to the inherent
/// implementation (which the conformance + e2e suites already pin), so `nano` stays
/// byte-identical while the service depends only on the port.
#[async_trait::async_trait]
impl SecretStore for Store {
    async fn get_secret(
        &self,
        owner: &str,
        path: &str,
        version: i64,
    ) -> Result<Option<SecretRow>, StoreError> {
        Store::get_secret(self, owner, path, version).await
    }

    async fn list_secrets(
        &self,
        owner: &str,
        prefix: &str,
    ) -> Result<Vec<(String, i64, i64)>, StoreError> {
        Store::list_secrets(self, owner, prefix).await
    }

    async fn put_secret(&self, put: PutSecret) -> Result<i64, StoreError> {
        Store::put_secret(self, put).await
    }

    async fn remove_secret(
        &self,
        owner: &str,
        path: &str,
        version: i64,
    ) -> Result<bool, StoreError> {
        Store::remove_secret(self, owner, path, version).await
    }

    async fn audit_append(&self, owner: &str, event: Event<'_>) -> Result<(), StoreError> {
        Store::audit_append(self, owner, event).await
    }

    async fn audit_list(&self, owner: &str, since: i64) -> Result<Vec<AuditRow>, StoreError> {
        Store::audit_list(self, owner, since).await
    }

    async fn put_scope_key(&self, put: ScopeKeyPut) -> Result<(), StoreError> {
        Store::put_scope_key(self, put).await
    }

    async fn get_scope_key(
        &self,
        owner: &str,
        scope_id: &str,
        epoch: i64,
    ) -> Result<Option<ScopeKeyRow>, StoreError> {
        Store::get_scope_key(self, owner, scope_id, epoch).await
    }

    async fn list_scope_members(
        &self,
        owner: &str,
        scope_id: &str,
        epoch: i64,
    ) -> Result<Vec<(String, i64)>, StoreError> {
        Store::list_scope_members(self, owner, scope_id, epoch).await
    }

    async fn put_env_secret(&self, put: EnvSecretPut) -> Result<i64, StoreError> {
        Store::put_env_secret(self, put).await
    }

    async fn get_env_secret(
        &self,
        scope_id: &str,
        epoch: i64,
        path: &str,
        version: i64,
    ) -> Result<Option<EnvSecretRow>, StoreError> {
        Store::get_env_secret(self, scope_id, epoch, path, version).await
    }
}
