/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   svc.rs                                               :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The orchestrating service value: an owner-scoped store, the auth skew window, and
//! an optional grobase client. It holds no plaintext and no recipient key — it routes
//! opaque envelopes and records audit. Cloned per connection by tonic, so every field
//! is cheaply clonable (the store is a pool handle, the grobase client an `Arc`).

use crate::audit_store::Event;
use crate::config::GrobaseCfg;
use crate::principal::Principal;
use crate::store_trait::SecretStore;
use std::sync::Arc;
use vault42_grobase::{AuditEvent, GrobaseClient};

/// The vault42 gRPC service. The store is the injected `SecretStore` port (embedded
/// SQLite for `nano`, grobase over `/query/v1` for the connected default).
#[derive(Clone)]
pub struct VaultSvc {
    pub(crate) store: Arc<dyn SecretStore>,
    pub(crate) skew_secs: i64,
    pub(crate) grobase: Option<Arc<GrobaseClient>>,
    pub(crate) contract_pub: Option<[u8; 32]>,
    pub(crate) scope_keys_enabled: bool,
}

impl VaultSvc {
    /// Build the service from its injected dependencies. `contract_pub`, when set, makes
    /// every request require a valid authority contract (managed multi-tenancy). The
    /// scope-key surface is OFF by default (`with_scope_keys` flips it on, flag-gated).
    pub fn new(
        store: Arc<dyn SecretStore>,
        skew_secs: i64,
        grobase: Option<GrobaseClient>,
        contract_pub: Option<[u8; 32]>,
    ) -> Self {
        Self {
            store,
            skew_secs,
            grobase: grobase.map(Arc::new),
            contract_pub,
            scope_keys_enabled: false,
        }
    }

    /// Enable (or leave disabled) the scope-key RPCs. OFF keeps the wire byte-parity:
    /// the scope-key RPCs return UNIMPLEMENTED until a deployment flips the flag on.
    pub fn with_scope_keys(mut self, enabled: bool) -> Self {
        self.scope_keys_enabled = enabled;
        self
    }

    /// Record an operation in the local audit chain (and grobase's, when wired). A
    /// local append failure is logged, not fatal; the op already succeeded.
    pub(crate) async fn emit_audit(&self, caller: &Principal, action: &str, target: &str) {
        let event = Event {
            actor: &caller.id,
            action,
            target,
        };
        if let Err(error) = self.store.audit_append(&caller.id, event).await {
            tracing::warn!(?error, "local audit append failed");
        }
        if let Some(grobase) = &self.grobase {
            let mirror = AuditEvent {
                actor: &caller.id,
                action,
                target,
            };
            let _ = grobase.audit_append(&caller.tenant, &mirror).await;
        }
    }
}

/// Build a grobase config into a live client (used at startup).
pub fn connect_grobase(cfg: &GrobaseCfg) -> anyhow::Result<GrobaseClient> {
    Ok(GrobaseClient::new(cfg.url.clone(), cfg.token.clone())?)
}
