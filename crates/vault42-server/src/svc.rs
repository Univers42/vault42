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
use crate::store::Store;
use std::sync::Arc;
use vault42_grobase::{AuditEvent, GrobaseClient};

/// The vault42 gRPC service.
#[derive(Clone)]
pub struct VaultSvc {
    pub(crate) store: Store,
    pub(crate) skew_secs: i64,
    pub(crate) grobase: Option<Arc<GrobaseClient>>,
}

impl VaultSvc {
    /// Build the service from its injected dependencies.
    pub fn new(store: Store, skew_secs: i64, grobase: Option<GrobaseClient>) -> Self {
        Self {
            store,
            skew_secs,
            grobase: grobase.map(Arc::new),
        }
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
