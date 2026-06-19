/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   audit_rpc.rs                                         :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The streaming audit read. Returns the caller's own tamper-evident chain (since a
//! given timestamp) as a server stream of events — seq, chained prev_hash + hash — so
//! a client can independently re-verify the links offline.

use crate::ops_write::map_store;
use crate::principal::Principal;
use crate::svc::VaultSvc;
use std::pin::Pin;
use tokio_stream::Stream;
use tonic::Status;
use vault42_proto::vault::v1::AuditEvent;

/// The server-streaming response type for `Audit`.
pub type AuditStream = Pin<Box<dyn Stream<Item = Result<AuditEvent, Status>> + Send>>;

impl VaultSvc {
    /// Stream the caller's audit events with `ts >= since`.
    pub(crate) async fn op_audit(
        &self,
        caller: &Principal,
        since: i64,
    ) -> Result<AuditStream, Status> {
        let rows = self
            .store
            .audit_list(&caller.id, since)
            .await
            .map_err(map_store)?;
        let events: Vec<Result<AuditEvent, Status>> = rows
            .into_iter()
            .map(|e| {
                Ok(AuditEvent {
                    seq: e.seq,
                    ts: e.ts_string(),
                    actor: e.actor,
                    action: e.action,
                    target: e.target,
                    prev_hash: e.prev_hash,
                    hash: e.hash,
                })
            })
            .collect();
        Ok(Box::pin(tokio_stream::iter(events)))
    }
}
