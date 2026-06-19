/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   verbs_audit.rs                                       :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! `audit` — stream this identity's tamper-evident chain. Each event prints its
//! sequence, timestamp, action, target, and a hash prefix; a client could re-verify
//! the `prev_hash`→`hash` links offline to detect any server-side tampering.

use crate::client::{attach_auth, Session};
use tonic::Request;
use vault42_proto::vault::v1::AuditRequest;

impl Session {
    /// Stream audit events with `ts >= since`.
    pub async fn cmd_audit(&mut self, since: i64) -> anyhow::Result<()> {
        let mut request = Request::new(AuditRequest { since });
        attach_auth(&mut request, &self.identity, "/vault.v1.Vault/Audit")?;
        let mut stream = self.client.audit(request).await?.into_inner();
        while let Some(event) = stream.message().await? {
            let hash = &event.hash[..event.hash.len().min(12)];
            println!(
                "seq {} ts {} {} {} hash={}",
                event.seq, event.ts, event.action, event.target, hash
            );
        }
        Ok(())
    }
}
