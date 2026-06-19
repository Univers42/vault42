/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   audit_store.rs                                       :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The per-owner tamper-evident audit chain. Each event's hash covers the previous
//! hash plus a length-prefixed canonical form of its fields (the grobase `chain.go`
//! discipline), so altering or deleting any past event breaks every later link. This
//! is the standalone chain; when grobase is wired the server also mirrors events there.

use crate::store::{now_unix, Store, StoreError};
use rusqlite::params;
use sha2::{Digest, Sha256};

/// One stored audit event.
pub struct AuditRow {
    pub seq: i64,
    pub ts: i64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub prev_hash: String,
    pub hash: String,
}

impl AuditRow {
    /// The timestamp as a decimal-seconds string (the proto carries `ts` as a string).
    pub fn ts_string(&self) -> String {
        self.ts.to_string()
    }
}

/// The non-secret content of an event to append.
pub struct Event<'a> {
    pub actor: &'a str,
    pub action: &'a str,
    pub target: &'a str,
}

impl Store {
    /// Append an event to `owner`'s chain, computing the next sequence and link hash.
    pub async fn audit_append(&self, owner: &str, event: Event<'_>) -> Result<(), StoreError> {
        let (owner, actor, action, target) = (
            owner.to_string(),
            event.actor.to_string(),
            event.action.to_string(),
            event.target.to_string(),
        );
        self.run(move |c| {
            append_event(
                c,
                &owner,
                &Event {
                    actor: &actor,
                    action: &action,
                    target: &target,
                },
            )
        })
        .await
    }

    /// Read `owner`'s events with `ts >= since`, sequence-ordered.
    pub async fn audit_list(&self, owner: &str, since: i64) -> Result<Vec<AuditRow>, StoreError> {
        let owner = owner.to_string();
        self.run(move |c| {
            let mut stmt = c
                .prepare(
                    "SELECT seq,ts,actor,action,target,prev_hash,hash FROM audit \
                     WHERE owner=?1 AND ts>=?2 ORDER BY seq",
                )
                .map_err(|_| StoreError::Sql)?;
            let rows = stmt
                .query_map(params![owner, since], |r| {
                    Ok(AuditRow {
                        seq: r.get(0)?,
                        ts: r.get(1)?,
                        actor: r.get(2)?,
                        action: r.get(3)?,
                        target: r.get(4)?,
                        prev_hash: r.get(5)?,
                        hash: r.get(6)?,
                    })
                })
                .map_err(|_| StoreError::Sql)?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(|_| StoreError::Sql)?);
            }
            Ok(out)
        })
        .await
    }
}

/// Insert one event, chaining its hash onto the owner's current head.
fn append_event(c: &rusqlite::Connection, owner: &str, event: &Event) -> Result<(), StoreError> {
    let (last_seq, last_hash): (i64, String) = c
        .query_row(
            "SELECT COALESCE(MAX(seq),0), \
             COALESCE((SELECT hash FROM audit WHERE owner=?1 ORDER BY seq DESC LIMIT 1),'') \
             FROM audit WHERE owner=?1",
            params![owner],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(|_| StoreError::Sql)?;
    let (seq, ts) = (last_seq + 1, now_unix());
    let hash = chain_hash(&last_hash, event, seq, ts);
    c.execute(
        "INSERT INTO audit(owner,seq,ts,actor,action,target,prev_hash,hash) \
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            owner,
            seq,
            ts,
            event.actor,
            event.action,
            event.target,
            last_hash,
            hash
        ],
    )
    .map_err(|_| StoreError::Sql)?;
    Ok(())
}

/// `sha256` over the previous hash and a length-prefixed canonical form of the event.
fn chain_hash(prev: &str, event: &Event, seq: i64, ts: i64) -> String {
    let (seq_b, ts_b) = (seq.to_le_bytes(), ts.to_le_bytes());
    let fields: [&[u8]; 6] = [
        prev.as_bytes(),
        &seq_b,
        &ts_b,
        event.actor.as_bytes(),
        event.action.as_bytes(),
        event.target.as_bytes(),
    ];
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    hex::encode(hasher.finalize())
}
