/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   attempts.rs                                          :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The attempt ledger behind every rate limit.
//!
//! One primitive, two callers: password guessing and one-time-code requests are the same question
//! about different buckets. Keyed on a normalized email rather than an address, because behind a
//! proxy the only source available is a header a client can set, and a limit keyed on a value the
//! attacker chooses is not a limit.
//!
//! The cost of keying on the subject is that an attacker can slow a real person down by guessing
//! at their address. That is why this backs off rather than locking out: the delay is bounded, it
//! decays on its own, and a correct password clears it. A hard lockout would hand any attacker a
//! way to deny an account indefinitely, which is a worse trade than a bounded wait.

use super::Store;
use crate::error::Result;
use rusqlite::params;

impl Store {
    /// Record one attempt in `bucket` for `subject` and return the running count.
    ///
    /// The window is a fixed span from the first attempt, not a sliding one: an attacker who
    /// paces themselves to the window boundary gains a factor of two, and a sliding window costs
    /// a row per attempt to compute. Two is not the difference between safe and unsafe here; a
    /// table that grows with an attacker's patience would be.
    pub async fn record_attempt(
        &self,
        bucket: &'static str,
        subject: String,
        now: i64,
        window_secs: i64,
    ) -> Result<i64> {
        self.call(move |conn| {
            let tx = conn
                .transaction()
                .map_err(|e| crate::error::Error::Internal(e.into()))?;
            let fresh: Option<(i64, i64)> = tx
                .query_row(
                    "SELECT count, window_start FROM attempts WHERE bucket=?1 AND subject=?2",
                    params![bucket, subject],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .ok();
            let count = match fresh {
                Some((count, started)) if now - started < window_secs => count + 1,
                _ => 1,
            };
            let started = match fresh {
                Some((_, started)) if now - started < window_secs => started,
                _ => now,
            };
            tx.execute(
                "INSERT INTO attempts(bucket, subject, count, window_start) VALUES(?1,?2,?3,?4) \
                 ON CONFLICT(bucket, subject) DO UPDATE SET count=?3, window_start=?4",
                params![bucket, subject, count, started],
            )
            .map_err(|e| crate::error::Error::Internal(e.into()))?;
            tx.commit()
                .map_err(|e| crate::error::Error::Internal(e.into()))?;
            Ok(count)
        })
        .await
    }

    /// Forget `subject`'s attempts in `bucket`. Called when the attempt succeeded, so a person
    /// who mistypes twice and then gets it right is not carrying a penalty into tomorrow.
    pub async fn clear_attempts(&self, bucket: &'static str, subject: String) -> Result<()> {
        self.call(move |conn| {
            conn.execute(
                "DELETE FROM attempts WHERE bucket=?1 AND subject=?2",
                params![bucket, subject],
            )
            .map_err(|e| crate::error::Error::Internal(e.into()))?;
            Ok(())
        })
        .await
    }
}
