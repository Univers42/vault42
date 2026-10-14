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

/// Closed rows one attempt deletes at most.
pub(super) const SWEEP_BATCH: i64 = 100;

/// Delete up to `?3` closed windows (`window_start <= ?2`) of bucket `?1`, oldest first.
const SWEEP: &str = "DELETE FROM attempts WHERE rowid IN (SELECT rowid FROM attempts \
                     WHERE bucket=?1 AND window_start <= ?2 ORDER BY window_start LIMIT ?3)";

impl Store {
    /// Record one attempt in `bucket` for `subject` and return the running count.
    ///
    /// The window is a fixed span from the first attempt, not a sliding one: an attacker who
    /// paces themselves to the window boundary gains a factor of two, and a sliding window costs
    /// a row per attempt to compute. Two is not the difference between safe and unsafe here; a
    /// table that grows with an attacker's patience would be.
    ///
    /// A closed window restarts inside the upsert, so the count never depends on the sweep having
    /// reached the caller's own row. Keep it there: an upsert that relied on the sweep would count
    /// forever the day the sweep is capped or moved — the permanent lockout the header rules out,
    /// since `guard` runs before the password that would clear it.
    ///
    /// The sweep exists because closed windows were kept forever: every address ever typed at the
    /// login form stayed in the database, an erased account's included, recreated by the first
    /// probe after the erase.
    ///
    /// Ponytail: forgetting is on write, not at expiry — a closed window survives until enough
    /// attempts in its bucket follow, so an idle bucket keeps its rows for as long as it stays
    /// idle. Each attempt deletes at most `SWEEP_BATCH` rows, so a backlog drains over the next
    /// attempts instead of stalling one on the pool's only connection: 0.019–0.021 s per batch
    /// from a million-row backlog, where one unbounded delete took 0.64 s + 4.19 s commit
    /// (sqlite3 3.45, WAL, laptop). A timer-driven sweep if retention must be bounded in time.
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
            let closed = now - window_secs;
            tx.execute(SWEEP, params![bucket, closed, SWEEP_BATCH])
                .map_err(|e| crate::error::Error::Internal(e.into()))?;
            let count = tx
                .query_row(
                    "INSERT INTO attempts(bucket, subject, count, window_start) VALUES(?1,?2,1,?3) \
                     ON CONFLICT(bucket, subject) DO UPDATE SET \
                       count = CASE WHEN window_start <= ?4 THEN 1 ELSE count + 1 END, \
                       window_start = CASE WHEN window_start <= ?4 THEN ?3 ELSE window_start END \
                     RETURNING count",
                    params![bucket, subject, now, closed],
                    |r| r.get(0),
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

#[cfg(test)]
mod tests {
    use crate::error::Error;

    const HOUR: i64 = 3600;

    /// A closed window holds nothing a later attempt reads, so it goes on the next attempt in its
    /// bucket: an address somebody once typed — an erased account's included — is no longer kept
    /// forever, though an idle bucket keeps it until that next attempt. Another bucket's rows are
    /// left to that bucket's own traffic.
    #[tokio::test]
    async fn a_closed_window_is_forgotten_on_the_next_attempt() {
        let store = crate::e2e::fresh_app("attempts-forget", None).store.clone();
        let record =
            |subject: &str, bucket, at| store.record_attempt(bucket, subject.to_string(), at, HOUR);
        record("closed@example.test", "login", 1_000).await.unwrap();
        record("other-bucket@example.test", "code", 1_000)
            .await
            .unwrap();
        record("open@example.test", "login", 1_000 + HOUR - 1)
            .await
            .unwrap();
        record("next@example.test", "login", 1_000 + HOUR)
            .await
            .unwrap();
        let left = store
            .call(|conn| {
                let mut stmt = conn
                    .prepare("SELECT subject FROM attempts ORDER BY subject")
                    .map_err(|e| Error::Internal(e.into()))?;
                let rows = stmt
                    .query_map([], |r| r.get::<_, String>(0))
                    .map_err(|e| Error::Internal(e.into()))?;
                rows.collect::<rusqlite::Result<Vec<_>>>()
                    .map_err(|e| Error::Internal(e.into()))
            })
            .await
            .unwrap();
        assert_eq!(
            left,
            [
                "next@example.test",
                "open@example.test",
                "other-bucket@example.test"
            ]
        );
    }

    /// The count restarts in the upsert, not in the sweep: a closed row behind a full batch of
    /// older ones is still read as closed, so a capped sweep can never become a lockout.
    #[tokio::test]
    async fn a_window_the_sweep_has_not_reached_still_restarts() {
        let store = crate::e2e::fresh_app("attempts-behind", None).store.clone();
        for _ in 0..6 {
            store
                .record_attempt("login", "me@example.test".to_string(), 5_000, HOUR)
                .await
                .unwrap();
        }
        store
            .call(|conn| {
                for i in 0..super::SWEEP_BATCH {
                    conn.execute(
                        "INSERT INTO attempts VALUES('login', ?1, 1, ?2)",
                        rusqlite::params![format!("older{i}@example.test"), i],
                    )
                    .map_err(|e| Error::Internal(e.into()))?;
                }
                Ok(())
            })
            .await
            .unwrap();
        let count = store
            .record_attempt("login", "me@example.test".to_string(), 5_000 + HOUR, HOUR)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    /// Forgetting closed windows does not reset a live one: the count still climbs inside it.
    #[tokio::test]
    async fn an_open_window_keeps_counting() {
        let store = crate::e2e::fresh_app("attempts-count", None).store.clone();
        for (at, want) in [(1_000, 1), (1_000 + HOUR - 1, 2), (1_000 + HOUR, 1)] {
            let count = store
                .record_attempt("login", "me@example.test".to_string(), at, HOUR)
                .await
                .unwrap();
            assert_eq!(count, want, "at {at}");
        }
    }

    /// The sweep runs on every attempt, so it must seek the window index (migration 10) rather
    /// than scan the bucket — a scan is the amplifier the index exists to remove.
    #[tokio::test]
    async fn the_sweep_seeks_the_window_index() {
        let store = crate::e2e::fresh_app("attempts-plan", None).store.clone();
        let plan = store
            .call(|conn| {
                let mut stmt = conn
                    .prepare(&format!("EXPLAIN QUERY PLAN {}", super::SWEEP))
                    .map_err(|e| Error::Internal(e.into()))?;
                let rows = stmt
                    .query_map(rusqlite::params!["login", 0, super::SWEEP_BATCH], |r| {
                        r.get::<_, String>(3)
                    })
                    .map_err(|e| Error::Internal(e.into()))?;
                rows.collect::<rusqlite::Result<Vec<_>>>()
                    .map_err(|e| Error::Internal(e.into()))
            })
            .await
            .unwrap();
        assert!(
            plan.iter().any(|step| step.contains("attempts_window")),
            "plan: {plan:?}"
        );
    }
}
