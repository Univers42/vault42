/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   store.rs                                             :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The embedded SQLite store — vault42's sealed-state substrate. It holds ONLY opaque
//! envelopes (the server has no recipient key, so it can never decrypt them) plus a
//! per-owner tamper-evident audit chain. One file on an encrypted volume; statically
//! bundled SQLite so the binary needs no system libraries. All access is owner-scoped
//! per request by the calling code; the pool is injected (no globals).

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use std::time::{SystemTime, UNIX_EPOCH};

/// Storage errors, split so the gRPC layer maps a version conflict (failed
/// precondition) apart from any other failure (internal).
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("version conflict")]
    Conflict,
    #[error("per-owner secret quota exceeded")]
    Quota,
    #[error("storage error")]
    Sql,
}

/// The schema: a versioned secrets table and a hash-chained audit table.
const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS secrets (\
  owner TEXT NOT NULL, path TEXT NOT NULL, secret_id TEXT NOT NULL, version INTEGER NOT NULL,\
  envelope BLOB NOT NULL, author_pubkey BLOB NOT NULL, updated_at INTEGER NOT NULL,\
  PRIMARY KEY (owner, path, version));\
CREATE INDEX IF NOT EXISTS secrets_owner_path ON secrets(owner, path);\
CREATE TABLE IF NOT EXISTS audit (\
  owner TEXT NOT NULL, seq INTEGER NOT NULL, ts INTEGER NOT NULL, actor TEXT NOT NULL,\
  action TEXT NOT NULL, target TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL,\
  PRIMARY KEY (owner, seq));";

/// A clonable handle to the SQLite connection pool. `max_secrets` caps the number of
/// distinct paths one owner may create (0 = unlimited) — a guardrail against a
/// cross-owner share-spam DoS.
#[derive(Clone)]
pub struct Store {
    pool: Pool<SqliteConnectionManager>,
    pub(crate) max_secrets: i64,
}

impl Store {
    /// Open (creating if needed) the store at `path` and apply the schema. The pool is
    /// capped at one connection so every read-then-write (version bump, audit-chain
    /// link) is serialized and atomic — no fork, no lost audit event under concurrency.
    pub fn open(path: &str, max_secrets: i64) -> anyhow::Result<Self> {
        let manager = SqliteConnectionManager::file(path)
            .with_init(|c| c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;"));
        // ponytail: single writer connection — shard by owner if write throughput matters
        let pool = r2d2::Pool::builder().max_size(1).build(manager)?;
        let store = Self { pool, max_secrets };
        store.migrate()?;
        Ok(store)
    }

    /// Apply the idempotent schema.
    fn migrate(&self) -> anyhow::Result<()> {
        self.pool.get()?.execute_batch(SCHEMA)?;
        Ok(())
    }

    /// Run a blocking closure on a pooled connection off the async runtime.
    pub(crate) async fn run<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        F: FnOnce(&rusqlite::Connection) -> Result<T, StoreError> + Send + 'static,
        T: Send + 'static,
    {
        let pool = self.pool.clone();
        let joined = tokio::task::spawn_blocking(move || {
            let conn = pool.get().map_err(|_| StoreError::Sql)?;
            f(&conn)
        })
        .await;
        match joined {
            Ok(result) => result,
            Err(_) => Err(StoreError::Sql),
        }
    }
}

/// Current Unix time in seconds — the row/audit timestamp source.
pub(crate) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
