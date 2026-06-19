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

//! The authority's tenant registry — a tiny SQLite table recording who registered
//! (tenant + author fingerprint + when). It exists for audit and to reject a second
//! claim on a taken tenant name; the contract itself is stateless (verified offline),
//! so this store is never on vault42's request path and stays near-empty.

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS tenants (\
  tenant TEXT NOT NULL, author_fp TEXT NOT NULL, created_at INTEGER NOT NULL,\
  PRIMARY KEY (tenant));";

/// A clonable handle to the registry pool.
#[derive(Clone)]
pub struct Store {
    pool: Pool<SqliteConnectionManager>,
}

impl Store {
    /// Open (creating if needed) the registry at `path` and apply the schema.
    pub fn open(path: &str) -> anyhow::Result<Self> {
        let manager = SqliteConnectionManager::file(path);
        let pool = Pool::builder().max_size(1).build(manager)?;
        pool.get()?.execute_batch(SCHEMA)?;
        Ok(Self { pool })
    }

    /// Record a tenant→fingerprint claim. Returns false if the tenant name is taken by
    /// a different fingerprint (idempotent for the same fingerprint).
    pub async fn claim_tenant(
        &self,
        tenant: &str,
        author_fp: &str,
        now: i64,
    ) -> anyhow::Result<bool> {
        let (tenant, author_fp) = (tenant.to_string(), author_fp.to_string());
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool.get()?;
            claim(&conn, &tenant, &author_fp, now)
        })
        .await?
    }
}

/// Insert the claim, accepting a repeat by the same fingerprint and rejecting a steal.
fn claim(
    conn: &rusqlite::Connection,
    tenant: &str,
    author_fp: &str,
    now: i64,
) -> anyhow::Result<bool> {
    let existing: Option<String> = conn
        .query_row(
            "SELECT author_fp FROM tenants WHERE tenant=?1",
            params![tenant],
            |r| r.get(0),
        )
        .ok();
    match existing {
        Some(fp) => Ok(fp == author_fp),
        None => {
            conn.execute(
                "INSERT INTO tenants(tenant, author_fp, created_at) VALUES(?1,?2,?3)",
                params![tenant, author_fp, now],
            )?;
            Ok(true)
        }
    }
}
