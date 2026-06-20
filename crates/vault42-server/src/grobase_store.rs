/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   grobase_store.rs                                     :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/20 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/20 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The grobase-backed `SecretStore`: persists opaque envelopes into a dedicated
//! grobase database over the Kong `/query/v1` front door. Per request it mints a
//! short GoTrue JWT for the owner (`jwt.rs`), so the data plane stamps
//! `owner_id = user:<sub>` on writes and the `read_scoped` mount appends the owner
//! predicate on reads — strict per-owner isolation, enforced server-side, never by
//! pool state. The envelope is stored as base64 TEXT (a bytea column cannot bind
//! from a JSON string); the server still never sees plaintext (the blob is opaque).

use crate::audit_store::{chain_hash, AuditRow, Event};
use crate::jwt;
use crate::secret_read::SecretRow;
use crate::secret_write::PutSecret;
use crate::store::StoreError;
use crate::store_trait::SecretStore;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const SECRETS_TABLE: &str = "vault42_secrets";
const AUDIT_TABLE: &str = "vault42_audit";

/// A grobase storage backend. Holds the Kong endpoint, the public + app API keys, the
/// mount id, and the co-deployed JWT secret used to mint per-owner sessions.
pub struct GrobaseStore {
    http: reqwest::Client,
    kong: String,
    anon_key: String,
    app_key: String,
    db_id: String,
    jwt_secret: Zeroizing<Vec<u8>>,
    jwt_ttl: i64,
}

/// The `/query/v1` execute response envelope (`QueryResult`).
#[derive(serde::Deserialize)]
struct QueryResponse {
    #[serde(default)]
    rows: Vec<Value>,
    #[serde(default, rename = "rowCount")]
    row_count: i64,
}

impl GrobaseStore {
    /// Build a store targeting `kong` (e.g. `http://kong:8000`), authenticating with
    /// the public `anon_key` + the service `app_key`, scoped to mount `db_id`, minting
    /// owner JWTs from `jwt_secret` valid for `jwt_ttl` seconds.
    pub fn new(
        kong: String,
        anon_key: String,
        app_key: String,
        db_id: String,
        jwt_secret: Vec<u8>,
        jwt_ttl: i64,
    ) -> Result<Self, StoreError> {
        let http = reqwest::Client::builder()
            .build()
            .map_err(|_| StoreError::Sql)?;
        Ok(Self {
            http,
            kong,
            anon_key,
            app_key,
            db_id,
            jwt_secret: Zeroizing::new(jwt_secret),
            jwt_ttl,
        })
    }

    /// Execute one `/query/v1` operation on `table` as `owner` (a minted JWT scopes it).
    async fn exec(&self, owner: &str, table: &str, body: Value) -> Result<QueryResponse, StoreError> {
        let subject = jwt::owner_subject(owner);
        let token = jwt::mint(&self.jwt_secret, &subject, now_unix(), self.jwt_ttl)
            .map_err(|_| StoreError::Sql)?;
        let url = format!("{}/query/v1/{}/tables/{table}", self.kong, self.db_id);
        let response = self
            .http
            .post(url)
            .header("apikey", &self.anon_key)
            .header("X-Baas-Api-Key", &self.app_key)
            .header("Authorization", format!("Bearer {token}"))
            .json(&body)
            .send()
            .await
            .map_err(|_| StoreError::Sql)?;
        if !response.status().is_success() {
            return Err(StoreError::Sql);
        }
        response.json::<QueryResponse>().await.map_err(|_| StoreError::Sql)
    }

    /// Read `owner`'s current head version for `path` (0 when absent) — the basis for
    /// the next version + the optimistic-concurrency check.
    async fn head_version(&self, owner: &str, path: &str) -> Result<i64, StoreError> {
        Ok(self
            .get_secret(owner, path, 0)
            .await?
            .map(|row| row.version)
            .unwrap_or(0))
    }

    /// Read `owner`'s audit head as `(last_seq, last_hash)` (`(0, "")` when empty).
    async fn audit_head(&self, owner: &str) -> Result<(i64, String), StoreError> {
        let body = json!({"op": "list", "sort": {"seq": "desc"}, "limit": 1});
        let resp = self.exec(owner, AUDIT_TABLE, body).await?;
        match resp.rows.first() {
            Some(row) => Ok((field_i64(row, "seq"), field_str(row, "hash"))),
            None => Ok((0, String::new())),
        }
    }
}

#[async_trait::async_trait]
impl SecretStore for GrobaseStore {
    async fn get_secret(
        &self,
        owner: &str,
        path: &str,
        version: i64,
    ) -> Result<Option<SecretRow>, StoreError> {
        let mut filter = json!({ "path": path });
        if version != 0 {
            filter["version"] = json!(version);
        }
        let body = json!({"op": "list", "filter": filter, "sort": {"version": "desc"}, "limit": 1});
        let resp = self.exec(owner, SECRETS_TABLE, body).await?;
        resp.rows.first().map(row_to_secret).transpose()
    }

    async fn list_secrets(
        &self,
        owner: &str,
        prefix: &str,
    ) -> Result<Vec<(String, i64, i64)>, StoreError> {
        // ponytail: client-side prefix+group over a 500-row page — push to the
        // aggregate op (MAX(version) GROUP BY path) if an owner exceeds 500 secrets.
        let body = json!({"op": "list", "limit": 500});
        let resp = self.exec(owner, SECRETS_TABLE, body).await?;
        Ok(fold_latest(resp.rows, prefix))
    }

    async fn put_secret(&self, put: PutSecret) -> Result<i64, StoreError> {
        let current = self.head_version(&put.owner, &put.path).await?;
        if matches!(put.expected_prev, Some(expected) if expected != current) {
            return Err(StoreError::Conflict);
        }
        let next = current + 1;
        let data = json!({
            "path": put.path,
            "secret_id": put.secret_id,
            "version": next,
            "envelope": STANDARD.encode(&put.envelope),
            "author_pubkey": STANDARD.encode(&put.author_pubkey),
            "updated_at": now_unix(),
        });
        self.exec(&put.owner, SECRETS_TABLE, json!({"op": "insert", "data": data}))
            .await?;
        Ok(next)
    }

    async fn remove_secret(
        &self,
        owner: &str,
        path: &str,
        version: i64,
    ) -> Result<bool, StoreError> {
        let mut filter = json!({ "path": path });
        if version != 0 {
            filter["version"] = json!(version);
        }
        let resp = self
            .exec(owner, SECRETS_TABLE, json!({"op": "delete", "filter": filter}))
            .await?;
        Ok(resp.row_count > 0)
    }

    async fn audit_append(&self, owner: &str, event: Event<'_>) -> Result<(), StoreError> {
        let (last_seq, last_hash) = self.audit_head(owner).await?;
        let (seq, ts) = (last_seq + 1, now_unix());
        let hash = chain_hash(&last_hash, &event, seq, ts);
        let data = json!({
            "seq": seq, "ts": ts, "actor": event.actor, "action": event.action,
            "target": event.target, "prev_hash": last_hash, "hash": hash,
        });
        self.exec(owner, AUDIT_TABLE, json!({"op": "insert", "data": data}))
            .await
            .map(|_| ())
    }

    async fn audit_list(&self, owner: &str, since: i64) -> Result<Vec<AuditRow>, StoreError> {
        let body = json!({"op": "list", "sort": {"seq": "asc"}, "limit": 500});
        let resp = self.exec(owner, AUDIT_TABLE, body).await?;
        Ok(resp
            .rows
            .iter()
            .map(row_to_audit)
            .filter(|row| row.ts >= since)
            .collect())
    }
}

/// Current Unix time in seconds — the row/audit timestamp + JWT `iat` source.
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Decode one `/query/v1` row into a `SecretRow`, base64-decoding the opaque columns.
fn row_to_secret(row: &Value) -> Result<SecretRow, StoreError> {
    let envelope = STANDARD
        .decode(field_str(row, "envelope"))
        .map_err(|_| StoreError::Sql)?;
    let author_pubkey = STANDARD
        .decode(field_str(row, "author_pubkey"))
        .map_err(|_| StoreError::Sql)?;
    Ok(SecretRow {
        version: field_i64(row, "version"),
        envelope,
        author_pubkey,
    })
}

/// Project a `/query/v1` row into an `AuditRow`.
fn row_to_audit(row: &Value) -> AuditRow {
    AuditRow {
        seq: field_i64(row, "seq"),
        ts: field_i64(row, "ts"),
        actor: field_str(row, "actor"),
        action: field_str(row, "action"),
        target: field_str(row, "target"),
        prev_hash: field_str(row, "prev_hash"),
        hash: field_str(row, "hash"),
    }
}

/// Reduce a page of rows to the latest `(path, version, updated_at)` per path under
/// `prefix`, path-sorted (the `ls` shape). `BTreeMap` keeps the path ordering.
fn fold_latest(rows: Vec<Value>, prefix: &str) -> Vec<(String, i64, i64)> {
    let mut latest: BTreeMap<String, (i64, i64)> = BTreeMap::new();
    for row in &rows {
        let path = field_str(row, "path");
        if !path.starts_with(prefix) {
            continue;
        }
        let (version, updated) = (field_i64(row, "version"), field_i64(row, "updated_at"));
        let entry = latest.entry(path).or_insert((0, 0));
        entry.0 = entry.0.max(version);
        entry.1 = entry.1.max(updated);
    }
    latest.into_iter().map(|(p, (v, u))| (p, v, u)).collect()
}

/// Read a row field as `i64`, accepting a JSON number or a numeric string (0 on miss).
fn field_i64(row: &Value, key: &str) -> i64 {
    let value = &row[key];
    value
        .as_i64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(0)
}

/// Read a row field as an owned `String` (empty on a missing/non-string field).
fn field_str(row: &Value, key: &str) -> String {
    row[key].as_str().unwrap_or("").to_string()
}
