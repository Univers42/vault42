/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   migrate.rs                                           :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Versioned schema migrations.
//!
//! Each migration is applied once inside a transaction and recorded in
//! `schema_migrations`, so a restart is idempotent and a partially applied migration
//! cannot exist. The SQL is deliberately portable: no SQLite-only syntax, so the move
//! to PostgreSQL later is mechanical rather than a rewrite.

/// P1: accounts, sessions, and the tenant registry the contract route claims into.
///
/// `sessions` stores only a hash of the bearer token, never the token, so a database
/// leak cannot be replayed as a login. The `CHECK` constraints keep the status and flag
/// domains enforced by the database rather than by whichever handler happens to write.
const M1: &str = "
CREATE TABLE IF NOT EXISTS accounts (
  id            TEXT    NOT NULL PRIMARY KEY,
  email         TEXT    NOT NULL UNIQUE,
  password_hash TEXT    NOT NULL,
  status        TEXT    NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active','disabled')),
  mfa_required  INTEGER NOT NULL DEFAULT 0 CHECK (mfa_required IN (0,1)),
  created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT    NOT NULL PRIMARY KEY,
  account_id TEXT    NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  issued_at  INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS sessions_account ON sessions(account_id);

CREATE TABLE IF NOT EXISTS tenants (
  tenant     TEXT    NOT NULL PRIMARY KEY,
  author_fp  TEXT    NOT NULL,
  account_id TEXT    REFERENCES accounts(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS tenants_author_fp ON tenants(author_fp);
";

/// P2: organizations, teams, and the invite ledger.
///
/// `team_members` denormalizes `org_id` so the composite foreign key onto
/// `org_members(org_id, account_id)` can exist. That key is the point of the table's
/// shape: it makes "a team member must already belong to the organization" a database
/// invariant rather than a check a handler could forget or a race could slip past.
///
/// Invites store only a hash of their token, for the same reason sessions do: a leaked
/// database must not yield a usable credential. `status` plus `accepted_at` make an
/// invite single-use.
const M2: &str = "
CREATE TABLE IF NOT EXISTS orgs (
  id         TEXT    NOT NULL PRIMARY KEY,
  slug       TEXT    NOT NULL UNIQUE,
  name       TEXT    NOT NULL,
  created_by TEXT    NOT NULL REFERENCES accounts(id),
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS org_members (
  org_id     TEXT    NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  account_id TEXT    NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  role       TEXT    NOT NULL CHECK (role IN ('owner','admin','member')),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (org_id, account_id)
);
CREATE INDEX IF NOT EXISTS org_members_account ON org_members(account_id);

CREATE TABLE IF NOT EXISTS teams (
  id         TEXT    NOT NULL PRIMARY KEY,
  org_id     TEXT    NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  slug       TEXT    NOT NULL,
  name       TEXT    NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (org_id, slug)
);

CREATE TABLE IF NOT EXISTS team_members (
  team_id    TEXT    NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  org_id     TEXT    NOT NULL,
  account_id TEXT    NOT NULL,
  team_role  TEXT    NOT NULL CHECK (team_role IN ('admin','member')),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (team_id, account_id),
  FOREIGN KEY (org_id, account_id)
    REFERENCES org_members(org_id, account_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS invites (
  id          TEXT    NOT NULL PRIMARY KEY,
  token_hash  TEXT    NOT NULL UNIQUE,
  scope_kind  TEXT    NOT NULL CHECK (scope_kind IN ('org','team','group')),
  scope_id    TEXT    NOT NULL,
  email       TEXT    NOT NULL,
  role        TEXT    NOT NULL,
  status      TEXT    NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending','accepted','revoked')),
  invited_by  TEXT    NOT NULL REFERENCES accounts(id),
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  accepted_at INTEGER,
  accepted_by TEXT    REFERENCES accounts(id)
);
CREATE INDEX IF NOT EXISTS invites_scope ON invites(scope_kind, scope_id);
CREATE INDEX IF NOT EXISTS invites_email ON invites(email);
";

/// P3: projects, environments, groups, member public keys, and project grants.
///
/// A project id must be a parseable UUID, not an arbitrary string: 42ctl derives a scope id
/// as `blake3(project_uuid_bytes ‖ env_name)[..16]`, so a non-UUID project id has no scope
/// and the whole env-secret path breaks. The schema cannot express that, so the handler
/// generates v4 UUIDs and validation refuses anything else.
///
/// `member_pubkeys` carries the same composite foreign key trick as `team_members`: you
/// cannot register keys for an organization you do not belong to.
///
/// `grants.env_id` is NULL for a project-wide grant, which by contract applies to every
/// environment in the project. That is a semantic the client already relies on.
const M3: &str = "
CREATE TABLE IF NOT EXISTS projects (
  id         TEXT    NOT NULL PRIMARY KEY,
  org_id     TEXT    NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  slug       TEXT    NOT NULL,
  name       TEXT    NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (org_id, slug)
);

CREATE TABLE IF NOT EXISTS environments (
  id           TEXT    NOT NULL PRIMARY KEY,
  project_id   TEXT    NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name         TEXT    NOT NULL,
  scope_pubkey TEXT,
  scope_epoch  INTEGER NOT NULL DEFAULT 0,
  created_at   INTEGER NOT NULL,
  UNIQUE (project_id, name)
);

CREATE TABLE IF NOT EXISTS groups (
  id         TEXT    NOT NULL PRIMARY KEY,
  project_id TEXT    NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name       TEXT    NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
  group_id   TEXT    NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  account_id TEXT    NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (group_id, account_id)
);

CREATE TABLE IF NOT EXISTS member_pubkeys (
  org_id      TEXT    NOT NULL,
  account_id  TEXT    NOT NULL,
  x25519_pub  TEXT    NOT NULL,
  ed25519_pub TEXT    NOT NULL,
  v42_address TEXT    NOT NULL,
  pubkey_sig  TEXT    NOT NULL,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (org_id, account_id),
  FOREIGN KEY (org_id, account_id)
    REFERENCES org_members(org_id, account_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS grants (
  id           TEXT    NOT NULL PRIMARY KEY,
  project_id   TEXT    NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  grantee_kind TEXT    NOT NULL CHECK (grantee_kind IN ('user','team')),
  grantee_id   TEXT    NOT NULL,
  project_role TEXT    NOT NULL CHECK (project_role IN ('read','write','admin')),
  env_id       TEXT    REFERENCES environments(id) ON DELETE CASCADE,
  granted_by   TEXT    NOT NULL REFERENCES accounts(id),
  created_at   INTEGER NOT NULL,
  revoked_at   INTEGER
);
CREATE INDEX IF NOT EXISTS grants_project ON grants(project_id);

CREATE TABLE IF NOT EXISTS grant_wraps (
  grant_id   TEXT    NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
  account_id TEXT    NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (grant_id, account_id)
);
";

/// The ordered migration ledger: `(version, name, sql)`.
const MIGRATIONS: &[(i64, &str, &str)] = &[
    (1, "accounts_sessions_tenants", M1),
    (2, "orgs_teams_invites", M2),
    (3, "projects_envs_groups_pubkeys_grants", M3),
];

/// Apply every migration not yet recorded, in version order.
pub(crate) fn run(conn: &mut rusqlite::Connection, now: i64) -> anyhow::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
           version    INTEGER NOT NULL PRIMARY KEY,
           name       TEXT    NOT NULL,
           applied_at INTEGER NOT NULL
         );",
    )?;
    for (version, name, sql) in MIGRATIONS {
        if is_applied(conn, *version)? {
            continue;
        }
        apply(conn, *version, name, sql, now)?;
        tracing::info!(version, name, "authority migration applied");
    }
    Ok(())
}

/// True if `version` is already recorded as applied.
fn is_applied(conn: &rusqlite::Connection, version: i64) -> anyhow::Result<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM schema_migrations WHERE version=?1",
        rusqlite::params![version],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// Apply one migration and record it, atomically.
fn apply(
    conn: &mut rusqlite::Connection,
    version: i64,
    name: &str,
    sql: &str,
    now: i64,
) -> anyhow::Result<()> {
    let tx = conn.transaction()?;
    tx.execute_batch(sql)?;
    tx.execute(
        "INSERT INTO schema_migrations(version, name, applied_at) VALUES(?1,?2,?3)",
        rusqlite::params![version, name, now],
    )?;
    tx.commit()?;
    Ok(())
}
