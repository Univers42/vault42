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

/// P4: configuration variables at three levels of scope.
///
/// `value` is OPAQUE to the authority. It is never parsed, never validated beyond a length
/// bound, and never interpreted: for a secret it is a sealed blob the client produced against
/// the environment's scope key, and the authority holds no key that could open it. That is the
/// zero-knowledge boundary expressed as a storage rule.
///
/// `is_secret` is metadata for the client, telling it whether a value needs unsealing. The
/// authority treats both kinds identically.
///
/// The primary key is `(scope_kind, scope_id, key)`, which is what makes precedence a query
/// rather than bookkeeping: one row per key per scope, and resolution folds environment over
/// project over organization.
const M4: &str = "
CREATE TABLE IF NOT EXISTS variables (
  scope_kind TEXT    NOT NULL CHECK (scope_kind IN ('org','project','env')),
  scope_id   TEXT    NOT NULL,
  key        TEXT    NOT NULL,
  value      TEXT    NOT NULL,
  is_secret  INTEGER NOT NULL DEFAULT 0 CHECK (is_secret IN (0,1)),
  updated_at INTEGER NOT NULL,
  updated_by TEXT    NOT NULL REFERENCES accounts(id),
  PRIMARY KEY (scope_kind, scope_id, key)
);
CREATE INDEX IF NOT EXISTS variables_scope ON variables(scope_kind, scope_id);
";

/// P4.5: a scope-key wrap belongs to ONE environment at ONE epoch.
///
/// The original table keyed wraps by `(grant_id, account_id)` alone, which made `missing`
/// answer the wrong question in two ways. A project-wide grant covers every environment, so
/// wrapping a member for `prod` dropped them from `missing` for `staging` and they were never
/// provisioned there. And an epoch-blind row still claimed a wrap existed after a rotation had
/// moved the scope to a new epoch, so rotation re-wrapped to nobody and the environment was
/// stranded with no repair path.
///
/// Existing rows carry neither an environment nor an epoch, so there is nothing to migrate
/// them to. Dropping them is safe and self-healing: a wrap row only records that a member has
/// already been handed the key, so losing it reports the member as missing and the next
/// reconcile re-wraps them. Bookkeeping is rebuilt; access is never lost.
const M5: &str = "
DROP TABLE IF EXISTS grant_wraps;
CREATE TABLE grant_wraps (
  grant_id   TEXT    NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
  account_id TEXT    NOT NULL,
  env_id     TEXT    NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  epoch      INTEGER NOT NULL CHECK (epoch >= 1),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (grant_id, account_id, env_id, epoch)
);
CREATE INDEX IF NOT EXISTS grant_wraps_scope ON grant_wraps(env_id, epoch);
";

/// P4.6: a group membership is bound to organization membership, like a team membership.
///
/// `group_members` referenced `accounts(id)`, so removing somebody from an organization left
/// their project group memberships behind, and a grant to that group still reached them. The
/// old `groups.rs` said as much: the rule was checked in a handler "because the group table has
/// no organization column to hang a composite foreign key from". This adds the column, so the
/// rule is enforced by the database on the way in AND on the way out — removing an
/// organization member now cascades their group memberships away.
///
/// The backfill inner-joins `org_members`, which drops any existing row whose account is no
/// longer an organization member. Those are exactly the stale memberships being eliminated, and
/// dropping them is what lets the constraint hold; keeping them would fail the migration.
const M6: &str = "
CREATE TABLE group_members_bound (
  group_id   TEXT    NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  org_id     TEXT    NOT NULL,
  account_id TEXT    NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (group_id, account_id),
  FOREIGN KEY (org_id, account_id)
    REFERENCES org_members(org_id, account_id) ON DELETE CASCADE
);
INSERT INTO group_members_bound(group_id, org_id, account_id, created_at)
  SELECT gm.group_id, p.org_id, gm.account_id, gm.created_at
    FROM group_members gm
    JOIN groups g ON g.id = gm.group_id
    JOIN projects p ON p.id = g.project_id
    JOIN org_members om ON om.org_id = p.org_id AND om.account_id = gm.account_id;
DROP TABLE group_members;
ALTER TABLE group_members_bound RENAME TO group_members;
";

/// P5: one-time codes and keystore escrow.
///
/// `otp_codes` holds at most one live code per address, keyed on the address, so a new request
/// replaces the old one. That is deliberate: letting codes accumulate would let somebody request
/// a hundred and then have a hundred simultaneous chances to guess. `code_hash` is a BLAKE3
/// digest bound to the address, never the code, and `attempts` is what bounds guessing against
/// a six-digit space.
///
/// `escrow` holds the passphrase-wrapped keystore for multi-device use. The blob is ciphertext
/// the authority cannot open — the passphrase never leaves the operator's machine — so this table
/// is storage, not custody.
const M7: &str = "
CREATE TABLE IF NOT EXISTS otp_codes (
  email       TEXT    NOT NULL PRIMARY KEY,
  code_hash   TEXT    NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  consumed_at INTEGER,
  attempts    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS escrow (
  email      TEXT    NOT NULL PRIMARY KEY,
  blob       TEXT    NOT NULL,
  updated_at INTEGER NOT NULL
);
";

/// P8: the attempt ledger behind every rate limit.
///
/// One table for both callers rather than one per caller: a login throttle and a code-request
/// throttle are the same question asked about different buckets, and two tables would drift.
/// Keyed on `(bucket, subject)` where the subject is a normalized email — never an IP, because
/// behind a proxy the only address available is one a client can set, and a limit keyed on a
/// value the attacker chooses is not a limit.
const M8: &str = "
CREATE TABLE IF NOT EXISTS attempts (
  bucket       TEXT    NOT NULL,
  subject      TEXT    NOT NULL,
  count        INTEGER NOT NULL,
  window_start INTEGER NOT NULL,
  PRIMARY KEY (bucket, subject)
);
";

/// P9: a project group can be granted a role, like a user or a team.
///
/// Groups could be created, joined and left, and authorized nothing: the grants CHECK admitted
/// `user` and `team` only. SQLite cannot alter a CHECK, so `grants` is rebuilt — and `grants` is
/// a PARENT: `grant_wraps` references it `ON DELETE CASCADE`. A DROP with foreign keys enforced
/// runs an implicit DELETE first, which would delete every wrap record in the database, so this
/// migration is flagged `rebuilds_a_parent` and applied with foreign keys off, then checked.
/// That is SQLite's own procedure for a schema change it cannot make with ALTER. The index goes
/// with the old table and is recreated.
const M9: &str = "
CREATE TABLE grants_admitting_groups (
  id           TEXT    NOT NULL PRIMARY KEY,
  project_id   TEXT    NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  grantee_kind TEXT    NOT NULL CHECK (grantee_kind IN ('user','team','group')),
  grantee_id   TEXT    NOT NULL,
  project_role TEXT    NOT NULL CHECK (project_role IN ('read','write','admin')),
  env_id       TEXT    REFERENCES environments(id) ON DELETE CASCADE,
  granted_by   TEXT    NOT NULL REFERENCES accounts(id),
  created_at   INTEGER NOT NULL,
  revoked_at   INTEGER
);
INSERT INTO grants_admitting_groups
  (id, project_id, grantee_kind, grantee_id, project_role, env_id, granted_by, created_at, revoked_at)
  SELECT id, project_id, grantee_kind, grantee_id, project_role, env_id, granted_by, created_at, revoked_at
    FROM grants;
DROP TABLE grants;
ALTER TABLE grants_admitting_groups RENAME TO grants;
CREATE INDEX IF NOT EXISTS grants_project ON grants(project_id);
";

/// The ledger of what has been applied.
const LEDGER: &str = "
CREATE TABLE IF NOT EXISTS schema_migrations (
  version    INTEGER NOT NULL PRIMARY KEY,
  name       TEXT    NOT NULL,
  applied_at INTEGER NOT NULL
);";

/// One schema step.
struct Migration {
    version: i64,
    name: &'static str,
    sql: &'static str,
    /// True when the step drops and recreates a table other tables reference, which must run
    /// with foreign keys off so the DROP does not cascade into them.
    rebuilds_a_parent: bool,
}

/// A step that only adds or rebuilds tables nothing references.
const fn step(version: i64, name: &'static str, sql: &'static str) -> Migration {
    Migration {
        version,
        name,
        sql,
        rebuilds_a_parent: false,
    }
}

/// The ordered migration ledger.
const MIGRATIONS: &[Migration] = &[
    step(1, "accounts_sessions_tenants", M1),
    step(2, "orgs_teams_invites", M2),
    step(3, "projects_envs_groups_pubkeys_grants", M3),
    step(4, "variables", M4),
    step(5, "grant_wraps_per_env_epoch", M5),
    step(6, "group_members_bound_to_org", M6),
    step(7, "otp_codes_and_escrow", M7),
    step(8, "attempts", M8),
    Migration {
        version: 9,
        name: "grants_admit_groups",
        sql: M9,
        rebuilds_a_parent: true,
    },
];

/// Apply every migration not yet recorded, in version order.
pub(crate) fn run(conn: &mut rusqlite::Connection, now: i64) -> anyhow::Result<()> {
    conn.execute_batch(LEDGER)?;
    for migration in MIGRATIONS {
        if is_applied(conn, migration.version)? {
            continue;
        }
        apply(conn, migration, now)?;
        tracing::info!(
            version = migration.version,
            name = migration.name,
            "authority migration applied"
        );
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
fn apply(conn: &mut rusqlite::Connection, migration: &Migration, now: i64) -> anyhow::Result<()> {
    if migration.rebuilds_a_parent {
        return apply_with_references_off(conn, migration, now);
    }
    let tx = conn.transaction()?;
    tx.execute_batch(migration.sql)?;
    record(&tx, migration, now)?;
    tx.commit()?;
    Ok(())
}

/// Apply a step that rebuilds a referenced table, with foreign keys off for its duration only.
///
/// `PRAGMA foreign_keys` is a no-op inside a transaction, so it is switched around the
/// transaction, and switched back on whether the step succeeded or not. Before committing, the
/// step must leave no reference dangling — `pragma_foreign_key_check` is what enforcement would
/// have said row by row — or it is rolled back.
fn apply_with_references_off(
    conn: &mut rusqlite::Connection,
    migration: &Migration,
    now: i64,
) -> anyhow::Result<()> {
    conn.execute_batch("PRAGMA foreign_keys=OFF;")?;
    let applied = rebuild_checked(conn, migration, now);
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;
    applied
}

/// The transaction behind `apply_with_references_off`: run, refuse dangling references, record.
fn rebuild_checked(
    conn: &mut rusqlite::Connection,
    migration: &Migration,
    now: i64,
) -> anyhow::Result<()> {
    let tx = conn.transaction()?;
    tx.execute_batch(migration.sql)?;
    let dangling: i64 =
        tx.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;
    if dangling > 0 {
        anyhow::bail!(
            "migration {} {} would leave {dangling} dangling reference(s); rolled back",
            migration.version,
            migration.name
        );
    }
    record(&tx, migration, now)?;
    tx.commit()?;
    Ok(())
}

/// Record `migration` as applied.
fn record(tx: &rusqlite::Transaction<'_>, migration: &Migration, now: i64) -> anyhow::Result<()> {
    tx.execute(
        "INSERT INTO schema_migrations(version, name, applied_at) VALUES(?1,?2,?3)",
        rusqlite::params![migration.version, migration.name, now],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A connection that enforces foreign keys, as `Store::open` configures every one.
    fn enforced() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().expect("in-memory database");
        conn.execute_batch("PRAGMA foreign_keys=ON;")
            .expect("foreign keys on");
        conn
    }

    /// Apply the ledger through `last`, as a binary from before the later migrations did.
    fn migrate_through(conn: &mut rusqlite::Connection, last: i64) {
        conn.execute_batch(LEDGER).expect("ledger");
        for migration in MIGRATIONS.iter().filter(|m| m.version <= last) {
            apply(conn, migration, 0).expect(migration.name);
        }
    }

    /// One account, organization, project and environment, a grant, and a wrap recorded for it.
    fn seed(conn: &rusqlite::Connection) {
        conn.execute_batch(
            "INSERT INTO accounts(id,email,password_hash,created_at) VALUES('a1','a@x.io','h',0);
             INSERT INTO orgs(id,slug,name,created_by,created_at) VALUES('o1','o','O','a1',0);
             INSERT INTO org_members(org_id,account_id,role,created_at) VALUES('o1','a1','owner',0);
             INSERT INTO projects(id,org_id,slug,name,created_at) VALUES('p1','o1','p','P',0);
             INSERT INTO environments(id,project_id,name,created_at) VALUES('e1','p1','prod',0);
             INSERT INTO grants(id,project_id,grantee_kind,grantee_id,project_role,env_id,granted_by,created_at)
               VALUES('g1','p1','user','a1','write','e1','a1',0);
             INSERT INTO grant_wraps(grant_id,account_id,env_id,epoch,created_at)
               VALUES('g1','a1','e1',1,0);",
        )
        .expect("seed");
    }

    fn count(conn: &rusqlite::Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .expect("count")
    }

    /// Rebuilding `grants` must not cost a single wrap record. `grant_wraps` references it with ON
    /// DELETE CASCADE, so the obvious rebuild — drop and rename with foreign keys on — deletes
    /// every wrap in the database as a side effect of the DROP, and rotation then re-wraps nobody.
    #[test]
    fn widening_grants_to_groups_keeps_every_wrap_and_every_reference() {
        let mut conn = enforced();
        migrate_through(&mut conn, 8);
        seed(&conn);

        run(&mut conn, 0).expect("the rest of the ledger applies");

        assert_eq!(count(&conn, "grants"), 1, "the grant survives");
        assert_eq!(
            count(&conn, "grant_wraps"),
            1,
            "and so does its wrap record"
        );
        conn.execute(
            "INSERT INTO grants(id,project_id,grantee_kind,grantee_id,project_role,granted_by,created_at)
             VALUES('g2','p1','group','grp1','read','a1',0)",
            [],
        )
        .expect("a group grant is storable");
        assert!(
            conn.execute(
                "INSERT INTO grants(id,project_id,grantee_kind,grantee_id,project_role,granted_by,created_at)
                 VALUES('g3','p1','robot','r1','read','a1',0)",
                [],
            )
            .is_err(),
            "an unknown grantee kind is still refused"
        );
        let keys_on: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .expect("pragma");
        assert_eq!(keys_on, 1, "foreign keys are enforced again afterwards");
        conn.execute("DELETE FROM projects WHERE id='p1'", [])
            .expect("delete project");
        assert_eq!(
            count(&conn, "grant_wraps"),
            0,
            "the rebuilt table still carries the cascade to its wraps"
        );
    }

    /// A rebuild that would leave a reference dangling is rolled back, not committed.
    #[test]
    fn a_rebuild_that_would_dangle_a_reference_is_rolled_back() {
        let mut conn = enforced();
        migrate_through(&mut conn, 8);
        seed(&conn);
        let breaking = Migration {
            version: 99,
            name: "orphans_a_wrap",
            sql: "DELETE FROM grants;",
            rebuilds_a_parent: true,
        };
        let error = apply(&mut conn, &breaking, 0).expect_err("must refuse");
        assert!(error.to_string().contains("dangling"), "{error}");
        assert_eq!(count(&conn, "grants"), 1, "nothing was committed");
        let keys_on: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .expect("pragma");
        assert_eq!(keys_on, 1, "foreign keys are back on even after a refusal");
    }
}
