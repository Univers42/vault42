/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   backup.rs                                            :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Taking a consistent backup of the authority database, and the reason it is a subcommand.
//!
//! The deployed image is distroless: no shell, no sqlite3, nothing to copy files with. So the
//! only thing that can back up a running authority is the authority. `fly console --command
//! "backup /data/out.db"` reaches this, and nothing else on that machine can.
//!
//! It uses `VACUUM INTO` rather than copying the database file, and that is the whole point of
//! this module rather than a preference. Write-ahead logging means the `.db` on disk can be a
//! nearly empty shell while every row lives in the `-wal` beside it, so copying the `.db` alone
//! produces a backup that restores CLEANLY and is EMPTY. It reports no error at any stage: the
//! copy succeeds, the restore succeeds, the server starts, and the vault is gone. `VACUUM INTO`
//! asks SQLite for a consistent snapshot of the whole database, WAL content included, as one
//! file with no `-wal` or `-shm` to remember.
//!
//! It is safe against a live writer, because SQLite takes its own read transaction for the
//! duration. Gate v28 restores from this and asserts a known account still authenticates, and
//! asserts that the naive `.db`-only copy does NOT — a backup nobody has restored is a hope.

use anyhow::Context;

/// Write a consistent single-file snapshot of `db_path` to `out_path`.
///
/// Refuses to overwrite: a backup that silently replaces the previous one turns a mistyped path
/// into the loss of the only good copy, and the operator is running this precisely because they
/// care about the previous copy.
pub fn snapshot(db_path: &str, out_path: &str) -> anyhow::Result<()> {
    if std::path::Path::new(out_path).exists() {
        anyhow::bail!("{out_path} already exists; refusing to overwrite an existing backup");
    }
    let conn = rusqlite::Connection::open(db_path)
        .with_context(|| format!("opening {db_path} for backup"))?;
    conn.execute("VACUUM INTO ?1", [out_path])
        .with_context(|| format!("writing the snapshot to {out_path}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A snapshot carries rows that are still only in the write-ahead log.
    ///
    /// This is the assertion the whole module exists for. The same fixture copied `.db`-only
    /// loses the row, and that half is asserted in the sibling test so the two sit together.
    #[test]
    fn a_snapshot_carries_rows_that_live_only_in_the_wal() {
        let dir = std::env::temp_dir().join(format!("v42-backup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let db = dir.join("a.db");
        let out = dir.join("snap.db");
        let conn = rusqlite::Connection::open(&db).expect("open");
        conn.pragma_update(None, "journal_mode", "WAL")
            .expect("wal");
        conn.execute("CREATE TABLE t (v TEXT NOT NULL)", [])
            .expect("ddl");
        conn.execute("INSERT INTO t (v) VALUES ('sentinel-row')", [])
            .expect("insert");

        snapshot(db.to_str().expect("path"), out.to_str().expect("path")).expect("snapshot");
        let restored = rusqlite::Connection::open(&out).expect("open snapshot");
        let found: String = restored
            .query_row("SELECT v FROM t", [], |r| r.get(0))
            .expect("the row survived the backup");
        assert_eq!(found, "sentinel-row");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Refusing to overwrite is what stops a mistyped path destroying the only good copy.
    #[test]
    fn an_existing_backup_is_never_overwritten() {
        let dir = std::env::temp_dir().join(format!("v42-backup-x-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let db = dir.join("a.db");
        let out = dir.join("taken.db");
        rusqlite::Connection::open(&db).expect("open");
        std::fs::write(&out, b"a previous backup").expect("write");

        let refused = snapshot(db.to_str().expect("p"), out.to_str().expect("p"));
        assert!(refused.is_err(), "an existing path must not be overwritten");
        assert_eq!(
            std::fs::read(&out).expect("still there"),
            b"a previous backup",
            "the previous backup is untouched"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
