/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   purge.rs                                             :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/10/13 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/10/13 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! `vault42-server purge-owner <fingerprint>` — the server half of erasing an account.
//!
//! The authority erases the account, but it cannot reach this database, and this server never
//! asks the authority anything: an erased member's own secrets, audit chain and scope-key wraps
//! stay here, and a wrap at ANY epoch keeps letting them list and fetch a scope's ciphertext.
//! The deployed image is distroless, so, as with the authority's `backup`, the only thing that
//! can edit a live store is this binary, reached with `fly ssh console --command`.
//!
//! Only rows the owner owns go. Other owners' audit entries that NAME them stay, because editing
//! another owner's hash chain would break it; scope ciphertext they authored stays too, because
//! it belongs to the team that shares the scope.

use anyhow::{bail, Context};
use rusqlite::{params, Connection, OpenFlags};

/// What one purge removed.
#[derive(Debug, PartialEq, Eq)]
pub struct Purged {
    pub secrets: usize,
    pub audit: usize,
    pub scope_keys: usize,
}

/// Delete every row `owner` owns from the store at `db_path`, in one transaction.
///
/// Refuses a path that does not exist, because opening would create an empty database and the
/// purge would "succeed" on nothing. Refuses when the owner holds the LAST wrap of a scope: a
/// scope with no wraps counts as unclaimed, and anybody holding a contract may then claim it.
pub fn purge_owner(db_path: &str, owner: &str) -> anyhow::Result<Purged> {
    if owner.len() != 32
        || !owner
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        bail!("{owner:?} is not an owner fingerprint (32 lowercase hex characters)");
    }
    let mut conn = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .with_context(|| format!("opening {db_path} (it must already exist)"))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let stranded: Vec<String> = tx
        .prepare(
            "SELECT scope_id FROM scope_keys GROUP BY scope_id
              HAVING SUM(owner = ?1) > 0 AND SUM(owner <> ?1) = 0",
        )?
        .query_map(params![owner], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    if !stranded.is_empty() {
        bail!("{owner} holds the only wraps of scope(s) {stranded:?}; purging would leave them claimable");
    }
    let purged = Purged {
        secrets: tx.execute("DELETE FROM secrets WHERE owner=?1", params![owner])?,
        audit: tx.execute("DELETE FROM audit WHERE owner=?1", params![owner])?,
        scope_keys: tx.execute("DELETE FROM scope_keys WHERE owner=?1", params![owner])?,
    };
    tx.commit()?;
    Ok(purged)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GONE: &str = "70b03e54272fdc2fdd2a0341364ad2d9";
    const KEPT: &str = "58cda63ccc76c21b357887f1918f005a";

    /// A store holding one row of each kind for `GONE` and for `KEPT`, sharing one scope.
    fn fixture(tag: &str) -> String {
        let path = std::env::temp_dir().join(format!("v42-purge-{tag}-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let path = path.to_string_lossy().into_owned();
        crate::store::Store::open(&path, 0).expect("schema");
        let conn = Connection::open(&path).expect("open");
        for owner in [GONE, KEPT] {
            conn.execute_batch(&format!(
                "INSERT INTO secrets VALUES ('{owner}', 'p', 'id', 1, x'00', x'00', 0);
                 INSERT INTO audit VALUES ('{owner}', 1, 0, 'a', 'put', 't', '', 'h');
                 INSERT INTO scope_keys VALUES ('{owner}', 'shared', 1, 'b', 'g', 0);"
            ))
            .expect("seed");
        }
        path
    }

    /// The purged owner's rows go, every other owner's rows stay.
    #[test]
    fn purging_removes_only_the_owners_rows() {
        let path = fixture("only");
        let purged = purge_owner(&path, GONE).expect("purge");
        assert_eq!(
            purged,
            Purged {
                secrets: 1,
                audit: 1,
                scope_keys: 1
            }
        );
        let conn = Connection::open(&path).expect("open");
        let left: i64 = conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM secrets) + (SELECT COUNT(*) FROM audit)
                      + (SELECT COUNT(*) FROM scope_keys WHERE owner=?1)",
                params![KEPT],
                |row| row.get(0),
            )
            .expect("count");
        assert_eq!(left, 3, "the other owner keeps all three rows");
    }

    /// Holding a scope's last wrap refuses the purge and changes nothing.
    #[test]
    fn the_last_wrap_of_a_scope_is_never_purged() {
        let path = fixture("last");
        Connection::open(&path)
            .expect("open")
            .execute(
                "INSERT INTO scope_keys VALUES (?1, 'solo', 1, 'b', 'g', 0)",
                params![GONE],
            )
            .expect("seed solo scope");
        let refusal = purge_owner(&path, GONE).expect_err("must refuse");
        assert!(format!("{refusal}").contains("solo"), "{refusal}");
        let kept: i64 = Connection::open(&path)
            .expect("open")
            .query_row(
                "SELECT COUNT(*) FROM secrets WHERE owner=?1",
                params![GONE],
                |row| row.get(0),
            )
            .expect("count");
        assert_eq!(kept, 1, "a refused purge deletes nothing");
    }

    /// A missing database and a malformed fingerprint are refused before anything is written.
    #[test]
    fn a_missing_store_or_a_bad_fingerprint_is_refused() {
        assert!(purge_owner("/nonexistent/vault42.db", GONE).is_err());
        let path = fixture("bad");
        for bad in ["", "70B03E54272FDC2FDD2A0341364AD2D9", "x' OR 1=1 --"] {
            assert!(purge_owner(&path, bad).is_err(), "{bad:?} must be refused");
        }
    }
}
