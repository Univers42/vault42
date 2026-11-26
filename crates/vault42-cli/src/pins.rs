/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   pins.rs                                              :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+ */
/*   Created: 2026/11/25 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/11/25 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! What this machine has already seen, so a server cannot answer "latest" with an older
//! revision.
//!
//! The stateless checks — the transport label must equal the revision signed in the envelope,
//! and a read that names a revision passes it as `min_rev` — are blind to the case that
//! matters: a bare latest read, where the client names no revision and the server may serve
//! revision 2 of a secret that is at 9. Nothing is forged; every signature verifies.
//!
//! Only local state can see that, so this module keeps it: the highest revision accepted per
//! handle, and the author key first seen for a shared secret.
//!
//! * Below the pin ⇒ refused. That is the rollback.
//! * At or above ⇒ accepted, and the pin rises. Two machines only ever move it up.
//! * A handle this machine deleted may go backwards once: `rm` removes the rows, so the next
//!   write legitimately starts at 1. The exception is written when the server confirms the
//!   tombstone, and no server can set it.
//!
//! The residual, stated: right after a local `rm`, one lower revision is accepted for that
//! handle, so a server that answers the delete by serving the old revision instead of the new
//! write is believed once. The next accepted read raises the pin again.
//!
//! `VAULT42_ACCEPT_ROLLBACK=1` overrides a refusal (a restore is a legitimate rollback no
//! client can distinguish from an attack) and lowers the pin to what it accepted.
//!
//! Not covered: a rollback before this machine's first read of a handle, and a read of an
//! explicit older revision, which asks for history.

use crate::client::Session;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Set to `1` to accept a revision below this machine's pin (a restore, not an attack).
pub const ACCEPT_ROLLBACK: &str = "VAULT42_ACCEPT_ROLLBACK";

/// Set to `1` to accept a changed author key for a secret shared to this identity.
pub const ACCEPT_NEW_AUTHOR: &str = "VAULT42_ACCEPT_NEW_AUTHOR";

/// What this machine knows about one handle.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// The highest revision accepted here; `0` means nothing seen yet.
    #[serde(default)]
    pub seen: u64,
    /// Set at `rm`: the next write for this handle may start below the pin, once.
    #[serde(default)]
    pub released: bool,
    /// The author key first seen for a shared secret, hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
}

/// The whole book: principal → handle → entry, one file per machine.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinBook {
    #[serde(default)]
    pub principals: BTreeMap<String, BTreeMap<String, Entry>>,
}

impl PinBook {
    /// Refuse `served` when it is below the pin, then record it.
    pub fn check(
        &mut self,
        principal: &str,
        handle: &str,
        served: u64,
        accept_rollback: bool,
    ) -> anyhow::Result<()> {
        let entry = self.entry(principal, handle);
        if entry.released {
            entry.released = false;
            entry.seen = served;
            return Ok(());
        }
        if served < entry.seen {
            let pinned = entry.seen;
            if !accept_rollback {
                anyhow::bail!(
                    "the server answered revision {served} for {handle}, but this machine has \
                     already read revision {pinned} — refusing what looks like a rollback. Two \
                     things produce this without an attack: a restore of the server's state, and a \
                     delete performed on ANOTHER machine (that delete restarts this secret at \
                     revision 1). If it is one of those, re-run with {ACCEPT_ROLLBACK}=1."
                );
            }
            eprintln!(
                "warning: {handle} went back from revision {pinned} to {served}; accepting it \
                 because {ACCEPT_ROLLBACK} is set"
            );
            entry.seen = served;
            return Ok(());
        }
        entry.seen = served;
        Ok(())
    }

    /// Record a revision this machine produced or read explicitly, without the floor check.
    pub fn record(&mut self, principal: &str, handle: &str, rev: u64) {
        let entry = self.entry(principal, handle);
        entry.seen = entry.seen.max(rev);
    }

    /// Mark `handle` as deleted here, so one lower revision is expected next.
    pub fn release(&mut self, principal: &str, handle: &str) {
        self.entry(principal, handle).released = true;
    }

    /// Pin a shared secret's author on first read; refuse a later change.
    pub fn check_author(
        &mut self,
        principal: &str,
        handle: &str,
        author_hex: &str,
        accept_change: bool,
    ) -> anyhow::Result<()> {
        let entry = self.entry(principal, handle);
        match entry.author.clone() {
            None => {
                entry.author = Some(author_hex.to_string());
                Ok(())
            }
            Some(pinned) if pinned == author_hex => Ok(()),
            Some(pinned) => {
                if !accept_change {
                    anyhow::bail!(
                        "the author key for {handle} changed: this machine pinned {pinned}, the \
                         server now offers {author_hex}. A re-share looks exactly like this; so \
                         does a substitution. Re-run with {ACCEPT_NEW_AUTHOR}=1 once you know \
                         which it is."
                    );
                }
                eprintln!(
                    "warning: the author key for {handle} changed from {pinned} to {author_hex}; \
                     accepting it because {ACCEPT_NEW_AUTHOR} is set"
                );
                entry.author = Some(author_hex.to_string());
                Ok(())
            }
        }
    }

    fn entry(&mut self, principal: &str, handle: &str) -> &mut Entry {
        self.principals
            .entry(principal.to_string())
            .or_default()
            .entry(handle.to_string())
            .or_default()
    }

    /// Read the book; absent means this machine has no pins yet.
    pub fn load() -> anyhow::Result<Self> {
        match std::fs::read(path()?) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|error| {
                anyhow::anyhow!(
                    "the revision pins at {} are unreadable ({error}); delete the file to \
                     re-adopt the server's current state, which forfeits the rollback check \
                     until it rebuilds",
                    path().map(|p| p.display().to_string()).unwrap_or_default()
                )
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error.into()),
        }
    }

    /// Persist the book, owner-readable only.
    pub fn save(&self) -> anyhow::Result<()> {
        let path = path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, serde_json::to_vec_pretty(self)?)?;
        restrict(&path)
    }
}

impl Session {
    /// Refuse a LATEST answer below this machine's pin, then record it.
    pub(crate) fn check_latest(&self, handle: &str, served: u64) -> anyhow::Result<()> {
        let mut book = PinBook::load()?;
        book.check(
            &self.principal,
            handle,
            served,
            matches!(std::env::var(ACCEPT_ROLLBACK).as_deref(), Ok("1")),
        )?;
        note_if_unsaved(&book);
        Ok(())
    }

    /// Record a revision this machine produced or asked for by number.
    pub(crate) fn record_revision(&self, handle: &str, rev: u64) {
        match PinBook::load() {
            Ok(mut book) => {
                book.record(&self.principal, handle, rev);
                note_if_unsaved(&book);
            }
            Err(error) => eprintln!(
                "note: revision {rev} of {handle} was not recorded locally ({error}); a later \
                 rollback of it would go unnoticed here"
            ),
        }
    }

    /// Mark a handle this machine just deleted.
    pub(crate) fn release_handle(&self, handle: &str) {
        match PinBook::load() {
            Ok(mut book) => {
                book.release(&self.principal, handle);
                note_if_unsaved(&book);
            }
            Err(error) => eprintln!("note: the delete of {handle} was not recorded: {error}"),
        }
    }

    /// The author of a blob in this identity's own namespace must be this identity.
    ///
    /// No first-use trust: the caller's own key is local. A secret SHARED to this identity is
    /// somebody else's by construction, so its author is pinned on first read instead.
    pub(crate) fn check_author(&self, handle: &str, author_pubkey: &[u8]) -> anyhow::Result<()> {
        if !handle.starts_with("shared/") {
            if self.identity.author_public().to_bytes().as_slice() == author_pubkey {
                return Ok(());
            }
            anyhow::bail!(
                "this was written by somebody else — a blob in your own namespace must be \
                 yours, so it is refused rather than opened"
            );
        }
        let mut book = PinBook::load()?;
        book.check_author(
            &self.principal,
            handle,
            &hex::encode(author_pubkey),
            matches!(std::env::var(ACCEPT_NEW_AUTHOR).as_deref(), Ok("1")),
        )?;
        note_if_unsaved(&book);
        Ok(())
    }
}

/// Warn, rather than fail, when a pin could not be written: losing a pin loses a check and
/// does not lose the secret.
fn note_if_unsaved(book: &PinBook) {
    if let Err(error) = book.save() {
        eprintln!(
            "note: this machine's revision pins could not be saved ({error}); a rollback of a \
             secret read in this run would go unnoticed"
        );
    }
}

/// The pin file, beside the keystore, so `$VAULT42_KEYSTORE` isolates it too.
fn path() -> anyhow::Result<PathBuf> {
    let keystore = crate::keystore_io::keystore_path()?;
    Ok(keystore
        .parent()
        .map(|parent| parent.join("revisions.json"))
        .unwrap_or_else(|| PathBuf::from("revisions.json")))
}

/// Keep the file readable by its owner alone.
#[cfg(unix)]
fn restrict(path: &std::path::Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict(_path: &std::path::Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rollback itself.
    #[test]
    fn a_revision_below_the_pin_is_refused() {
        let mut book = PinBook::default();
        book.check("p", "h", 9, false).expect("first read");
        let error = book
            .check("p", "h", 2, false)
            .expect_err("revision 2 must be refused after 9");
        assert!(error.to_string().contains("rollback"), "{error}");
    }

    /// The positive control: a newer revision is accepted and raises the pin.
    #[test]
    fn a_higher_revision_is_accepted_and_raises_the_pin() {
        let mut book = PinBook::default();
        book.check("p", "h", 2, false).expect("first read");
        book.check("p", "h", 9, false).expect("a newer revision");
        assert_eq!(book.principals["p"]["h"].seen, 9);
        assert!(book.check("p", "h", 8, false).is_err());
    }

    /// `rm` then `set` is not an attack: the released handle may restart once.
    #[test]
    fn a_deleted_handle_may_restart_once() {
        let mut book = PinBook::default();
        book.check("p", "h", 7, false).expect("read");
        book.release("p", "h");
        book.check("p", "h", 0, false)
            .expect("the head after a delete");
        assert!(!book.principals["p"]["h"].released);
        book.record("p", "h", 1);
        assert!(book.check("p", "h", 0, false).is_err());
    }

    /// The override accepts the restore and moves the pin, so the next read compares against
    /// what was accepted rather than refusing forever.
    #[test]
    fn the_override_accepts_a_restore_and_moves_the_pin() {
        let mut book = PinBook::default();
        book.check("p", "h", 9, false).expect("read");
        book.check("p", "h", 4, true).expect("restore accepted");
        assert_eq!(book.principals["p"]["h"].seen, 4);
        book.check("p", "h", 5, false).expect("forward again");
    }

    /// Two identities on one machine keep separate floors.
    #[test]
    fn pins_are_per_principal() {
        let mut book = PinBook::default();
        book.check("one", "h", 5, false).expect("one");
        book.check("two", "h", 1, false).expect("two");
        assert!(book.check("one", "h", 1, false).is_err());
    }

    /// A shared secret's author is pinned, and a change is refused until overridden.
    #[test]
    fn a_changed_author_is_refused_until_said_so() {
        let mut book = PinBook::default();
        book.check_author("p", "shared/x", "aa", false)
            .expect("pin");
        book.check_author("p", "shared/x", "aa", false)
            .expect("same");
        assert!(book.check_author("p", "shared/x", "bb", false).is_err());
        book.check_author("p", "shared/x", "bb", true)
            .expect("override");
        book.check_author("p", "shared/x", "bb", false)
            .expect("the new key is the pin now");
    }
}
