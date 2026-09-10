/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   offboard.rs                                          :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Offboarding: taking access away.
//!
//! Storing a secret is the first thing a vault must do; removing somebody's access to it is
//! the second. Until this module existed the authority had no route that removed anything, so
//! rotation's promise — "a revoked member loses access by absence at the new epoch" — described
//! a state nobody could reach.
//!
//! Two rules run through every operation here.
//!
//! Removal is authorization, not erasure. Nothing here can reach the scope keys a departing
//! member already holds: those are wrapped to their own X25519 key and stored in vault42, which
//! the authority cannot read or delete. What removal does is stop them being re-wrapped, so the
//! next `rotate-scope` leaves them behind. Callers are told this rather than left to assume the
//! stronger thing, because an operator who believes removal alone locked somebody out has been
//! misled at the worst possible moment.
//!
//! An organization must never lose its last owner. An organization with no owner cannot be
//! administered, invited to, or repaired, and there is no route back. Every path that could
//! remove one refuses.

use super::Store;
use crate::error::{Error, Result};
use rusqlite::params;

impl Store {
    /// Revoke a grant, so it authorizes nobody from now on.
    ///
    /// Soft: the row stays with `revoked_at` set, because the audit question "who used to be
    /// able to read this" outlives the grant. Every read filters `revoked_at IS NULL`, so a
    /// revoked grant contributes no authorized members and rotation passes it by.
    pub async fn revoke_grant(&self, grant_id: String) -> Result<()> {
        let now = vault42_contract::signing::now_unix();
        self.call(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE grants SET revoked_at=?2 WHERE id=?1 AND revoked_at IS NULL",
                    params![grant_id, now],
                )
                .map_err(|e| Error::Internal(e.into()))?;
            if changed == 0 {
                return Err(Error::NotFound);
            }
            Ok(())
        })
        .await
    }

    /// Remove an account from an organization, taking its derived memberships with it.
    ///
    /// One transaction, because a half-removed member is worse than either outcome: their team
    /// and group memberships and their published public key go with them, and their direct
    /// grants on the organization's projects are revoked. The cascades are the database's work
    /// — `team_members`, `group_members` and `member_pubkeys` all hang a composite foreign key
    /// off `org_members` — so the only thing this has to do by hand is the polymorphic grant
    /// column, which can carry no foreign key.
    pub async fn remove_org_member(&self, org_id: String, account_id: String) -> Result<()> {
        let now = vault42_contract::signing::now_unix();
        self.call(move |conn| {
            let tx = conn.transaction().map_err(|e| Error::Internal(e.into()))?;
            require_not_last_owner(&tx, &org_id, &account_id)?;
            revoke_user_grants_in_org(&tx, &org_id, &account_id, now)?;
            let changed = tx
                .execute(
                    "DELETE FROM org_members WHERE org_id=?1 AND account_id=?2",
                    params![org_id, account_id],
                )
                .map_err(|e| Error::Internal(e.into()))?;
            if changed == 0 {
                return Err(Error::NotFound);
            }
            tx.commit().map_err(|e| Error::Internal(e.into()))?;
            Ok(())
        })
        .await
    }

    /// Remove an account from a team. Their organization membership is untouched, so a grant
    /// held directly still reaches them; only the team's grants stop doing so.
    pub async fn remove_team_member(&self, team_id: String, account_id: String) -> Result<()> {
        self.delete_membership(
            "DELETE FROM team_members WHERE team_id=?1 AND account_id=?2",
            (team_id, account_id),
        )
        .await
    }

    /// Remove an account from a project group. Their organization membership is untouched.
    pub async fn remove_group_member(&self, group_id: String, account_id: String) -> Result<()> {
        self.delete_membership(
            "DELETE FROM group_members WHERE group_id=?1 AND account_id=?2",
            (group_id, account_id),
        )
        .await
    }

    /// Erase an account: every session, membership, public key and direct grant, and the
    /// credentials and address themselves. What remains is an opaque id with nothing personal
    /// attached to it.
    ///
    /// The row is emptied rather than dropped, and that is a decision rather than a shortcut.
    /// Five columns record who did something — who founded an organization, who sent and who
    /// accepted an invite, who granted a role, who last wrote a variable. Deleting the row would
    /// mean either destroying that history or reassigning it to somebody who did not do it, and
    /// for a vault the history of who granted access is part of what it is for. Emptying the row
    /// keeps the record truthful while leaving nothing of the person in it.
    ///
    /// Three independent things then stop the account being used: the address is replaced with a
    /// tombstone that `normalize_email` refuses to parse, so no login request can even name it;
    /// the password hash is replaced with a value no password verifies against; and the status is
    /// no longer active, which `login` checks before the password. Refused while the account is
    /// the last owner of any organization, which would strand it.
    pub async fn erase_account(&self, account_id: String) -> Result<()> {
        let now = vault42_contract::signing::now_unix();
        self.call(move |conn| {
            let tx = conn.transaction().map_err(|e| Error::Internal(e.into()))?;
            require_owner_nowhere(&tx, &account_id)?;
            revoke_all_user_grants(&tx, &account_id, now)?;
            revoke_pending_invites(&tx, &account_id)?;
            drop_all_memberships(&tx, &account_id)?;
            release_tenants(&tx, &account_id)?;
            if tombstone(&tx, &account_id)? == 0 {
                return Err(Error::NotFound);
            }
            tx.commit().map_err(|e| Error::Internal(e.into()))?;
            Ok(())
        })
        .await
    }

    /// Delete one membership row, reporting `NotFound` when there was nothing to remove so a
    /// caller can tell "already gone" from "never there".
    async fn delete_membership(&self, sql: &'static str, ids: (String, String)) -> Result<()> {
        self.call(move |conn| {
            let changed = conn
                .execute(sql, params![ids.0, ids.1])
                .map_err(|e| Error::Internal(e.into()))?;
            if changed == 0 {
                return Err(Error::NotFound);
            }
            Ok(())
        })
        .await
    }
}

/// Refuse removing the organization's only owner.
fn require_not_last_owner(
    conn: &rusqlite::Connection,
    org_id: &str,
    account_id: &str,
) -> Result<()> {
    let role: Option<String> = conn
        .query_row(
            "SELECT role FROM org_members WHERE org_id=?1 AND account_id=?2",
            params![org_id, account_id],
            |row| row.get(0),
        )
        .ok();
    if role.as_deref() != Some("owner") {
        return Ok(());
    }
    let owners: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM org_members WHERE org_id=?1 AND role='owner'",
            params![org_id],
            |row| row.get(0),
        )
        .map_err(|e| Error::Internal(e.into()))?;
    if owners <= 1 {
        return Err(Error::Conflict(
            "this is the organization's only owner; promote another owner first".into(),
        ));
    }
    Ok(())
}

/// Refuse deleting an account that is the last owner of any organization.
fn require_owner_nowhere(conn: &rusqlite::Connection, account_id: &str) -> Result<()> {
    let stranded: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM org_members mine
              WHERE mine.account_id=?1 AND mine.role='owner'
                AND (SELECT COUNT(*) FROM org_members peer
                      WHERE peer.org_id=mine.org_id AND peer.role='owner') <= 1",
            params![account_id],
            |row| row.get(0),
        )
        .map_err(|e| Error::Internal(e.into()))?;
    if stranded > 0 {
        return Err(Error::Conflict(
            "this account is the only owner of an organization; promote another owner first".into(),
        ));
    }
    Ok(())
}

/// Revoke the direct user grants this account holds on one organization's projects.
fn revoke_user_grants_in_org(
    conn: &rusqlite::Connection,
    org_id: &str,
    account_id: &str,
    now: i64,
) -> Result<()> {
    conn.execute(
        "UPDATE grants SET revoked_at=?3
          WHERE grantee_kind='user' AND grantee_id=?2 AND revoked_at IS NULL
            AND project_id IN (SELECT id FROM projects WHERE org_id=?1)",
        params![org_id, account_id, now],
    )
    .map_err(|e| Error::Internal(e.into()))?;
    Ok(())
}

/// Revoke every direct user grant this account holds, anywhere.
fn revoke_all_user_grants(conn: &rusqlite::Connection, account_id: &str, now: i64) -> Result<()> {
    conn.execute(
        "UPDATE grants SET revoked_at=?2
          WHERE grantee_kind='user' AND grantee_id=?1 AND revoked_at IS NULL",
        params![account_id, now],
    )
    .map_err(|e| Error::Internal(e.into()))?;
    Ok(())
}

/// Revoke the invitations this account sent and never saw accepted.
///
/// An invitation is a bearer token that grants membership. Leaving one live after its issuer is
/// gone means an address they chose can still join an organization nobody is now accountable for.
fn revoke_pending_invites(conn: &rusqlite::Connection, account_id: &str) -> Result<()> {
    conn.execute(
        "UPDATE invites SET status='revoked' WHERE invited_by=?1 AND status='pending'",
        params![account_id],
    )
    .map_err(|e| Error::Internal(e.into()))?;
    Ok(())
}

/// Release every tenant name the account claimed, so the name is free to claim again.
///
/// The row is DELETED rather than emptied, which is the opposite of what happens to the
/// account itself, and deliberately so: a tenant row records no history of who did what, it
/// is purely a live reservation on a name. Keeping it would preserve nothing and would leave
/// the name permanently unusable by anyone — the state 42ctl's `account delete` help had to
/// warn about, because a name outlived the only account that could ever present its key.
/// The schema's `ON DELETE SET NULL` does not cover this: the account row is tombstoned, not
/// deleted, so the cascade never fires.
fn release_tenants(conn: &rusqlite::Connection, account_id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM tenants WHERE account_id=?1",
        params![account_id],
    )
    .map_err(|e| Error::Internal(e.into()))?;
    Ok(())
}

/// Drop every organization membership, which cascades teams, groups and published keys.
fn drop_all_memberships(conn: &rusqlite::Connection, account_id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM org_members WHERE account_id=?1",
        params![account_id],
    )
    .map_err(|e| Error::Internal(e.into()))?;
    Ok(())
}

/// Replace the account's address and credentials with values nothing can present, returning how
/// many rows were changed so a caller can tell an unknown account from an erased one.
///
/// The tombstone address deliberately contains no `@`, so it fails email validation at the
/// request boundary and no login can name it, and it embeds the id so it stays unique.
fn tombstone(conn: &rusqlite::Connection, account_id: &str) -> Result<usize> {
    conn.execute(
        "UPDATE accounts
            SET email=?2, password_hash='erased', status='disabled', mfa_required=0
          WHERE id=?1 AND status='active'",
        params![account_id, format!("erased:{account_id}")],
    )
    .map_err(|e| Error::Internal(e.into()))
}
