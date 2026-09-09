/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   invites.rs                                           :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The invite ledger.
//!
//! Accepting an invite and being enrolled by it happen in one transaction. Split apart,
//! a crash between them would leave an invite marked used with no membership to show for
//! it, and the token could not be presented again.
//!
//! An invite is bound to the address it was issued to: holding the token is not enough,
//! the accepting account's email must match. The token is the secret, but binding the
//! address means an intercepted token is still useless to anyone else.

use super::{is_constraint_violation, Store};
use crate::error::{Error, Result};
use rusqlite::params;

/// An invite to issue.
pub struct NewInvite {
    pub id: String,
    pub token_hash: String,
    pub scope_kind: String,
    pub scope_id: String,
    pub email: String,
    pub role: String,
    pub invited_by: String,
    pub expires_at: i64,
}

/// An invite as the API reports it.
pub struct InviteRow {
    pub id: String,
    pub scope_kind: String,
    pub scope_id: String,
    pub email: String,
    pub role: String,
    pub status: String,
    pub expires_at: i64,
}

/// What a caller presents to redeem an invite.
pub struct Acceptance {
    pub token_hash: String,
    pub account_id: String,
    pub email: String,
    pub now: i64,
}

/// What redeeming an invite granted.
pub struct Accepted {
    pub scope_kind: String,
    pub scope_id: String,
    pub role: String,
}

impl Store {
    /// Record a new invite.
    pub async fn issue_invite(&self, new: NewInvite) -> Result<()> {
        let now = new.expires_at;
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO invites(id, token_hash, scope_kind, scope_id, email, role,
                                     invited_by, created_at, expires_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    new.id,
                    new.token_hash,
                    new.scope_kind,
                    new.scope_id,
                    new.email,
                    new.role,
                    new.invited_by,
                    vault42_contract::signing::now_unix(),
                    now
                ],
            )
            .map_err(|error| {
                if is_constraint_violation(&error) {
                    Error::Internal(anyhow::anyhow!("invite token collision"))
                } else {
                    Error::Internal(error.into())
                }
            })?;
            Ok(())
        })
        .await
    }

    /// Look up an invite by id. Never returns its token.
    pub async fn invite_by_id(&self, id: String) -> Result<Option<InviteRow>> {
        self.call(move |conn| {
            let found = conn.query_row(
                "SELECT id, scope_kind, scope_id, email, role, status, expires_at
                   FROM invites WHERE id=?1",
                params![id],
                read_invite,
            );
            match found {
                Ok(row) => Ok(Some(row)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(error) => Err(Error::Internal(error.into())),
            }
        })
        .await
    }

    /// Redeem an invite and enrol the caller, atomically.
    pub async fn accept_invite(&self, acceptance: Acceptance) -> Result<Accepted> {
        self.call(move |conn| {
            let tx = conn.transaction().map_err(|e| Error::Internal(e.into()))?;
            let invite = load_pending(&tx, &acceptance)?;
            enrol(&tx, &invite, &acceptance)?;
            mark_accepted(&tx, &invite.id, &acceptance)?;
            tx.commit().map_err(|e| Error::Internal(e.into()))?;
            Ok(Accepted {
                scope_kind: invite.scope_kind,
                scope_id: invite.scope_id,
                role: invite.role,
            })
        })
        .await
    }
}

/// Map a row onto an `InviteRow`.
fn read_invite(row: &rusqlite::Row<'_>) -> rusqlite::Result<InviteRow> {
    Ok(InviteRow {
        id: row.get(0)?,
        scope_kind: row.get(1)?,
        scope_id: row.get(2)?,
        email: row.get(3)?,
        role: row.get(4)?,
        status: row.get(5)?,
        expires_at: row.get(6)?,
    })
}

/// Fetch the invite for this token and refuse it unless it is redeemable now.
fn load_pending(tx: &rusqlite::Transaction<'_>, acceptance: &Acceptance) -> Result<InviteRow> {
    let found = tx.query_row(
        "SELECT id, scope_kind, scope_id, email, role, status, expires_at
           FROM invites WHERE token_hash=?1",
        params![acceptance.token_hash],
        read_invite,
    );
    let invite = match found {
        Ok(invite) => invite,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Err(Error::NotFound),
        Err(error) => return Err(Error::Internal(error.into())),
    };
    if invite.status != "pending" {
        return Err(Error::Conflict(format!("invite already {}", invite.status)));
    }
    if invite.expires_at <= acceptance.now {
        return Err(Error::Conflict("invite has expired".into()));
    }
    if invite.email != acceptance.email {
        return Err(Error::Forbidden);
    }
    Ok(invite)
}

/// Grant the membership the invite promises.
fn enrol(
    tx: &rusqlite::Transaction<'_>,
    invite: &InviteRow,
    acceptance: &Acceptance,
) -> Result<()> {
    match invite.scope_kind.as_str() {
        "org" => enrol_in_org(tx, invite, acceptance),
        "team" => enrol_in_team(tx, invite, acceptance),
        "group" => enrol_in_group(tx, invite, acceptance),
        other => Err(Error::BadRequest(format!(
            "invites of kind {other:?} cannot be accepted yet"
        ))),
    }
}

/// Add the caller to the invited organization.
fn enrol_in_org(
    tx: &rusqlite::Transaction<'_>,
    invite: &InviteRow,
    acceptance: &Acceptance,
) -> Result<()> {
    tx.execute(
        "INSERT OR IGNORE INTO org_members(org_id, account_id, role, created_at)
         VALUES(?1,?2,?3,?4)",
        params![
            invite.scope_id,
            acceptance.account_id,
            invite.role,
            acceptance.now
        ],
    )
    .map_err(|e| Error::Internal(e.into()))?;
    Ok(())
}

/// Add the caller to the invited team, which requires existing organization membership.
fn enrol_in_team(
    tx: &rusqlite::Transaction<'_>,
    invite: &InviteRow,
    acceptance: &Acceptance,
) -> Result<()> {
    let org_id: String = tx
        .query_row(
            "SELECT org_id FROM teams WHERE id=?1",
            params![invite.scope_id],
            |row| row.get(0),
        )
        .map_err(|_| Error::NotFound)?;
    tx.execute(
        "INSERT INTO team_members(team_id, org_id, account_id, team_role, created_at)
         VALUES(?1,?2,?3,?4,?5)
         ON CONFLICT(team_id, account_id) DO UPDATE SET team_role=excluded.team_role",
        params![
            invite.scope_id,
            org_id,
            acceptance.account_id,
            invite.role,
            acceptance.now
        ],
    )
    .map_err(|error| {
        if is_constraint_violation(&error) {
            Error::BadRequest(
                "accept the organization invite first; a team member must belong to the organization"
                    .into(),
            )
        } else {
            Error::Internal(error.into())
        }
    })?;
    Ok(())
}

/// Add the caller to the invited group, which requires organization membership.
fn enrol_in_group(
    tx: &rusqlite::Transaction<'_>,
    invite: &InviteRow,
    acceptance: &Acceptance,
) -> Result<()> {
    let org_id: String = tx
        .query_row(
            "SELECT p.org_id FROM groups g JOIN projects p ON p.id = g.project_id WHERE g.id=?1",
            params![invite.scope_id],
            |row| row.get(0),
        )
        .map_err(|_| Error::NotFound)?;
    let member: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM org_members WHERE org_id=?1 AND account_id=?2",
            params![org_id, acceptance.account_id],
            |row| row.get(0),
        )
        .map_err(|e| Error::Internal(e.into()))?;
    if member == 0 {
        return Err(Error::BadRequest(
            "accept the organization invite first; a group member must belong to the organization"
                .into(),
        ));
    }
    tx.execute(
        "INSERT OR IGNORE INTO group_members(group_id, account_id, created_at) VALUES(?1,?2,?3)",
        params![invite.scope_id, acceptance.account_id, acceptance.now],
    )
    .map_err(|e| Error::Internal(e.into()))?;
    Ok(())
}

/// Mark the invite used so it cannot be redeemed twice.
fn mark_accepted(tx: &rusqlite::Transaction<'_>, id: &str, acceptance: &Acceptance) -> Result<()> {
    tx.execute(
        "UPDATE invites SET status='accepted', accepted_at=?2, accepted_by=?3
          WHERE id=?1 AND status='pending'",
        params![id, acceptance.now, acceptance.account_id],
    )
    .map_err(|e| Error::Internal(e.into()))?;
    Ok(())
}
