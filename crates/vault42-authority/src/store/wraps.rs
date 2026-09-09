/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   grants.rs                                            :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */
//! Scope-key wrap bookkeeping: who a grant authorizes, and which of them hold the key.
//!
//! A wrap is meaningful only against one environment at one epoch, because the scope key it
//! wraps belongs to one environment and is replaced at every rotation. Answering without both
//! coordinates reports a member as provisioned in an environment they cannot read, or at an
//! epoch that no longer exists.
//!
//! `missing` is a provisioning worklist and nothing more. It is deliberately NOT the
//! authorized-member set: the two coincide only until the first member is provisioned, and a
//! caller that needs everyone the grant authorizes — rotation does — must read `members`.

use super::Store;
use crate::error::{Error, Result};
use rusqlite::params;

/// The environment scope a wrap is bound to. A scope key belongs to one environment and is
/// replaced at each rotation, so a wrap without both coordinates describes nothing.
pub struct WrapScope {
    pub env_id: String,
    pub epoch: i64,
}

/// Who a grant authorizes, and which of them still need a wrap for one `WrapScope`.
pub struct GrantFulfilment {
    pub members: Vec<String>,
    pub missing: Vec<String>,
}

impl Store {
    /// Everyone a grant authorizes, plus those of them still lacking a wrap for `scope`.
    ///
    /// Both halves come from one connection so they describe the same instant: a caller that
    /// read them separately could re-wrap against a member list that changed in between.
    pub async fn grant_fulfilment(
        &self,
        grant_id: String,
        scope: WrapScope,
    ) -> Result<GrantFulfilment> {
        self.call(move |conn| {
            check_wrap_env(conn, &grant_id, &scope.env_id)?;
            let members = authorized_members(conn, &grant_id)?;
            let mut missing = Vec::new();
            for account_id in &members {
                if !has_wrap(conn, &grant_id, account_id, &scope)? {
                    missing.push(account_id.clone());
                }
            }
            Ok(GrantFulfilment { members, missing })
        })
        .await
    }

    /// Record that a scope-key wrap now exists for an authorized member at one `WrapScope`.
    ///
    /// Refuses an account the grant does not authorize: `missing` is computed against the
    /// same set, so admitting an outsider here would make the bookkeeping describe access
    /// nobody granted. Refuses likewise an environment the grant does not cover.
    pub async fn add_grant_wrap(
        &self,
        grant_id: String,
        account_id: String,
        scope: WrapScope,
    ) -> Result<()> {
        let now = vault42_contract::signing::now_unix();
        self.call(move |conn| {
            check_wrap_env(conn, &grant_id, &scope.env_id)?;
            let authorized = authorized_members(conn, &grant_id)?;
            if !authorized.iter().any(|member| member == &account_id) {
                return Err(Error::BadRequest(
                    "account is not authorized by this grant".into(),
                ));
            }
            conn.execute(
                "INSERT OR IGNORE INTO
                   grant_wraps(grant_id, account_id, env_id, epoch, created_at)
                 VALUES(?1,?2,?3,?4,?5)",
                params![grant_id, account_id, scope.env_id, scope.epoch, now],
            )
            .map_err(|e| Error::Internal(e.into()))?;
            Ok(())
        })
        .await
    }
}

/// Refuse an environment the grant does not cover.
///
/// The environment must belong to the grant's project, and an env-scoped grant covers only
/// its own environment. Without this a wrap recorded against an unrelated environment would
/// make that environment's `missing` list omit a member who was never provisioned there.
fn check_wrap_env(conn: &rusqlite::Connection, grant_id: &str, env_id: &str) -> Result<()> {
    let scoped_to: Option<String> = conn
        .query_row(
            "SELECT g.env_id FROM grants g
               JOIN environments e ON e.project_id = g.project_id
              WHERE g.id=?1 AND g.revoked_at IS NULL AND e.id=?2",
            params![grant_id, env_id],
            |row| row.get(0),
        )
        .map_err(|_| Error::NotFound)?;
    match scoped_to {
        Some(only) if only != env_id => Err(Error::NotFound),
        _ => Ok(()),
    }
}

/// Every account the grant authorizes: the named user, or the team's current membership —
/// in both cases only while they still belong to the project's organization.
///
/// The organization join is what makes offboarding real for a direct user grant. `grantee_id`
/// is polymorphic (a user or a team) so it carries no foreign key, which meant a grant kept
/// naming somebody after they were removed from the organization, and rotation re-wrapped the
/// scope key straight back to them. Resolving membership here rather than at removal time
/// means no removal path can forget it, and re-adding somebody later does not silently
/// resurrect a grant they used to hold. Team grants get the same guarantee from
/// `team_members`, whose composite foreign key cascades on removal.
fn authorized_members(conn: &rusqlite::Connection, grant_id: &str) -> Result<Vec<String>> {
    let (kind, grantee): (String, String) = conn
        .query_row(
            "SELECT grantee_kind, grantee_id FROM grants WHERE id=?1 AND revoked_at IS NULL",
            params![grant_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| Error::NotFound)?;
    if kind == "user" {
        return granted_user_if_still_a_member(conn, grant_id, &grantee);
    }
    collect_accounts(
        conn,
        "SELECT account_id FROM team_members WHERE team_id=?1 ORDER BY account_id",
        &grantee,
    )
}

/// The user a direct grant names, but only while they still belong to the project's
/// organization — an empty result once they have been removed.
fn granted_user_if_still_a_member(
    conn: &rusqlite::Connection,
    grant_id: &str,
    grantee: &str,
) -> Result<Vec<String>> {
    let mut stmt = conn
        .prepare(
            "SELECT om.account_id FROM grants g
               JOIN projects p ON p.id = g.project_id
               JOIN org_members om ON om.org_id = p.org_id AND om.account_id = ?2
              WHERE g.id = ?1",
        )
        .map_err(|e| Error::Internal(e.into()))?;
    let rows = stmt
        .query_map(params![grant_id, grantee], |row| row.get::<_, String>(0))
        .map_err(|e| Error::Internal(e.into()))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| Error::Internal(e.into()))
}

/// Run a single-column, single-parameter account query and collect the ids.
fn collect_accounts(
    conn: &rusqlite::Connection,
    sql: &str,
    parameter: &str,
) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(sql).map_err(|e| Error::Internal(e.into()))?;
    let rows = stmt
        .query_map(params![parameter], |row| row.get::<_, String>(0))
        .map_err(|e| Error::Internal(e.into()))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| Error::Internal(e.into()))
}

/// True when a wrap already exists for this grant and account at `scope`.
fn has_wrap(
    conn: &rusqlite::Connection,
    grant_id: &str,
    account_id: &str,
    scope: &WrapScope,
) -> Result<bool> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM grant_wraps
              WHERE grant_id=?1 AND account_id=?2 AND env_id=?3 AND epoch=?4",
            params![grant_id, account_id, scope.env_id, scope.epoch],
            |row| row.get(0),
        )
        .map_err(|e| Error::Internal(e.into()))?;
    Ok(count > 0)
}
