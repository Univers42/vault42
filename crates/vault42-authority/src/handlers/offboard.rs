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

//! Offboarding routes: the DELETE half of the organization model.
//!
//! Every response here carries the same warning, and it is not boilerplate. Removing somebody
//! stops them being re-wrapped; it does not reach the scope keys they already hold, which live
//! wrapped to their own key in vault42 where the authority cannot touch them. Access to
//! existing secrets ends at the next `rotate-scope`. An operator who believes a removal alone
//! locked somebody out has been misled at the moment it matters most, so the API says so.
//!
//! Who may remove whom follows the role hierarchy rather than a flat admin check. Leaving is
//! always allowed. Removing somebody else requires administering the organization. Unseating an
//! owner or an admin requires being an owner, because otherwise an admin could remove every
//! owner and inherit the organization. An organization's last owner cannot be removed at all —
//! that is enforced in the store, where every path that could do it converges.

use super::{org_context, org_project};
use crate::app::App;
use crate::auth::Principal;
use crate::error::{Error, Result};
use crate::rbac::OrgRole;
use axum::extract::{Path, State};
use axum::Json;
use serde::Serialize;
use std::sync::Arc;

/// What a removal actually achieved, and what it did not.
#[derive(Serialize)]
pub struct RemovedResp {
    removed: bool,
    rotate_required: bool,
    detail: &'static str,
}

/// The one honest answer for every removal on this surface.
fn removed() -> Json<RemovedResp> {
    Json(RemovedResp {
        removed: true,
        rotate_required: true,
        detail: "authorization removed; scope keys already held remain readable until the \
                 environment is rotated — run `vault rotate-scope` for each environment",
    })
}

/// Remove an account from an organization, with its teams, groups, public key and direct
/// grants. Administrators, or the member themselves.
pub async fn org_member(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path((org, user)): Path<(String, String)>,
) -> Result<Json<RemovedResp>> {
    let (org_id, role) = org_context(&app, org, &caller).await?;
    let user = resolve_member(&app, &org_id, user).await?;
    let target = app
        .store
        .org_role(org_id.clone(), user.clone())
        .await?
        .ok_or(Error::NotFound)?;
    may_remove((&caller.account_id, role), (&user, target))?;
    app.store.remove_org_member(org_id, user).await?;
    Ok(removed())
}

/// Remove an account from a team. Organization administrators, or the member themselves.
pub async fn team_member(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path((org, team, user)): Path<(String, String, String)>,
) -> Result<Json<RemovedResp>> {
    let (org_id, role) = org_context(&app, org, &caller).await?;
    let user = resolve_member(&app, &org_id, user).await?;
    require_admin_unless_self(&caller.account_id, role, &user)?;
    let team_id = app
        .store
        .resolve_team(org_id, team)
        .await?
        .ok_or(Error::NotFound)?;
    app.store.remove_team_member(team_id, user).await?;
    Ok(removed())
}

/// Remove an account from a project group. Organization administrators, or the member
/// themselves.
pub async fn group_member(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path((group, user)): Path<(String, String)>,
) -> Result<Json<RemovedResp>> {
    let (_, org_id) = app
        .store
        .resolve_group(group.clone())
        .await?
        .ok_or(Error::NotFound)?;
    let role = app
        .store
        .org_role(org_id.clone(), caller.account_id.clone())
        .await?
        .ok_or(Error::NotFound)?;
    let user = resolve_member(&app, &org_id, user).await?;
    require_admin_unless_self(&caller.account_id, role, &user)?;
    app.store.remove_group_member(group, user).await?;
    Ok(removed())
}

/// Revoke a grant. Administrators only — a grant can cover a team, so there is no self to
/// appeal to.
pub async fn grant(
    State(app): State<Arc<App>>,
    caller: Principal,
    Path((org, project, grant)): Path<(String, String, String)>,
) -> Result<Json<RemovedResp>> {
    let (project_id, _, role) = org_project(&app, (org, project), &caller).await?;
    role.require_admin()?;
    let owner = app
        .store
        .grant_project(grant.clone())
        .await?
        .ok_or(Error::NotFound)?;
    if owner != project_id {
        return Err(Error::NotFound);
    }
    app.store.revoke_grant(grant).await?;
    Ok(removed())
}

/// Erase the caller's own account: every session, membership, public key and direct grant, and
/// the credentials and address themselves. What remains is an opaque id, so the record of who
/// granted whom access stays truthful without holding anything personal.
///
/// Self only. An account is global while an organization is not, so no organization
/// administrator is entitled to erase one; removing somebody from the organization is the
/// operation an administrator has. Refused while the caller is the last owner of any
/// organization, which would strand it.
pub async fn account(State(app): State<Arc<App>>, caller: Principal) -> Result<Json<RemovedResp>> {
    app.store.erase_account(caller.account_id).await?;
    Ok(removed())
}

/// Resolve a member reference (account id or email) within the organization.
///
/// Resolution happens BEFORE every authorization check on this surface, and the order is the
/// whole point: `may_remove` and `require_admin_unless_self` both permit removing YOURSELF by
/// comparing ids, so an address compared against an id never matches and a plain member typing
/// their own email to leave would be refused for lack of admin. Resolving first makes "leaving
/// is always allowed" true for the identifier people actually have.
///
/// Scoped to this organization's membership, so it answers nothing about addresses outside it.
async fn resolve_member(app: &App, org_id: &str, reference: String) -> Result<String> {
    let normalized =
        crate::validate::normalize_email(&reference).unwrap_or_else(|_| reference.clone());
    app.store
        .resolve_org_member(org_id.to_string(), normalized)
        .await?
        .ok_or_else(|| Error::BadRequest(format!("no member {reference:?} in this organization")))
}

/// Whether `caller` may remove `target` from an organization.
///
/// Leaving is always allowed, so nobody can be trapped in an organization. Removing anyone else
/// requires administering it. Unseating an owner or an admin requires being an owner: without
/// that rule an admin could remove every owner and inherit the organization.
fn may_remove(caller: (&str, OrgRole), target: (&str, OrgRole)) -> Result<()> {
    if caller.0 == target.0 {
        return Ok(());
    }
    caller.1.require_admin()?;
    if target.1.can_administer() && !matches!(caller.1, OrgRole::Owner) {
        return Err(Error::Forbidden);
    }
    Ok(())
}

/// Require organization administration unless the caller is removing themselves.
fn require_admin_unless_self(caller_id: &str, role: OrgRole, target: &str) -> Result<()> {
    if caller_id == target {
        return Ok(());
    }
    role.require_admin()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Leaving is always allowed, at every role, so nobody is trapped in an organization.
    #[test]
    fn anybody_may_remove_themselves() {
        for role in [OrgRole::Owner, OrgRole::Admin, OrgRole::Member] {
            may_remove(("me", role), ("me", role)).expect("leaving is always allowed");
            require_admin_unless_self("me", role, "me").expect("leaving a team is allowed");
        }
    }

    /// A plain member cannot remove anybody else, at any target role.
    #[test]
    fn a_plain_member_cannot_remove_anybody_else() {
        for target in [OrgRole::Owner, OrgRole::Admin, OrgRole::Member] {
            assert!(may_remove(("me", OrgRole::Member), ("them", target)).is_err());
        }
        assert!(require_admin_unless_self("me", OrgRole::Member, "them").is_err());
    }

    /// An admin removes plain members but cannot unseat an owner or another admin: otherwise
    /// one admin could remove every owner and inherit the organization.
    #[test]
    fn an_admin_cannot_unseat_an_administrator() {
        may_remove(("me", OrgRole::Admin), ("them", OrgRole::Member)).expect("members are fair");
        for target in [OrgRole::Owner, OrgRole::Admin] {
            assert!(
                may_remove(("me", OrgRole::Admin), ("them", target)).is_err(),
                "an admin must not unseat an administrator"
            );
        }
    }

    /// An owner may remove anybody, including another owner — the store still refuses the last.
    #[test]
    fn an_owner_may_remove_any_role() {
        for target in [OrgRole::Owner, OrgRole::Admin, OrgRole::Member] {
            may_remove(("me", OrgRole::Owner), ("them", target)).expect("an owner may remove");
        }
    }
}
