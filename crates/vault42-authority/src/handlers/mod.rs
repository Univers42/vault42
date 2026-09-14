/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   mod.rs                                               :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Route handlers for the organization model.

pub mod environments;
pub mod github;
pub mod grants;
pub mod groups;
pub mod invites;
pub mod offboard;
pub mod orgs;
pub mod projects;
pub mod pubkeys;
pub mod secondfactor;
pub mod teams;
pub mod variables;

use crate::app::App;
use crate::auth::Principal;
use crate::error::{Error, Result};
use crate::rbac::OrgRole;

/// How long a fresh invite stays redeemable.
const INVITE_TTL_SECS: i64 = 7 * 86_400;

/// Resolve an organization reference and the caller's role in it.
///
/// A non-member gets `NotFound` rather than `Forbidden`: an outsider should not be able to
/// probe which organization slugs exist.
async fn org_context(
    app: &App,
    reference: String,
    caller: &Principal,
) -> Result<(String, OrgRole)> {
    let org_id = app
        .store
        .resolve_org(reference)
        .await?
        .ok_or(Error::NotFound)?;
    let role = app
        .store
        .org_role(org_id.clone(), caller.account_id.clone())
        .await?
        .ok_or(Error::NotFound)?;
    Ok((org_id, role))
}

/// Resolve an organization and refuse unless the caller may administer it.
///
/// The role travels back with the id because administering is not one privilege: a route
/// that hands out a standing still has to compare it to the caller's own.
async fn admin_context(
    app: &App,
    reference: String,
    caller: &Principal,
) -> Result<(String, OrgRole)> {
    let (org_id, role) = org_context(app, reference, caller).await?;
    role.require_admin()?;
    Ok((org_id, role))
}

/// Resolve a member reference — an account id or an email address — within the organization.
///
/// 42ctl documents every `--user` flag as "user id or email" and sends whichever the operator
/// typed. Stored verbatim, an address became a membership row matching no account: a team that
/// silently authorized nobody, a group that refused an actual member as "not a member of the
/// organization". One resolver for the team, group and removal routes, so a fourth route cannot
/// be written without it. Resolving within the organization keeps an address from being a lookup
/// oracle for accounts outside it.
///
/// On the removal routes it must run BEFORE any authorization check. `may_remove` and
/// `require_admin_unless_self` permit removing YOURSELF by comparing ids, so an address compared
/// against an id never matches, and a plain member typing their own email to leave would be
/// refused for lack of admin. Resolving first makes "leaving is always allowed" true for the
/// identifier people actually have.
async fn resolve_member(app: &App, org_id: &str, reference: String) -> Result<String> {
    let normalized =
        crate::validate::normalize_email(&reference).unwrap_or_else(|_| reference.clone());
    app.store
        .resolve_org_member(org_id.to_string(), normalized)
        .await?
        .ok_or_else(|| Error::BadRequest(format!("no member {reference:?} in this organization")))
}

/// Resolve a project reference and the caller's role in its organization.
///
/// Most project routes do not carry the organization in their path, so the project is what
/// establishes which organization to authorize against — found among the caller's own
/// organizations, since a slug is unique only inside one.
async fn project_context(
    app: &App,
    reference: String,
    caller: &Principal,
) -> Result<(String, String, OrgRole)> {
    let (project_id, org_id) = app
        .store
        .resolve_member_project(caller.account_id.clone(), reference)
        .await?
        .ok_or(Error::NotFound)?;
    let role = app
        .store
        .org_role(org_id.clone(), caller.account_id.clone())
        .await?
        .ok_or(Error::NotFound)?;
    Ok((project_id, org_id, role))
}

/// Resolve a project and refuse unless the caller may administer its organization.
async fn project_admin(
    app: &App,
    reference: String,
    caller: &Principal,
) -> Result<(String, String)> {
    let (project_id, org_id, role) = project_context(app, reference, caller).await?;
    role.require_admin()?;
    Ok((project_id, org_id))
}

/// Resolve an organization and a project from a path that names both.
///
/// The project is looked up INSIDE that organization. Authorizing against an organization the
/// caller administers while acting on a project of another is impossible by construction, and
/// a slug that another organization also uses resolves to this organization's project.
async fn org_project(
    app: &App,
    refs: (String, String),
    caller: &Principal,
) -> Result<(String, String, OrgRole)> {
    let (org_ref, project_ref) = refs;
    let (org_id, role) = org_context(app, org_ref, caller).await?;
    let project_id = app
        .store
        .resolve_project_in_org(org_id.clone(), project_ref)
        .await?
        .ok_or(Error::NotFound)?;
    Ok((project_id, org_id, role))
}

/// Refuse an id that is not a UUID.
///
/// Project ids must be parseable UUIDs because 42ctl derives an environment's scope id as
/// `blake3(project_uuid_bytes ‖ env_name)[..16]`. A non-UUID project id would have no
/// derivable scope and every env-secret operation on it would fail later, far from here.
fn check_uuid(value: &str, field: &str) -> Result<()> {
    if uuid::Uuid::parse_str(value).is_ok() {
        return Ok(());
    }
    Err(Error::BadRequest(format!("{field} must be a UUID")))
}

/// Reject a slug that would not be safe as an identifier.
///
/// Reuses the tenant rule from `vault42-contract` rather than restating it: both end up as
/// user-visible identifiers in the same system.
fn check_slug(slug: &str, field: &str) -> Result<()> {
    if vault42_contract::validate::valid_tenant(slug) {
        return Ok(());
    }
    Err(Error::BadRequest(format!(
        "{field} must be 1..=64 characters of [A-Za-z0-9_-]"
    )))
}
