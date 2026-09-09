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
async fn admin_context(app: &App, reference: String, caller: &Principal) -> Result<String> {
    let (org_id, role) = org_context(app, reference, caller).await?;
    role.require_admin()?;
    Ok(org_id)
}

/// Resolve a project reference and the caller's role in its organization.
///
/// Most project routes do not carry the organization in their path, so the project is what
/// establishes which organization to authorize against.
async fn project_context(
    app: &App,
    reference: String,
    caller: &Principal,
) -> Result<(String, String, OrgRole)> {
    let (project_id, org_id) = app
        .store
        .resolve_project(reference)
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

/// Resolve an organization and a project from a path that names both, and check they agree.
///
/// Without the agreement check a caller could authorize against an organization they
/// administer while acting on a project belonging to a different one, since the project
/// reference alone decides what is modified.
async fn org_project(
    app: &App,
    refs: (String, String),
    caller: &Principal,
) -> Result<(String, String, OrgRole)> {
    let (org_ref, project_ref) = refs;
    let (org_id, role) = org_context(app, org_ref, caller).await?;
    let (project_id, project_org) = app
        .store
        .resolve_project(project_ref)
        .await?
        .ok_or(Error::NotFound)?;
    if project_org != org_id {
        return Err(Error::NotFound);
    }
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
