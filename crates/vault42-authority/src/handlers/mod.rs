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

pub mod invites;
pub mod orgs;
pub mod teams;

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
