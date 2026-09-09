/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   rbac.rs                                              :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Roles and the permission checks over them.
//!
//! Roles are a closed set enforced by a `CHECK` constraint in the schema and parsed here,
//! rather than the opaque strings the existing client forwards. A typo therefore fails
//! loudly at the boundary instead of being stored and silently never matching.
//!
//! Only `Owner` and `Admin` may administer an organization. That single rule is what makes
//! "an administrator can invite people" true, and it is checked in one place so a new
//! route cannot forget it.

use crate::error::{Error, Result};

/// A member's standing in an organization, most privileged first.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OrgRole {
    Owner,
    Admin,
    Member,
}

/// A member's standing in a team.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TeamRole {
    Admin,
    Member,
}

impl OrgRole {
    /// Parse a wire role, refusing anything outside the closed set.
    pub fn parse(raw: &str) -> Result<Self> {
        match raw {
            "owner" => Ok(Self::Owner),
            "admin" => Ok(Self::Admin),
            "member" => Ok(Self::Member),
            other => Err(Error::BadRequest(format!(
                "role must be owner, admin or member; got {other:?}"
            ))),
        }
    }

    /// The stored form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
        }
    }

    /// True when this role may invite, add members, and create teams.
    pub fn can_administer(self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }

    /// Refuse unless this role may administer the organization.
    pub fn require_admin(self) -> Result<Self> {
        if self.can_administer() {
            return Ok(self);
        }
        Err(Error::Forbidden)
    }
}

impl TeamRole {
    /// Parse a wire team role, refusing anything outside the closed set.
    pub fn parse(raw: &str) -> Result<Self> {
        match raw {
            "admin" => Ok(Self::Admin),
            "member" => Ok(Self::Member),
            other => Err(Error::BadRequest(format!(
                "team_role must be admin or member; got {other:?}"
            ))),
        }
    }

    /// The stored form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Member => "member",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn org_roles_round_trip_and_reject_junk() {
        for role in [OrgRole::Owner, OrgRole::Admin, OrgRole::Member] {
            assert_eq!(OrgRole::parse(role.as_str()).unwrap(), role);
        }
        assert!(
            OrgRole::parse("Owner").is_err(),
            "case must not be accepted"
        );
        assert!(OrgRole::parse("root").is_err());
        assert!(OrgRole::parse("").is_err());
    }

    #[test]
    fn only_owner_and_admin_administer() {
        assert!(OrgRole::Owner.can_administer());
        assert!(OrgRole::Admin.can_administer());
        assert!(!OrgRole::Member.can_administer());
        assert!(OrgRole::Member.require_admin().is_err());
        assert!(OrgRole::Admin.require_admin().is_ok());
    }

    #[test]
    fn team_roles_round_trip_and_reject_junk() {
        for role in [TeamRole::Admin, TeamRole::Member] {
            assert_eq!(TeamRole::parse(role.as_str()).unwrap(), role);
        }
        assert!(
            TeamRole::parse("owner").is_err(),
            "owner is an org role, not a team role"
        );
        assert!(TeamRole::parse("").is_err());
    }
}
