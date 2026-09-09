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

//! Account authentication: password hashing, session tokens, and the request guard.

pub mod guard;
pub mod handlers;
pub mod password;
pub mod session;

/// Who is making a request, resolved from a bearer token.
///
/// `account_id` is the canonical user id: it is what `/v1/orgs/{org}/members` returns,
/// what a grant names, and what appears in `fulfilled.missing`. 42ctl reads the same
/// value from a session's `sub` claim, so these must never diverge.
#[derive(Clone)]
pub struct Principal {
    pub account_id: String,
    pub email: String,
    pub mfa_required: bool,
    pub token_hash: String,
}
