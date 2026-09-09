/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   guard.rs                                             :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The bearer-token request guard.
//!
//! Extracting `Principal` is the whole authorization check for an authenticated route:
//! a handler that takes one cannot be reached without a live session, so there is no way
//! to forget the check by omitting a line inside the handler body.

use crate::app::App;
use crate::auth::{session, Principal};
use crate::error::Error;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use std::sync::Arc;

#[axum::async_trait]
impl FromRequestParts<Arc<App>> for Principal {
    type Rejection = Error;

    /// Resolve the `Authorization: Bearer` token to its principal, or reject as 401.
    async fn from_request_parts(
        parts: &mut Parts,
        app: &Arc<App>,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer(parts).ok_or(Error::Unauthorized)?;
        let principal = app
            .store
            .session_principal(
                session::hash_token(&token),
                vault42_contract::signing::now_unix(),
            )
            .await?;
        principal.ok_or(Error::Unauthorized)
    }
}

/// Pull the token out of an `Authorization: Bearer <token>` header.
///
/// The scheme match is case-insensitive per RFC 7235; anything else yields `None`, which
/// the caller turns into a 401 without saying which part was wrong.
fn bearer(parts: &Parts) -> Option<String> {
    let raw = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let (scheme, token) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    Some(token.to_string())
}
