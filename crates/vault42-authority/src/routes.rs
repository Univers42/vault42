/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   routes.rs                                            :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The authority's route table.
//!
//! Paths are fixed by the client that already speaks them: `42ctl` sends these exact routes
//! today, so the table is a contract to satisfy rather than a design choice. A handler
//! taking `Principal` is authenticated by construction; the rest are open.
//!
//! Both `/v1/invites/accept` and `/v1/orgs/invites/accept` exist because the client uses
//! both. They resolve to one handler, so there is one implementation of redemption.

use crate::app::App;
use crate::auth::handlers as auth;
use crate::contract;
use crate::handlers::{invites, orgs, teams};
use axum::routing::{get, post};
use axum::Router;
use std::sync::Arc;

/// Build the router over the shared application state.
pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/contract-key", get(contract::contract_key))
        .route("/v1/register", post(contract::register))
        .merge(auth_routes())
        .merge(org_routes())
        .merge(invite_routes())
        .with_state(app)
}

/// Account routes.
fn auth_routes() -> Router<Arc<App>> {
    Router::new()
        .route("/v1/auth/signup", post(auth::signup))
        .route("/v1/auth/login", post(auth::login))
        .route("/v1/auth/logout", post(auth::logout))
        .route("/v1/auth/me", get(auth::me))
        .route("/v1/auth/passwd", post(auth::passwd))
}

/// Organization and team routes.
fn org_routes() -> Router<Arc<App>> {
    Router::new()
        .route("/v1/orgs", post(orgs::create))
        .route("/v1/orgs/:org/members", get(orgs::members))
        .route("/v1/orgs/:org/invites", post(orgs::invite))
        .route("/v1/orgs/:org/teams", post(teams::create).get(teams::list))
        .route("/v1/orgs/:org/teams/:team/members", post(teams::add_member))
        .route("/v1/orgs/:org/teams/:team/invites", post(teams::invite))
}

/// Invite redemption and lookup.
fn invite_routes() -> Router<Arc<App>> {
    Router::new()
        .route("/v1/orgs/invites/accept", post(invites::accept))
        .route("/v1/invites/accept", post(invites::accept))
        .route("/v1/invites/:id", get(invites::show))
}

/// Liveness probe for the fly health check.
async fn healthz() -> &'static str {
    "ok"
}
