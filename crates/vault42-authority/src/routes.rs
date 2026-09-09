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
use crate::handlers::{
    environments, grants, groups, invites, offboard, orgs, projects, pubkeys, secondfactor, teams,
    variables,
};
use axum::routing::{delete, get, post};
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
        .merge(project_routes())
        .merge(grant_routes())
        .merge(variable_routes())
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
        .route("/v1/auth/account", delete(offboard::account))
        .route("/v1/auth/otp/request", post(secondfactor::request))
        .route("/v1/auth/otp/verify", post(secondfactor::verify))
        .route(
            "/v1/auth/escrow",
            axum::routing::put(secondfactor::escrow_put),
        )
        .route("/v1/auth/escrow/fetch", post(secondfactor::escrow_fetch))
        .route("/v1/auth/mfa", post(secondfactor::set_mfa))
}

/// Organization and team routes.
fn org_routes() -> Router<Arc<App>> {
    Router::new()
        .route("/v1/orgs", post(orgs::create))
        .route("/v1/orgs/:org", get(orgs::show))
        .route("/v1/orgs/:org/members", get(orgs::members))
        .route("/v1/orgs/:org/members/:user", delete(offboard::org_member))
        .route("/v1/orgs/:org/invites", post(orgs::invite))
        .route("/v1/orgs/:org/teams", post(teams::create).get(teams::list))
        .route("/v1/orgs/:org/teams/:team/members", post(teams::add_member))
        .route(
            "/v1/orgs/:org/teams/:team/members/:user",
            delete(offboard::team_member),
        )
        .route("/v1/orgs/:org/teams/:team/invites", post(teams::invite))
}

/// Projects, environments, groups, and member public keys.
fn project_routes() -> Router<Arc<App>> {
    Router::new()
        .route(
            "/v1/orgs/:org/projects",
            post(projects::create).get(projects::list),
        )
        .route(
            "/v1/projects/:project/environments",
            post(environments::create).get(environments::list),
        )
        .route(
            "/v1/projects/:project/environments/:env/scopekey",
            axum::routing::put(environments::set_scope_key),
        )
        .route("/v1/projects/:project/groups", post(groups::create))
        .route("/v1/groups/:group/members", post(groups::add_member))
        .route(
            "/v1/groups/:group/members/:user",
            delete(offboard::group_member),
        )
        .route("/v1/groups/:group/invites", post(groups::invite))
        .route(
            "/v1/orgs/:org/pubkey",
            axum::routing::put(pubkeys::put_self),
        )
        .route("/v1/orgs/:org/users/:user/pubkey", get(pubkeys::get_member))
}

/// Project grants and their scope-key wraps.
fn grant_routes() -> Router<Arc<App>> {
    Router::new()
        .route(
            "/v1/orgs/:org/projects/:project/grants",
            post(grants::create).get(grants::list),
        )
        .route(
            "/v1/orgs/:org/projects/:project/grants/:grant/fulfilled",
            get(grants::fulfilled),
        )
        .route(
            "/v1/orgs/:org/projects/:project/grants/:grant/wraps",
            post(grants::add_wrap),
        )
        .route(
            "/v1/orgs/:org/projects/:project/grants/:grant",
            delete(offboard::grant),
        )
}

/// Variables at the three scope levels, plus the resolved view.
fn variable_routes() -> Router<Arc<App>> {
    Router::new()
        .route("/v1/orgs/:org/variables", get(variables::org_list))
        .route(
            "/v1/orgs/:org/variables/:key",
            axum::routing::put(variables::org_put).delete(variables::org_delete),
        )
        .route(
            "/v1/projects/:project/variables",
            get(variables::project_list),
        )
        .route(
            "/v1/projects/:project/variables/:key",
            axum::routing::put(variables::project_put).delete(variables::project_delete),
        )
        .route(
            "/v1/projects/:project/environments/:env/variables",
            get(variables::env_list),
        )
        .route(
            "/v1/projects/:project/environments/:env/variables/:key",
            axum::routing::put(variables::env_put).delete(variables::env_delete),
        )
        .route(
            "/v1/projects/:project/environments/:env/resolve",
            get(variables::resolve),
        )
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
