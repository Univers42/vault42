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
//! Paths are fixed by the client that already speaks them: `42ctl` sends these exact
//! routes today, so the table is a contract to satisfy rather than a design choice. A
//! handler taking `Principal` is authenticated by construction; the rest are open.

use crate::app::App;
use crate::auth::handlers;
use crate::contract;
use axum::routing::{get, post};
use axum::Router;
use std::sync::Arc;

/// Build the router over the shared application state.
pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/contract-key", get(contract::contract_key))
        .route("/v1/register", post(contract::register))
        .route("/v1/auth/signup", post(handlers::signup))
        .route("/v1/auth/login", post(handlers::login))
        .route("/v1/auth/logout", post(handlers::logout))
        .route("/v1/auth/me", get(handlers::me))
        .route("/v1/auth/passwd", post(handlers::passwd))
        .with_state(app)
}

/// Liveness probe for the fly health check.
async fn healthz() -> &'static str {
    "ok"
}
