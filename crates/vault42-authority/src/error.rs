/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   error.rs                                             :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The authority's error type and its HTTP mapping.
//!
//! The mapping is the security boundary for error reporting: `Internal` deliberately
//! renders as a bare "internal error" and logs the cause server-side, so a SQL string,
//! a path, or a credential can never reach a client through an error body.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

/// Every way an authority request can fail.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    /// The caller has spent its attempts for this address in the current window.
    ///
    /// Deliberately indistinguishable between an address that has an account and one that does
    /// not, because the limit is counted before anything is looked up. A limit that answered
    /// differently for a real address would be an account-enumeration oracle wearing the costume
    /// of a defence.
    #[error("too many attempts; try again later")]
    TooManyRequests,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    Conflict(String),
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

/// The result type every handler returns.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// The HTTP status this error renders as.
    fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for Error {
    /// Render as `{"error": "..."}`, logging and redacting internal causes.
    fn into_response(self) -> Response {
        if let Self::Internal(cause) = &self {
            tracing::error!(%cause, "authority internal error");
        }
        let body = Json(serde_json::json!({ "error": self.to_string() }));
        (self.status(), body).into_response()
    }
}
