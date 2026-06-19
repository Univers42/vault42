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

//! Errors raised by the grobase client seam. Messages carry no secret material and
//! no token bytes; a failed HMAC, a transport failure, a decode failure, and a
//! non-2xx status are distinguishable so the server can map each to the right gRPC
//! status (unauthenticated vs. unavailable).

/// The grobase-client error type.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The HMAC key could not be accepted (should not happen — HMAC takes any length).
    #[error("vault42-grobase: invalid HMAC key")]
    Key,
    /// A network/transport failure talking to grobase.
    #[error("vault42-grobase: transport failure")]
    Transport,
    /// A request or response body could not be (de)serialized.
    #[error("vault42-grobase: codec error")]
    Decode,
    /// grobase returned a non-success HTTP status.
    #[error("vault42-grobase: unexpected status {0}")]
    Status(u16),
}

/// The crate-wide result alias.
pub type Result<T> = core::result::Result<T, Error>;
