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

//! Errors raised by the grobase client seam. Kept minimal; network/JSON errors are
//! added with the async REST methods in P5.

/// The grobase-client error type.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The HMAC key could not be accepted (should not happen — HMAC takes any length).
    #[error("vault42-grobase: invalid HMAC key")]
    Key,
}

/// The crate-wide result alias.
pub type Result<T> = core::result::Result<T, Error>;
