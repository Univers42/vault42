/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   lib.rs                                               :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! vault42-grobase — the client seam from vault42 to the private grobase substrate.
//! P3 ships the `X-Service-Auth` HMAC signer (byte-compatible with grobase); the
//! async REST methods (`keys/verify`, `permissions/decide`, `query/execute`, audit)
//! land with the server in P5. One crate so the server and CLI share a single client
//! implementation (DRY) rather than re-deriving the signing scheme.

mod error;
mod serviceauth;

pub use error::{Error, Result};
pub use serviceauth::service_auth_header;
