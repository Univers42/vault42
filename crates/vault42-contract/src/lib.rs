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

//! vault42-contract as a library — the contract authority's reusable half.
//!
//! The binary in `main.rs` is a thin wrapper over these modules. They are public so
//! `vault42-authority` can reuse contract issuance and tenant claiming instead of
//! copying them: the signing key is the root of trust the whole duo hangs on, and it
//! must exist in exactly one implementation.

pub mod authority;
pub mod config;
pub mod otp;
pub mod routes;
pub mod signing;
pub mod store;
pub mod validate;
