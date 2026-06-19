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
//! It ships the `X-Service-Auth` HMAC signer (byte-compatible with grobase) and the
//! async REST methods the server orchestrates over: `verify_key` (`/v1/keys/verify`),
//! `decide` (`/permissions/decide`, ABAC PDP), and `audit_append`
//! (`/v1/audit/tenants/{id}/events`, the tamper-evident chain). One crate so the
//! server and any other caller share a single signed client (DRY) rather than
//! re-deriving the signing scheme. Every method is off-path unless a private grobase
//! is configured — the deployed server's zero-knowledge identity is its own.

mod audit;
mod client;
mod decide;
mod error;
mod serviceauth;
mod verify;

pub use audit::AuditEvent;
pub use client::GrobaseClient;
pub use decide::{DecideInput, Decision};
pub use error::{Error, Result};
pub use serviceauth::service_auth_header;
pub use verify::VerifiedKey;
