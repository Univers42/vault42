/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   app.rs                                               :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The shared application state every handler receives.
//!
//! Built once in `main` and threaded through axum's `State`, so nothing here is a global
//! and a test can construct its own `App` over a temporary database.

use crate::config::{MailConfig, OtpConfig};
use crate::store::Store;
use vault42_contract::authority::Authority;

/// Everything a handler needs: the database, the contract signing key, and policy.
pub struct App {
    pub store: Store,
    pub authority: Authority,
    pub session_ttl_secs: i64,
    pub register_token: Option<String>,
    pub otp: OtpConfig,
    pub mail: MailConfig,
}

impl App {
    /// The secret one-time-code proofs are signed with, or `Forbidden` when second factors are
    /// not configured.
    ///
    /// Failing rather than defaulting is the point. A missing secret means the deployment has no
    /// second factor, and quietly treating that as "no proof needed" would turn an unconfigured
    /// authority into one that skips the check it was asked to make.
    pub fn proof_secret(&self) -> crate::error::Result<&[u8]> {
        self.otp.proof_secret.as_deref().ok_or_else(|| {
            crate::error::Error::BadRequest(
                "second factors are not configured on this authority".into(),
            )
        })
    }
}
