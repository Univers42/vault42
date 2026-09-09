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

use crate::store::Store;
use vault42_contract::authority::Authority;

/// Everything a handler needs: the database, the contract signing key, and policy.
pub struct App {
    pub store: Store,
    pub authority: Authority,
    pub session_ttl_secs: i64,
    pub register_token: Option<String>,
}
