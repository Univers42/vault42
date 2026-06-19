/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   factory.rs                                           :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The connection factory and per-client handler state. Each accepted TCP connection
//! gets its own `Edge` carrying a shared reference to the authorized-key allowlist; the
//! handler logic (auth + jailed session) lives in `handler`.

use russh_keys::key::PublicKey;
use std::sync::Arc;

/// Builds one `Edge` handler per incoming connection.
pub struct EdgeFactory {
    pub(crate) authorized: Arc<Vec<PublicKey>>,
}

impl EdgeFactory {
    /// Create a factory over the authorized-key allowlist.
    pub fn new(authorized: Vec<PublicKey>) -> Self {
        Self {
            authorized: Arc::new(authorized),
        }
    }
}

impl russh::server::Server for EdgeFactory {
    type Handler = Edge;

    /// Hand a fresh handler (sharing the allowlist) to a new connection.
    fn new_client(&mut self, _peer: Option<std::net::SocketAddr>) -> Edge {
        Edge {
            authorized: self.authorized.clone(),
        }
    }
}

/// Per-connection handler state.
pub struct Edge {
    pub(crate) authorized: Arc<Vec<PublicKey>>,
}
