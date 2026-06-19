/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   handler.rs                                           :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The russh handler: publickey authentication against the allowlist, then a jailed
//! session. Auth is TRANSPORT-ONLY — accepting a key proves the peer holds it, but the
//! edge never receives any private key and never decrypts a secret. The session is
//! deliberately inert (it serves a usage banner): the zero-knowledge client crypto
//! stays on the user's machine, reached over a forwarded gRPC port, so owning this box
//! never reveals a secret.

use crate::factory::Edge;
use async_trait::async_trait;
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelId, CryptoVec};
use russh_keys::key::PublicKey;

#[async_trait]
impl Handler for Edge {
    type Error = russh::Error;

    /// Accept only keys present in the allowlist; reject everything else.
    async fn auth_publickey(&mut self, _user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        if self.authorized.iter().any(|allowed| allowed == key) {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::Reject {
                proceed_with_methods: None,
            })
        }
    }

    /// Allow opening a session channel (it will only ever serve the banner).
    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    /// Any exec request is answered with the usage banner, then the channel closes.
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        deliver_banner(channel, session);
        Ok(())
    }

    /// A shell request is treated identically — there is no interactive shell here.
    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        deliver_banner(channel, session);
        Ok(())
    }
}

/// Write the usage banner to the channel, report success, and close it.
fn deliver_banner(channel: ChannelId, session: &mut Session) {
    let banner: &[u8] = b"vault42 ssh edge: authenticated transport only.\r\n\
        Run the local `vault42` CLI over a forwarded gRPC port; your keystore unlock \
        stays on your machine, so this host never sees plaintext.\r\n";
    session.data(channel, CryptoVec::from_slice(banner));
    session.exit_status_request(channel, 0);
    session.close(channel);
}
