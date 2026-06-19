/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   client.rs                                            :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The grobase REST client. Every call is a JSON POST signed with `X-Service-Auth`
//! (HMAC over the body), so the shared internal token authenticates the hop without
//! ever crossing the wire. The token is held in a `Zeroizing` buffer. Construct one
//! client and inject it (no globals); the seam methods live in sibling modules.

use crate::error::{Error, Result};
use crate::serviceauth::service_auth_header;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// A configured client to a private grobase instance: a reqwest pool, the base URL,
/// and the shared HMAC token.
pub struct GrobaseClient {
    http: reqwest::Client,
    base: String,
    token: Zeroizing<Vec<u8>>,
}

impl GrobaseClient {
    /// Build a client for `base` (e.g. `http://control-plane:3022`) signing with `token`.
    pub fn new(base: impl Into<String>, token: Vec<u8>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .build()
            .map_err(|_| Error::Transport)?;
        Ok(Self {
            http,
            base: base.into(),
            token: Zeroizing::new(token),
        })
    }

    /// POST `path` with a JSON `body`, signed with `X-Service-Auth`. The HMAC binds
    /// method, path, body, and timestamp, so a captured request cannot be replayed
    /// past the grobase skew window.
    pub(crate) async fn signed_post(&self, path: &str, body: &[u8]) -> Result<reqwest::Response> {
        let header = service_auth_header(self.token.as_slice(), now_unix(), "POST", path, body)?;
        self.http
            .post(format!("{}{path}", self.base))
            .header("X-Service-Auth", header)
            .header("Content-Type", "application/json")
            .body(body.to_vec())
            .send()
            .await
            .map_err(|_| Error::Transport)
    }
}

/// Current Unix time in seconds — the `X-Service-Auth` timestamp.
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
