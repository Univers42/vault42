/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   throttle.rs                                          :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Rate limits, in one place so both callers cannot drift.
//!
//! Two things were unlimited and both were measured, not guessed: twenty wrong passwords in a row
//! followed by the right one let the right one through, and ten one-time-code requests in a row
//! all answered 200 — which in production is ten real messages through a real mail credential, at
//! somebody's inbox and this project's sending reputation.
//!
//! THE LIMIT MUST NOT BECOME AN ORACLE. The code-request path already answers identically for an
//! address that has an account and one that does not, which is the property that stops an attacker
//! enumerating users. A limit applied only after the account lookup would undo it: the throttled
//! answer would arrive only for addresses that exist. So the count is taken BEFORE anything is
//! looked up, on the address as given.

use crate::app::App;
use crate::error::{Error, Result};
use std::sync::Arc;

/// Password attempts against one address.
pub(crate) const LOGIN: &str = "login";

/// One-time-code requests for one address.
pub(crate) const CODE: &str = "code";

/// How many attempts a window tolerates before the answer becomes a refusal.
///
/// Five is generous for a person and ruinous for a guesser: a nine-character password is out of
/// reach at five tries an hour, while somebody who mistypes twice notices nothing. The window is
/// an hour because the point is to make guessing cost time, and a shorter one is a shorter wait
/// for the attacker as much as for the user.
const LIMIT: i64 = 5;
const WINDOW_SECS: i64 = 3600;

/// Refuse when `subject` has already spent its attempts in `bucket`.
///
/// Called before the work, so a throttled caller costs an index lookup rather than an Argon2
/// verification — otherwise the limit protects the account and hands over the CPU.
pub(crate) async fn guard(app: &Arc<App>, bucket: &'static str, subject: &str) -> Result<()> {
    let spent = app
        .store
        .record_attempt(bucket, subject.to_string(), now(), WINDOW_SECS)
        .await?;
    if spent > LIMIT {
        return Err(Error::TooManyRequests);
    }
    Ok(())
}

/// Seconds since the epoch, from the one clock this crate uses.
fn now() -> i64 {
    vault42_contract::signing::now_unix()
}
