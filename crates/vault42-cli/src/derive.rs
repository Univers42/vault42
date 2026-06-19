/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   derive.rs                                            :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Deterministic secret-id derivation. A secret's id is a UUIDv5 over
//! `principal:path`, so the SAME (principal, path) always yields the SAME id — a
//! rotate reuses the id with no server round-trip, and the reader can compute the
//! expected id locally to bind a read to the right secret (anti-substitution).

use uuid::Uuid;

/// Fixed namespace for vault42 secret ids.
const NAMESPACE: Uuid = Uuid::from_bytes([
    0x42, 0x76, 0x61, 0x75, 0x6c, 0x74, 0x34, 0x32, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x69, 0x64,
]);

/// The deterministic secret id for `(principal, path)`.
pub fn secret_id(principal: &str, path: &str) -> String {
    Uuid::new_v5(&NAMESPACE, format!("{principal}:{path}").as_bytes()).to_string()
}
