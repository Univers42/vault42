/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   kdf.rs                                               :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Argon2id passphrase key derivation for the keystore. `KdfParams` are stored with
//! the wrapped blob so a future open uses the same costs; `default` is hardened.

use crate::error::{Error, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Argon2id cost parameters. `default` is hardened; `fast_for_tests` is tests-only.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: 65_536,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

impl KdfParams {
    /// Deliberately weak parameters for fast tests only — never for real keystores.
    pub fn fast_for_tests() -> Self {
        Self {
            m_cost: 64,
            t_cost: 1,
            p_cost: 1,
        }
    }
}

/// Derive the 32-byte Key-Storage-Key from a passphrase via Argon2id; the result is
/// zeroized on drop.
pub(crate) fn derive_ksk(
    passphrase: &[u8],
    salt: &[u8],
    params: KdfParams,
) -> Result<Zeroizing<[u8; 32]>> {
    let cost = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(|_| Error::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, cost);
    let mut ksk = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase, salt, ksk.as_mut())
        .map_err(|_| Error::Kdf)?;
    Ok(ksk)
}
