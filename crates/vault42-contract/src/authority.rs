/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   authority.rs                                         :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The contract authority: it owns the signing key and mints contracts. This is the
//! only thing the authority computes — a signature — so once a tenant is registered it
//! does no further work for that tenant; vault42 verifies the contract offline forever
//! after. That is what keeps the authority near-idle (scale-to-zero) and the cost ~free.

use crate::config::Config;
use crate::signing;
use ed25519_dalek::SigningKey;
use vault42_core::{issue_contract, Contract};

/// Holds the contract signing key and the issuance TTL.
pub struct Authority {
    signing: SigningKey,
    ttl_days: i64,
}

impl Authority {
    /// Load the signing key (env seed, persisted file, or freshly generated).
    pub fn load(cfg: &Config) -> anyhow::Result<Self> {
        let signing = match &cfg.seed_hex {
            Some(hex_seed) => signing::from_hex_seed(hex_seed)?,
            None => signing::load_or_create(&cfg.key_path)?,
        };
        Ok(Self {
            signing,
            ttl_days: cfg.ttl_days,
        })
    }

    /// The hex of the authority public key — vault42's `VAULT42_CONTRACT_PUBKEY`.
    pub fn public_hex(&self) -> String {
        hex::encode(self.signing.verifying_key().to_bytes())
    }

    /// Issue a contract binding `tenant` to `author_fp` for the configured TTL.
    pub fn issue(&self, tenant: &str, author_fp: [u8; 16]) -> anyhow::Result<(String, i64)> {
        let now = signing::now_unix();
        let expires_at = now + self.ttl_days * 86_400;
        let contract = Contract {
            version: 1,
            tenant: tenant.to_string(),
            author_fp,
            issued_at: now,
            expires_at,
        };
        Ok((issue_contract(&self.signing, &contract)?, expires_at))
    }
}
