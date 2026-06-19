/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   identity.rs                                          :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! A client identity: an X25519 encryption keypair and an Ed25519 signing keypair.
//! Both private keys zeroize on drop (the dalek `zeroize` features are enabled). The
//! `keystore` module reads these crate-private fields to seal/open the identity.

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

/// An X25519 (encryption) + Ed25519 (signing) keypair owned by one principal.
pub struct Identity {
    pub(crate) enc: StaticSecret,
    pub(crate) sign: SigningKey,
}

impl Identity {
    /// Generate a fresh identity from the OS CSPRNG.
    pub fn generate() -> Self {
        Self {
            enc: StaticSecret::random(),
            sign: SigningKey::generate(&mut OsRng),
        }
    }

    /// The X25519 public key others wrap DEKs to.
    pub fn encryption_public(&self) -> PublicKey {
        PublicKey::from(&self.enc)
    }

    /// The Ed25519 verifying key readers pin to check authorship.
    pub fn author_public(&self) -> VerifyingKey {
        self.sign.verifying_key()
    }

    /// Borrow the X25519 secret (to unwrap DEKs addressed to this identity).
    pub fn encryption_secret(&self) -> &StaticSecret {
        &self.enc
    }

    /// Borrow the Ed25519 signing key (to author envelopes).
    pub fn signing_key(&self) -> &SigningKey {
        &self.sign
    }
}
