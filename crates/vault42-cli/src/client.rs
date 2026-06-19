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

//! The signed gRPC session. Each request carries `x-v42-ts/-pub/-sig`: an Ed25519
//! signature over `ts\n<grpc-method>`, proving key possession without a password and
//! binding the call to its operation; plus `x-v42-contract` when the identity has
//! registered with an authority (managed multi-tenancy). The channel uses TLS for
//! `https://` URLs (the fly edge cert) and plaintext for local `http://`.

use crate::contract_io;
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, ClientTlsConfig};
use tonic::Request;
use vault42_core::Identity;
use vault42_proto::vault::v1::vault_client::VaultClient;

/// An authenticated client session: the gRPC client, the unlocked identity, the derived
/// principal id, and the saved contract token (if registered).
pub struct Session {
    pub client: VaultClient<Channel>,
    pub identity: Identity,
    pub principal: String,
    pub contract: Option<String>,
}

impl Session {
    /// Connect to `url` with the unlocked `identity`, loading any saved contract.
    pub async fn connect(url: &str, identity: Identity) -> anyhow::Result<Self> {
        let principal = hex::encode(vault42_core::fingerprint(
            &identity.author_public().to_bytes(),
        ));
        let endpoint = if url.starts_with("https") {
            Channel::from_shared(url.to_string())?
                .tls_config(ClientTlsConfig::new().with_native_roots())?
        } else {
            Channel::from_shared(url.to_string())?
        };
        let channel = endpoint.connect().await?;
        Ok(Self {
            client: VaultClient::new(channel),
            identity,
            principal,
            contract: contract_io::load_contract(),
        })
    }

    /// Attach signed auth metadata for `method` (and the contract, if registered).
    pub(crate) fn authorize<T>(
        &self,
        request: &mut Request<T>,
        method: &str,
    ) -> anyhow::Result<()> {
        let ts = now_unix();
        let challenge = format!("{ts}\n{method}");
        let sig = vault42_core::sign_request(self.identity.signing_key(), challenge.as_bytes());
        let pubkey = self.identity.author_public().to_bytes();
        let meta = request.metadata_mut();
        meta.insert("x-v42-ts", MetadataValue::try_from(ts.to_string())?);
        meta.insert("x-v42-pub", MetadataValue::try_from(hex::encode(pubkey))?);
        meta.insert("x-v42-sig", MetadataValue::try_from(hex::encode(sig))?);
        if let Some(contract) = &self.contract {
            meta.insert(
                "x-v42-contract",
                MetadataValue::try_from(contract.as_str())?,
            );
        }
        Ok(())
    }
}

/// Current Unix time in seconds — the challenge timestamp.
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
