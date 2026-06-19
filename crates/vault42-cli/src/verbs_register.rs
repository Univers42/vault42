/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   verbs_register.rs                                    :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! `register` — claim a tenant with a contract authority and save the returned contract.
//! The CLI sends only its PUBLIC author key; the authority signs a contract binding that
//! key to the tenant and returns it. The contract is then attached to every vault42
//! request. No secret or private key ever leaves the machine.

use crate::contract_io;
use serde::{Deserialize, Serialize};
use vault42_core::Identity;

#[derive(Serialize)]
struct RegisterReq<'a> {
    tenant: &'a str,
    author_pubkey: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<&'a str>,
}

#[derive(Deserialize)]
struct RegisterResp {
    contract: String,
    tenant: String,
    expires_at: i64,
}

/// Register `identity` as `tenant` with the authority, sending the invite `token` when
/// the authority requires one, and saving the returned contract.
pub async fn cmd_register(
    identity: &Identity,
    authority: &str,
    tenant: &str,
    token: Option<&str>,
) -> anyhow::Result<()> {
    let author_pubkey = hex::encode(identity.author_public().to_bytes());
    let url = format!("{}/v1/register", authority.trim_end_matches('/'));
    let response = reqwest::Client::new()
        .post(url)
        .json(&RegisterReq {
            tenant,
            author_pubkey: &author_pubkey,
            token,
        })
        .send()
        .await?;
    if !response.status().is_success() {
        anyhow::bail!("registration failed: HTTP {}", response.status().as_u16());
    }
    let body: RegisterResp = response.json().await?;
    contract_io::save_contract(&body.contract)?;
    println!(
        "registered tenant '{}' (contract valid until {})",
        body.tenant, body.expires_at
    );
    println!(
        "contract saved to {}",
        contract_io::contract_path().display()
    );
    Ok(())
}
