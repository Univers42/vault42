/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   ops_env.rs                                          :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/22 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/22 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Shared env-secret operations (put / get) — the "shared env secret" storage that lets
//! a provisioned member READ an env secret. The secret is sealed CLIENT-SIDE to the
//! scope's X25519 PUBLIC key, so a PUT verifies the caller's author signature WITHOUT
//! decrypting (it holds no scope secret), then appends the next version keyed by
//! `(scope_id, epoch, path)` with optimistic concurrency. A GET returns the opaque
//! envelope to ANY authenticated caller: the seal IS the access control — only a holder
//! of the scope private key (recovered via a wrapped scope key) can decrypt it. The
//! envelope is stored base64 TEXT and crosses the wire as raw bytes; zero-knowledge holds.

use crate::env_store::EnvSecretPut;
use crate::ops_write::map_store;
use crate::principal::Principal;
use crate::svc::VaultSvc;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use tonic::Status;
use vault42_core::{verify_envelope_author, Envelope};
use vault42_proto::vault::v1::{
    GetEnvSecretRequest, GetEnvSecretResponse, PutEnvSecretRequest, PutEnvSecretResponse,
};

impl VaultSvc {
    /// Store a caller-authored env secret for `(scope_id, epoch, path)`. Verifies the
    /// envelope's author signature against the caller's key WITHOUT decrypting (a forged
    /// or unsigned envelope is `permission_denied`), enforces `expected_prev_rev` against
    /// the stored head (a stale writer is `failed_precondition`), then appends the next
    /// version and audits. The row is NOT owner-scoped — the seal to the scope public key
    /// is the access control.
    pub(crate) async fn op_put_env_secret(
        &self,
        caller: &Principal,
        req: PutEnvSecretRequest,
    ) -> Result<PutEnvSecretResponse, Status> {
        let env = Envelope::from_bytes(&req.envelope)
            .map_err(|_| Status::invalid_argument("malformed envelope"))?;
        verify_envelope_author(&env, &caller.pubkey)
            .map_err(|_| Status::permission_denied("env secret not authored by caller"))?;
        let version = self
            .store
            .put_env_secret(env_put(&req, caller))
            .await
            .map_err(map_store)?;
        self.emit_audit(caller, "env_secret_put", &env_target(&req))
            .await;
        Ok(PutEnvSecretResponse {
            version: version as u64,
        })
    }

    /// Fetch one env-secret version (0 = latest) for `(scope_id, epoch, path)`, returning
    /// the opaque envelope + author key as raw bytes to ANY authenticated caller. The seal
    /// protects the plaintext; the server never decrypts. `not_found` when absent.
    pub(crate) async fn op_get_env_secret(
        &self,
        _caller: &Principal,
        req: GetEnvSecretRequest,
    ) -> Result<GetEnvSecretResponse, Status> {
        let row = self
            .store
            .get_env_secret(
                &req.scope_id,
                req.epoch as i64,
                &req.path,
                req.version as i64,
            )
            .await
            .map_err(map_store)?
            .ok_or_else(|| Status::not_found("no env secret for this scope/path"))?;
        Ok(GetEnvSecretResponse {
            envelope: decode_b64(&row.envelope_b64)?,
            version: row.version as u64,
            author_pubkey: decode_b64(&row.author_pubkey_b64)?,
        })
    }
}

/// Build the storage put from the request + caller, base64-encoding the opaque envelope
/// and the caller's author key. `expected_prev_rev` becomes the optimistic-concurrency head.
fn env_put(req: &PutEnvSecretRequest, caller: &Principal) -> EnvSecretPut {
    EnvSecretPut {
        scope_id: req.scope_id.clone(),
        epoch: req.epoch as i64,
        path: req.path.clone(),
        expected_prev: Some(req.expected_prev_rev as i64),
        envelope_b64: STANDARD.encode(&req.envelope),
        author_pubkey_b64: STANDARD.encode(caller.pubkey),
    }
}

/// The audit target string for an env-secret put: `scope@epoch/path`.
fn env_target(req: &PutEnvSecretRequest) -> String {
    format!("{}@{}/{}", req.scope_id, req.epoch, req.path)
}

/// Decode a base64 TEXT column back to the raw bytes the wire carries.
fn decode_b64(text: &str) -> Result<Vec<u8>, Status> {
    STANDARD
        .decode(text)
        .map_err(|_| Status::internal("corrupt stored env secret"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use std::sync::Arc;
    use vault42_core::{
        generate_keyset, grant_scope_key, open, open_scope_key, scope_recipients, seal, Identity,
        Kind, Metadata, ReadScope, RecipientSecretKey, DEFAULT_MODE,
    };

    /// A fresh service over a throwaway SQLite store (no grobase, no contract gate).
    fn fresh_svc(tag: &str) -> VaultSvc {
        let path =
            std::env::temp_dir().join(format!("vault42-env-{}-{tag}.db", std::process::id()));
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
        let store = Store::open(path.to_str().expect("path"), 0).expect("open");
        VaultSvc::new(Arc::new(store), 120, None, None)
    }

    /// Env-secret metadata with the `secret_id` a reader's `ReadScope` pins.
    fn env_meta(secret_id: &str) -> Metadata {
        Metadata {
            version: 2,
            secret_id: secret_id.into(),
            tenant: "self".into(),
            owner: "scope:env-prod".into(),
            rev: 1,
            content_type: "env".into(),
            recovery_optin: false,
            project_id: String::new(),
            relative_path: String::new(),
            kind: Kind::Generic,
            mode: DEFAULT_MODE,
        }
    }

    /// Rebuild an X25519 secret from a recovered scope private key buffer.
    fn scope_static(scope_priv: &[u8; 32]) -> RecipientSecretKey {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(scope_priv);
        RecipientSecretKey::from(bytes)
    }

    #[tokio::test]
    async fn provisioned_member_reads_and_decrypts_env_secret() {
        let svc = fresh_svc("roundtrip");
        let (author, granter, reader) = (
            Identity::generate(),
            Identity::generate(),
            Identity::generate(),
        );
        let (keyset, scope_secret) = generate_keyset([7u8; 16], 1);
        let plaintext = b"DATABASE_URL=postgres://prod";
        let env = seal(
            plaintext,
            env_meta("env-1"),
            &scope_recipients(&keyset, None),
            author.signing_key(),
        )
        .expect("seal");
        let author_p = Principal::from_pubkey(author.author_public().to_bytes());
        let req = PutEnvSecretRequest {
            scope_id: hex::encode([7u8; 16]),
            epoch: 1,
            path: "prod/.env".into(),
            envelope: env.to_bytes().expect("env bytes"),
            expected_prev_rev: 0,
        };
        let put = svc.op_put_env_secret(&author_p, req).await.expect("put");
        assert_eq!(put.version, 1);
        let reader_p = Principal::from_pubkey(reader.author_public().to_bytes());
        let got = svc
            .op_get_env_secret(
                &reader_p,
                GetEnvSecretRequest {
                    scope_id: hex::encode([7u8; 16]),
                    epoch: 1,
                    path: "prod/.env".into(),
                    version: 0,
                },
            )
            .await
            .expect("get");
        let grant = grant_scope_key(
            &scope_secret,
            &reader.encryption_public(),
            granter.signing_key(),
            [7u8; 16],
            1,
        )
        .expect("grant");
        let scope_priv =
            open_scope_key(&grant, reader.encryption_secret(), &granter.author_public())
                .expect("open scope key");
        let stored = Envelope::from_bytes(&got.envelope).expect("env");
        let opened = open(
            &stored,
            &scope_static(&scope_priv),
            &author.author_public(),
            &ReadScope {
                secret_id: "env-1",
                min_rev: 0,
            },
        )
        .expect("open");
        assert_eq!(&opened[..], plaintext);
    }

    #[tokio::test]
    async fn forged_author_env_secret_is_rejected() {
        let svc = fresh_svc("forged");
        let (author, attacker) = (Identity::generate(), Identity::generate());
        let (keyset, _scope_secret) = generate_keyset([8u8; 16], 1);
        let env = seal(
            b"x",
            env_meta("env-2"),
            &scope_recipients(&keyset, None),
            author.signing_key(),
        )
        .expect("seal");
        let attacker_p = Principal::from_pubkey(attacker.author_public().to_bytes());
        let req = PutEnvSecretRequest {
            scope_id: hex::encode([8u8; 16]),
            epoch: 1,
            path: "prod/.env".into(),
            envelope: env.to_bytes().expect("env bytes"),
            expected_prev_rev: 0,
        };
        let err = svc
            .op_put_env_secret(&attacker_p, req)
            .await
            .expect_err("forged author must reject");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn unsigned_env_secret_is_rejected() {
        let svc = fresh_svc("unsigned");
        let author = Identity::generate();
        let author_p = Principal::from_pubkey(author.author_public().to_bytes());
        let req = PutEnvSecretRequest {
            scope_id: hex::encode([9u8; 16]),
            epoch: 1,
            path: "prod/.env".into(),
            envelope: b"not an envelope".to_vec(),
            expected_prev_rev: 0,
        };
        let err = svc
            .op_put_env_secret(&author_p, req)
            .await
            .expect_err("garbage envelope must reject");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn stale_expected_prev_rev_is_rejected() {
        let svc = fresh_svc("stale");
        let (keyset, _scope_secret) = generate_keyset([10u8; 16], 1);
        let author = Identity::generate();
        let author_p = Principal::from_pubkey(author.author_public().to_bytes());
        let scope_id = hex::encode([10u8; 16]);
        let put_req = |expected_prev: u64| {
            let env = seal(
                b"v",
                env_meta("env-3"),
                &scope_recipients(&keyset, None),
                author.signing_key(),
            )
            .expect("seal");
            PutEnvSecretRequest {
                scope_id: scope_id.clone(),
                epoch: 1,
                path: "prod/.env".into(),
                envelope: env.to_bytes().expect("env bytes"),
                expected_prev_rev: expected_prev,
            }
        };
        svc.op_put_env_secret(&author_p, put_req(0))
            .await
            .expect("first put");
        let err = svc
            .op_put_env_secret(&author_p, put_req(0))
            .await
            .expect_err("stale expected_prev must reject");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }
}
