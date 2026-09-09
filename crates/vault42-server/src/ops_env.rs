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
    EnvSecretEntry, GetEnvSecretRequest, GetEnvSecretResponse, ListEnvSecretsRequest,
    ListEnvSecretsResponse, PutEnvSecretRequest, PutEnvSecretResponse,
};

impl VaultSvc {
    /// Store a caller-authored env secret for `(scope_id, epoch, path)`.
    ///
    /// Requires the caller to hold a wrap for the scope, verifies the envelope's author
    /// signature against the caller's key WITHOUT decrypting, enforces `expected_prev_rev`
    /// against the stored head, then appends the next version and audits.
    ///
    /// THE MEMBERSHIP CHECK IS NOT DEFENCE IN DEPTH, it is the only access control this path
    /// has ever had. Until it existed, the write verified one thing — that the envelope was
    /// authored by whoever sent it — which any attacker satisfies by authoring their own. So any
    /// account that could reach the port could overwrite any `(scope_id, epoch, path)`, and
    /// scope ids are `blake3(project ‖ env)`, so an attacker need not even have seen one.
    ///
    /// It stayed open because the sentence "the seal to the scope public key is the access
    /// control" sat in this doc comment. That is true of READING and was never true of writing:
    /// sealing to a public key is something anyone holding a public key can do. A confidentiality
    /// argument was carried onto an integrity path. See THREAT-MODEL R22.
    pub(crate) async fn op_put_env_secret(
        &self,
        caller: &Principal,
        req: PutEnvSecretRequest,
    ) -> Result<PutEnvSecretResponse, Status> {
        self.require_scope_member(caller, &req.scope_id).await?;
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

    /// Fetch one env-secret version (0 = latest) for `(scope_id, epoch, path)`, returning the
    /// opaque envelope + author key as raw bytes. `not_found` when absent.
    ///
    /// Members only. The seal still protects the plaintext and always did, so this is genuinely
    /// defence in depth here rather than the load-bearing check it is on the write path — but
    /// serving it to any authenticated caller handed a stranger the existence of a path, its
    /// version count, its author's key and its ciphertext length. None of that is plaintext and
    /// all of it is somebody's business.
    pub(crate) async fn op_get_env_secret(
        &self,
        caller: &Principal,
        req: GetEnvSecretRequest,
    ) -> Result<GetEnvSecretResponse, Status> {
        self.require_scope_member(caller, &req.scope_id).await?;
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

    /// Enumerate the env-secret paths of `(scope_id, epoch)`, each at its latest version,
    /// so an admin's rotate can re-seal every secret. Returns path + version only (no
    /// envelope) to ANY authenticated caller — the seal still gates decryption.
    pub(crate) async fn op_list_env_secrets(
        &self,
        caller: &Principal,
        req: ListEnvSecretsRequest,
    ) -> Result<ListEnvSecretsResponse, Status> {
        self.require_scope_member(caller, &req.scope_id).await?;
        let entries = self
            .store
            .list_env_secrets(&req.scope_id, req.epoch as i64)
            .await
            .map_err(map_store)?;
        Ok(ListEnvSecretsResponse {
            entries: entries.into_iter().map(env_entry).collect(),
        })
    }

    /// Require the caller to hold a wrap for `scope_id`.
    ///
    /// Holding a wrap is the only membership the server can see, and it is the right one: the
    /// scope secret reaches a member only through their wrap, and every legitimate env-secret
    /// operation needs that secret or the public key it leads to.
    ///
    /// WHAT THIS DOES NOT SEPARATE is read from write. A member granted read-only access holds a
    /// wrap exactly like a writer does, because reading requires it, so this refuses strangers
    /// and non-members and cannot refuse a member who oversteps. Distinguishing them needs the
    /// grant blob to carry a granter-signed role, which `GrantedScopeKey` does not — that is a
    /// protocol change across the core crate, the client and this server, recorded as R22a rather
    /// than guessed at here.
    async fn require_scope_member(&self, caller: &Principal, scope_id: &str) -> Result<(), Status> {
        let standing = self
            .store
            .scope_standing(scope_id, &caller.id)
            .await
            .map_err(map_store)?;
        if standing.subject_is_member {
            return Ok(());
        }
        Err(Status::permission_denied(
            "only a member of this scope may read or write its env secrets",
        ))
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

/// Map one stored `(path, version)` pair to a wire `EnvSecretEntry`.
fn env_entry((path, version): (String, i64)) -> EnvSecretEntry {
    EnvSecretEntry {
        path,
        version: version as u64,
    }
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

    /// Enrol `member` into `scope` the way the real flow does, so the caller is authorized.
    ///
    /// `creator` self-wraps when it is enrolling itself, which is `vault env-init`; otherwise it
    /// grants onward, which is `vault sync-keys`. These tests predate any authorization on the
    /// env-secret paths, so they wrote as an identity nobody had wrapped — a state the crypto
    /// permits, since sealing needs only the scope PUBLIC key, and one no authorized flow
    /// produces. Adding the check is what makes the enrolment step necessary, not a defect in
    /// the tests.
    async fn enrol(
        svc: &VaultSvc,
        creator: &Identity,
        member: &Identity,
        secret: &zeroize::Zeroizing<[u8; 32]>,
        scope: [u8; 16],
    ) {
        let creator_p = Principal::from_pubkey(creator.author_public().to_bytes());
        let member_p = Principal::from_pubkey(member.author_public().to_bytes());
        let blob = grant_scope_key(
            secret,
            &member.encryption_public(),
            creator.signing_key(),
            scope,
            1,
        )
        .expect("grant")
        .to_bytes()
        .expect("to_bytes");
        svc.op_wrap_scope_key(
            &creator_p,
            vault42_proto::vault::v1::WrapScopeKeyRequest {
                member_id: member_p.id,
                scope_id: hex::encode(scope),
                epoch: 1,
                granted_blob: blob,
                granter_pubkey: creator.author_public().to_bytes().to_vec(),
            },
        )
        .await
        .expect("enrol the member into the scope");
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
        enrol(&svc, &author, &author, &scope_secret, [7u8; 16]).await;
        enrol(&svc, &author, &reader, &scope_secret, [7u8; 16]).await;
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

    /// A stranger with no relationship to the scope cannot overwrite its env secrets.
    ///
    /// This was open: the write verified only that the envelope was authored by whoever sent it,
    /// which an attacker satisfies by authoring their own. Scope ids are `blake3(project ‖ env)`,
    /// so the attacker need not have seen one. THREAT-MODEL R22.
    #[tokio::test]
    async fn a_stranger_cannot_overwrite_an_env_secret() {
        let svc = fresh_svc("stranger-write");
        let (admin, stranger) = (Identity::generate(), Identity::generate());
        let scope = [21u8; 16];
        let (keyset, secret) = generate_keyset(scope, 1);
        enrol(&svc, &admin, &admin, &secret, scope).await;

        let admin_p = Principal::from_pubkey(admin.author_public().to_bytes());
        let honest = seal(
            b"DATABASE_URL=postgres://prod",
            env_meta("env-1"),
            &scope_recipients(&keyset, None),
            admin.signing_key(),
        )
        .expect("seal");
        svc.op_put_env_secret(
            &admin_p,
            PutEnvSecretRequest {
                scope_id: hex::encode(scope),
                epoch: 1,
                path: "prod/.env".into(),
                envelope: honest.to_bytes().expect("bytes"),
                expected_prev_rev: 0,
            },
        )
        .await
        .expect("positive control: a member of the scope may write it");

        let stranger_p = Principal::from_pubkey(stranger.author_public().to_bytes());
        let hostile = seal(
            b"DATABASE_URL=postgres://attacker",
            env_meta("env-1"),
            &scope_recipients(&keyset, None),
            stranger.signing_key(),
        )
        .expect("the stranger can seal: the scope public key is public");
        let refusal = svc
            .op_put_env_secret(
                &stranger_p,
                PutEnvSecretRequest {
                    scope_id: hex::encode(scope),
                    epoch: 1,
                    path: "prod/.env".into(),
                    envelope: hostile.to_bytes().expect("bytes"),
                    expected_prev_rev: 1,
                },
            )
            .await
            .expect_err("a stranger must not overwrite an env secret");
        assert_eq!(refusal.code(), tonic::Code::PermissionDenied);
    }

    /// A stranger cannot enumerate a scope's env-secret paths, nor fetch one.
    ///
    /// The seal always protected the plaintext, so this is defence in depth — but the path names,
    /// the version count, the author's key and the ciphertext length were served to anybody.
    #[tokio::test]
    async fn a_stranger_can_neither_list_nor_fetch_env_secrets() {
        let svc = fresh_svc("stranger-read");
        let (admin, stranger) = (Identity::generate(), Identity::generate());
        let scope = [22u8; 16];
        let (keyset, secret) = generate_keyset(scope, 1);
        enrol(&svc, &admin, &admin, &secret, scope).await;
        let admin_p = Principal::from_pubkey(admin.author_public().to_bytes());
        let env = seal(
            b"v",
            env_meta("env-1"),
            &scope_recipients(&keyset, None),
            admin.signing_key(),
        )
        .expect("seal");
        svc.op_put_env_secret(
            &admin_p,
            PutEnvSecretRequest {
                scope_id: hex::encode(scope),
                epoch: 1,
                path: "prod/.env".into(),
                envelope: env.to_bytes().expect("bytes"),
                expected_prev_rev: 0,
            },
        )
        .await
        .expect("the admin writes one");

        let stranger_p = Principal::from_pubkey(stranger.author_public().to_bytes());
        let listed = svc
            .op_list_env_secrets(
                &stranger_p,
                ListEnvSecretsRequest {
                    scope_id: hex::encode(scope),
                    epoch: 1,
                },
            )
            .await
            .expect_err("a stranger must not enumerate the paths");
        assert_eq!(listed.code(), tonic::Code::PermissionDenied);
        let fetched = svc
            .op_get_env_secret(
                &stranger_p,
                GetEnvSecretRequest {
                    scope_id: hex::encode(scope),
                    epoch: 1,
                    path: "prod/.env".into(),
                    version: 0,
                },
            )
            .await
            .expect_err("a stranger must not fetch it either");
        assert_eq!(fetched.code(), tonic::Code::PermissionDenied);

        svc.op_list_env_secrets(
            &admin_p,
            ListEnvSecretsRequest {
                scope_id: hex::encode(scope),
                epoch: 1,
            },
        )
        .await
        .expect("positive control: the member can still list");
    }

    /// Membership is checked BEFORE the envelope, and a stranger learns nothing from which.
    ///
    /// The ordering is deliberate and it creates a trap: `unsigned_env_secret_is_rejected` would
    /// pass on the membership refusal alone, testing nothing about signatures, which is why that
    /// test enrols its author. This pins the ordering so a future reorder cannot make it vacuous
    /// again without failing here.
    #[tokio::test]
    async fn a_stranger_is_refused_before_the_envelope_is_examined() {
        let svc = fresh_svc("order");
        let stranger = Identity::generate();
        let stranger_p = Principal::from_pubkey(stranger.author_public().to_bytes());
        let refusal = svc
            .op_put_env_secret(
                &stranger_p,
                PutEnvSecretRequest {
                    scope_id: hex::encode([23u8; 16]),
                    epoch: 1,
                    path: "prod/.env".into(),
                    envelope: b"not an envelope at all".to_vec(),
                    expected_prev_rev: 0,
                },
            )
            .await
            .expect_err("refused");
        assert_eq!(
            refusal.code(),
            tonic::Code::PermissionDenied,
            "a malformed envelope from a stranger must answer PermissionDenied, not \
             InvalidArgument — otherwise the error tells an outsider their envelope parsed"
        );
    }

    #[tokio::test]
    async fn unsigned_env_secret_is_rejected() {
        let svc = fresh_svc("unsigned");
        let author = Identity::generate();
        let (_keyset, secret) = generate_keyset([9u8; 16], 1);
        let author_p = Principal::from_pubkey(author.author_public().to_bytes());
        enrol(&svc, &author, &author, &secret, [9u8; 16]).await;
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
        let (keyset, scope_secret) = generate_keyset([10u8; 16], 1);
        let author = Identity::generate();
        let author_p = Principal::from_pubkey(author.author_public().to_bytes());
        enrol(&svc, &author, &author, &scope_secret, [10u8; 16]).await;
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

    /// Seal one env secret to `path` at version `expected_prev + 1` and PUT it.
    async fn put_path(svc: &VaultSvc, author: &Identity, path: &str, expected_prev: u64) {
        let (keyset, _scope_secret) = generate_keyset([11u8; 16], 1);
        let env = seal(
            b"v",
            env_meta("env-list"),
            &scope_recipients(&keyset, None),
            author.signing_key(),
        )
        .expect("seal");
        let author_p = Principal::from_pubkey(author.author_public().to_bytes());
        let req = PutEnvSecretRequest {
            scope_id: hex::encode([11u8; 16]),
            epoch: 1,
            path: path.into(),
            envelope: env.to_bytes().expect("env bytes"),
            expected_prev_rev: expected_prev,
        };
        svc.op_put_env_secret(&author_p, req).await.expect("put");
    }

    #[tokio::test]
    async fn list_env_secrets_returns_latest_version_per_path() {
        let svc = fresh_svc("list");
        let author = Identity::generate();
        let (_keyset, secret) = generate_keyset([11u8; 16], 1);
        enrol(&svc, &author, &author, &secret, [11u8; 16]).await;
        put_path(&svc, &author, "prod/.env", 0).await;
        put_path(&svc, &author, "staging/.env", 0).await;
        put_path(&svc, &author, "staging/.env", 1).await;
        let caller = Principal::from_pubkey(author.author_public().to_bytes());
        let resp = svc
            .op_list_env_secrets(
                &caller,
                ListEnvSecretsRequest {
                    scope_id: hex::encode([11u8; 16]),
                    epoch: 1,
                },
            )
            .await
            .expect("list");
        let entries: Vec<(String, u64)> = resp
            .entries
            .into_iter()
            .map(|e| (e.path, e.version))
            .collect();
        assert_eq!(
            entries,
            vec![
                ("prod/.env".to_string(), 1),
                ("staging/.env".to_string(), 2)
            ]
        );
    }
}
