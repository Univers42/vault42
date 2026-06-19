/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   e2e.rs                                               :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! In-process end-to-end gRPC proof of the zero-knowledge contract. Each test spins a
//! real tonic server over a loopback socket and drives it with a real signed client:
//! seal→push→get→open is byte-identical (v01); a sentinel plaintext never appears in
//! the wire envelope (v02); a different identity cannot read another's secret (v03); a
//! tampered or method-mismatched signature is rejected; a stale write is a conflict.

use crate::store::Store;
use crate::svc::VaultSvc;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};
use tonic::{Code, Request};
use vault42_core::{
    issue_contract, open, seal, AuthorPublicKey, Contract, Envelope, Identity, Metadata, ReadScope,
    Recipients,
};
use vault42_proto::vault::v1::vault_client::VaultClient;
use vault42_proto::vault::v1::vault_server::VaultServer;
use vault42_proto::vault::v1::{GetRequest, PushRequest, ShareRequest};

/// A throwaway SQLite store on a per-test temp file (WAL sidecars cleaned best-effort),
/// capped at `max_secrets` distinct paths per owner (0 = unlimited).
fn fresh_capped(tag: &str, max_secrets: i64) -> Store {
    let path = std::env::temp_dir().join(format!("vault42-e2e-{}-{tag}.db", std::process::id()));
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    Store::open(path.to_str().expect("path"), max_secrets).expect("open store")
}

/// A fresh unlimited store.
fn fresh_store(tag: &str) -> Store {
    fresh_capped(tag, 0)
}

/// Serve the vault on an ephemeral loopback port and return its address.
async fn spawn(store: Store) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let svc = VaultSvc::new(store, 120, None, None);
    tokio::spawn(async move {
        Server::builder()
            .add_service(VaultServer::new(svc))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("serve");
    });
    addr
}

/// Serve a CONTRACT-GATED vault (managed multi-tenancy) on an ephemeral port.
async fn spawn_gated(store: Store, authority_pub: [u8; 32]) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let svc = VaultSvc::new(store, 120, None, Some(authority_pub));
    tokio::spawn(async move {
        Server::builder()
            .add_service(VaultServer::new(svc))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("serve");
    });
    addr
}

/// Attach a contract token to a signed request.
fn with_contract<T>(mut request: Request<T>, contract: &str) -> Request<T> {
    request
        .metadata_mut()
        .insert("x-v42-contract", contract.parse().expect("contract"));
    request
}

/// A lazily-connecting client to `addr`.
fn client(addr: std::net::SocketAddr) -> VaultClient<Channel> {
    let channel = Channel::from_shared(format!("http://{addr}"))
        .expect("uri")
        .connect_lazy();
    VaultClient::new(channel)
}

/// The hex principal id of an identity.
fn principal_of(id: &Identity) -> String {
    hex::encode(vault42_core::fingerprint(&id.author_public().to_bytes()))
}

/// The test secret id for `(owner, path)` — any value, kept consistent for read scope.
fn sid(owner: &str, path: &str) -> String {
    format!("sid:{owner}:{path}")
}

/// Seal `plaintext` for `id` under `owner`/`path`/`rev`, returning the wire bytes.
fn seal_for(id: &Identity, owner: &str, path: &str, rev: u64, plaintext: &[u8]) -> Vec<u8> {
    let meta = Metadata {
        version: 1,
        secret_id: sid(owner, path),
        tenant: "self".into(),
        owner: owner.into(),
        rev,
        content_type: "opaque".into(),
        recovery_optin: false,
    };
    let recipients = Recipients {
        users: &[id.encryption_public()],
        recovery: None,
    };
    seal(plaintext, meta, &recipients, id.signing_key())
        .expect("seal")
        .to_bytes()
        .expect("encode")
}

/// Build a request signed by `id` for `method` (the same scheme the CLI uses).
fn signed<T>(msg: T, id: &Identity, method: &str) -> Request<T> {
    let ts = now();
    let sig = vault42_core::sign_request(id.signing_key(), format!("{ts}\n{method}").as_bytes());
    let mut req = Request::new(msg);
    let meta = req.metadata_mut();
    meta.insert("x-v42-ts", ts.to_string().parse().expect("ts"));
    meta.insert(
        "x-v42-pub",
        hex::encode(id.author_public().to_bytes())
            .parse()
            .expect("pub"),
    );
    meta.insert("x-v42-sig", hex::encode(sig).parse().expect("sig"));
    req
}

/// Current Unix seconds.
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

/// Whether `haystack` contains the contiguous byte sequence `needle`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn push_get_roundtrip_is_byte_identical() {
    let addr = spawn(fresh_store("rt")).await;
    let mut c = client(addr);
    let id = Identity::generate();
    let owner = principal_of(&id);
    let secret = b"sk-PLAINTEXT-SENTINEL-123";
    let envelope = seal_for(&id, &owner, "api/key", 1, secret);
    let push = signed(
        PushRequest {
            path: "api/key".into(),
            envelope,
            expected_prev_rev: 0,
        },
        &id,
        "/vault.v1.Vault/Push",
    );
    assert_eq!(c.push(push).await.expect("push").into_inner().version, 1);

    let get = signed(
        GetRequest {
            path: "api/key".into(),
            version: 0,
        },
        &id,
        "/vault.v1.Vault/Get",
    );
    let resp = c.get(get).await.expect("get").into_inner();
    let env = Envelope::from_bytes(&resp.envelope).expect("decode");
    let mut author = [0u8; 32];
    author.copy_from_slice(&resp.author_pubkey);
    let scope = ReadScope {
        secret_id: &sid(&owner, "api/key"),
        min_rev: 0,
    };
    let opened = open(
        &env,
        id.encryption_secret(),
        &AuthorPublicKey::from_bytes(&author).expect("author"),
        &scope,
    )
    .expect("open");
    assert_eq!(&opened[..], secret);
}

#[tokio::test]
async fn envelope_on_the_wire_has_no_plaintext() {
    let id = Identity::generate();
    let owner = principal_of(&id);
    let secret = b"TOP-SECRET-SENTINEL-XYZZY";
    let envelope = seal_for(&id, &owner, "p", 1, secret);
    assert!(
        !contains(&envelope, secret),
        "sentinel plaintext must never appear in the opaque envelope"
    );
}

#[tokio::test]
async fn cross_owner_get_is_not_found() {
    let addr = spawn(fresh_store("xo")).await;
    let mut c = client(addr);
    let alice = Identity::generate();
    let owner = principal_of(&alice);
    let envelope = seal_for(&alice, &owner, "p", 1, b"alice-secret");
    c.push(signed(
        PushRequest {
            path: "p".into(),
            envelope,
            expected_prev_rev: 0,
        },
        &alice,
        "/vault.v1.Vault/Push",
    ))
    .await
    .expect("alice push");

    let bob = Identity::generate();
    let err = c
        .get(signed(
            GetRequest {
                path: "p".into(),
                version: 0,
            },
            &bob,
            "/vault.v1.Vault/Get",
        ))
        .await
        .expect_err("bob must not read alice's secret");
    assert_eq!(err.code(), Code::NotFound);
}

#[tokio::test]
async fn tampered_signature_is_unauthenticated() {
    let addr = spawn(fresh_store("sig")).await;
    let mut c = client(addr);
    let id = Identity::generate();
    let owner = principal_of(&id);
    let envelope = seal_for(&id, &owner, "p", 1, b"x");
    let mut req = signed(
        PushRequest {
            path: "p".into(),
            envelope,
            expected_prev_rev: 0,
        },
        &id,
        "/vault.v1.Vault/Push",
    );
    req.metadata_mut()
        .insert("x-v42-sig", "00".repeat(64).parse().expect("sig"));
    let err = c.push(req).await.expect_err("tampered signature must fail");
    assert_eq!(err.code(), Code::Unauthenticated);
}

#[tokio::test]
async fn signature_is_bound_to_method() {
    let addr = spawn(fresh_store("method")).await;
    let mut c = client(addr);
    let id = Identity::generate();
    let req = signed(
        GetRequest {
            path: "p".into(),
            version: 0,
        },
        &id,
        "/vault.v1.Vault/Push",
    );
    let err = c
        .get(req)
        .await
        .expect_err("a Push signature must not authorize Get");
    assert_eq!(err.code(), Code::Unauthenticated);
}

#[tokio::test]
async fn stale_expected_prev_is_a_conflict() {
    let addr = spawn(fresh_store("ver")).await;
    let mut c = client(addr);
    let id = Identity::generate();
    let owner = principal_of(&id);
    c.push(signed(
        PushRequest {
            path: "p".into(),
            envelope: seal_for(&id, &owner, "p", 1, b"v1"),
            expected_prev_rev: 0,
        },
        &id,
        "/vault.v1.Vault/Push",
    ))
    .await
    .expect("first push");
    let err = c
        .push(signed(
            PushRequest {
                path: "p".into(),
                envelope: seal_for(&id, &owner, "p", 2, b"v2"),
                expected_prev_rev: 0,
            },
            &id,
            "/vault.v1.Vault/Push",
        ))
        .await
        .expect_err("stale write must be rejected");
    assert_eq!(err.code(), Code::FailedPrecondition);
}

#[tokio::test]
async fn push_under_a_foreign_owner_is_denied() {
    let addr = spawn(fresh_store("foreign")).await;
    let mut c = client(addr);
    let alice = Identity::generate();
    let foreign_owner = "0".repeat(32);
    let envelope = seal_for(&alice, &foreign_owner, "p", 1, b"inject");
    let err = c
        .push(signed(
            PushRequest {
                path: "p".into(),
                envelope,
                expected_prev_rev: 0,
            },
            &alice,
            "/vault.v1.Vault/Push",
        ))
        .await
        .expect_err("push into another owner's namespace must be denied");
    assert_eq!(err.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn share_round_trips_to_a_friend() {
    let addr = spawn(fresh_store("share")).await;
    let mut c = client(addr);
    let alice = Identity::generate();
    let bob = Identity::generate();
    let bob_owner = principal_of(&bob);
    let shared_path = format!("shared/{}/note", principal_of(&alice));
    let secret = b"shared-secret-99";
    let meta = Metadata {
        version: 1,
        secret_id: sid(&bob_owner, &shared_path),
        tenant: "self".into(),
        owner: bob_owner.clone(),
        rev: 1,
        content_type: "opaque".into(),
        recovery_optin: false,
    };
    let recipients = Recipients {
        users: &[bob.encryption_public(), alice.encryption_public()],
        recovery: None,
    };
    let envelope = seal(secret, meta, &recipients, alice.signing_key())
        .expect("seal")
        .to_bytes()
        .expect("encode");
    c.share(signed(
        ShareRequest {
            path: shared_path.clone(),
            envelope,
            expected_prev_rev: 0,
        },
        &alice,
        "/vault.v1.Vault/Share",
    ))
    .await
    .expect("alice shares to bob");

    let resp = c
        .get(signed(
            GetRequest {
                path: shared_path.clone(),
                version: 0,
            },
            &bob,
            "/vault.v1.Vault/Get",
        ))
        .await
        .expect("bob reads the shared secret")
        .into_inner();
    let env = Envelope::from_bytes(&resp.envelope).expect("decode");
    let mut author = [0u8; 32];
    author.copy_from_slice(&resp.author_pubkey);
    assert_eq!(vault42_core::fingerprint(&author), env.author_pubkey_id);
    let scope = ReadScope {
        secret_id: &sid(&bob_owner, &shared_path),
        min_rev: 0,
    };
    let opened = open(
        &env,
        bob.encryption_secret(),
        &AuthorPublicKey::from_bytes(&author).expect("author"),
        &scope,
    )
    .expect("bob opens alice's shared secret");
    assert_eq!(&opened[..], secret);
}

#[tokio::test]
async fn many_tenants_are_fully_isolated() {
    let addr = spawn(fresh_store("tenants")).await;
    let mut c = client(addr);
    let ids: Vec<Identity> = (0..24).map(|_| Identity::generate()).collect();
    for (i, id) in ids.iter().enumerate() {
        let owner = principal_of(id);
        let envelope = seal_for(
            id,
            &owner,
            "p",
            1,
            format!("secret-of-tenant-{i}").as_bytes(),
        );
        c.push(signed(
            PushRequest {
                path: "p".into(),
                envelope,
                expected_prev_rev: 0,
            },
            id,
            "/vault.v1.Vault/Push",
        ))
        .await
        .expect("push");
    }
    for (i, id) in ids.iter().enumerate() {
        let owner = principal_of(id);
        let resp = c
            .get(signed(
                GetRequest {
                    path: "p".into(),
                    version: 0,
                },
                id,
                "/vault.v1.Vault/Get",
            ))
            .await
            .expect("get")
            .into_inner();
        let env = Envelope::from_bytes(&resp.envelope).expect("decode");
        let mut author = [0u8; 32];
        author.copy_from_slice(&resp.author_pubkey);
        let scope = ReadScope {
            secret_id: &sid(&owner, "p"),
            min_rev: 0,
        };
        let opened = open(
            &env,
            id.encryption_secret(),
            &AuthorPublicKey::from_bytes(&author).expect("author"),
            &scope,
        )
        .expect("each tenant opens its own");
        assert_eq!(&opened[..], format!("secret-of-tenant-{i}").as_bytes());
    }
    let outsider = Identity::generate();
    let err = c
        .get(signed(
            GetRequest {
                path: "p".into(),
                version: 0,
            },
            &outsider,
            "/vault.v1.Vault/Get",
        ))
        .await
        .expect_err("a tenant that never wrote sees nothing");
    assert_eq!(err.code(), Code::NotFound);
}

#[tokio::test]
async fn many_versions_round_trip() {
    let addr = spawn(fresh_store("versions")).await;
    let mut c = client(addr);
    let id = Identity::generate();
    let owner = principal_of(&id);
    let total = 40u64;
    for v in 1..=total {
        let envelope = seal_for(&id, &owner, "v", v, format!("value-{v}").as_bytes());
        let resp = c
            .push(signed(
                PushRequest {
                    path: "v".into(),
                    envelope,
                    expected_prev_rev: v - 1,
                },
                &id,
                "/vault.v1.Vault/Push",
            ))
            .await
            .expect("push")
            .into_inner();
        assert_eq!(resp.version, v);
    }
    let latest = c
        .get(signed(
            GetRequest {
                path: "v".into(),
                version: 0,
            },
            &id,
            "/vault.v1.Vault/Get",
        ))
        .await
        .expect("get latest")
        .into_inner();
    assert_eq!(latest.version, total);
    let v5 = c
        .get(signed(
            GetRequest {
                path: "v".into(),
                version: 5,
            },
            &id,
            "/vault.v1.Vault/Get",
        ))
        .await
        .expect("get v5")
        .into_inner();
    assert_eq!(v5.version, 5);
}

#[tokio::test]
async fn edge_paths_and_payloads_round_trip() {
    let addr = spawn(fresh_store("edge")).await;
    let mut c = client(addr);
    let id = Identity::generate();
    let owner = principal_of(&id);
    let cases: Vec<(String, Vec<u8>)> = vec![
        ("a".into(), Vec::new()),
        ("deep/nested/path/with/many/segments".into(), b"x".to_vec()),
        (
            "unicode-\u{e9}\u{1f510}-key".into(),
            "secr\u{e9}t-\u{1f511}".as_bytes().to_vec(),
        ),
        ("binary".into(), (0u8..=255).collect()),
        ("big".into(), vec![0xab; 256 * 1024]),
    ];
    for (path, payload) in &cases {
        let envelope = seal_for(&id, &owner, path, 1, payload);
        c.push(signed(
            PushRequest {
                path: path.clone(),
                envelope,
                expected_prev_rev: 0,
            },
            &id,
            "/vault.v1.Vault/Push",
        ))
        .await
        .expect("push");
        let resp = c
            .get(signed(
                GetRequest {
                    path: path.clone(),
                    version: 0,
                },
                &id,
                "/vault.v1.Vault/Get",
            ))
            .await
            .expect("get")
            .into_inner();
        let env = Envelope::from_bytes(&resp.envelope).expect("decode");
        let mut author = [0u8; 32];
        author.copy_from_slice(&resp.author_pubkey);
        let scope = ReadScope {
            secret_id: &sid(&owner, path),
            min_rev: 0,
        };
        let opened = open(
            &env,
            id.encryption_secret(),
            &AuthorPublicKey::from_bytes(&author).expect("author"),
            &scope,
        )
        .expect("open");
        assert_eq!(
            &opened[..],
            &payload[..],
            "roundtrip failed for path {path}"
        );
    }
}

#[tokio::test]
async fn contract_gate_accepts_valid_and_rejects_the_rest() {
    let authority = Identity::generate();
    let addr = spawn_gated(
        fresh_store("contract"),
        authority.author_public().to_bytes(),
    )
    .await;
    let mut c = client(addr);
    let user = Identity::generate();
    let owner = principal_of(&user);
    let fp = vault42_core::fingerprint(&user.author_public().to_bytes());
    let issue = |author_fp, from: i64, to: i64| {
        issue_contract(
            authority.signing_key(),
            &Contract {
                version: 1,
                tenant: "acme".into(),
                author_fp,
                issued_at: now() + from,
                expires_at: now() + to,
            },
        )
        .expect("issue")
    };
    let env = seal_for(&user, &owner, "p", 1, b"data");

    // valid contract → accepted
    let ok = with_contract(
        signed(
            PushRequest {
                path: "p".into(),
                envelope: env.clone(),
                expected_prev_rev: 0,
            },
            &user,
            "/vault.v1.Vault/Push",
        ),
        &issue(fp, -10, 3600),
    );
    assert!(c.push(ok).await.is_ok());

    // no contract → unauthenticated
    let bare = signed(
        GetRequest {
            path: "p".into(),
            version: 0,
        },
        &user,
        "/vault.v1.Vault/Get",
    );
    assert_eq!(
        c.get(bare).await.expect_err("no contract").code(),
        Code::Unauthenticated
    );

    // contract bound to a DIFFERENT key → permission denied
    let other_fp = vault42_core::fingerprint(&Identity::generate().author_public().to_bytes());
    let wrong = with_contract(
        signed(
            GetRequest {
                path: "p".into(),
                version: 0,
            },
            &user,
            "/vault.v1.Vault/Get",
        ),
        &issue(other_fp, -10, 3600),
    );
    assert_eq!(
        c.get(wrong).await.expect_err("wrong key").code(),
        Code::PermissionDenied
    );

    // expired contract → unauthenticated
    let stale = with_contract(
        signed(
            GetRequest {
                path: "p".into(),
                version: 0,
            },
            &user,
            "/vault.v1.Vault/Get",
        ),
        &issue(fp, -7200, -3600),
    );
    assert_eq!(
        c.get(stale).await.expect_err("expired").code(),
        Code::Unauthenticated
    );
}

#[tokio::test]
async fn per_owner_quota_caps_distinct_secrets() {
    let addr = spawn(fresh_capped("quota", 3)).await;
    let mut c = client(addr);
    let id = Identity::generate();
    let owner = principal_of(&id);
    for i in 0..3 {
        let envelope = seal_for(&id, &owner, &format!("s{i}"), 1, b"x");
        c.push(signed(
            PushRequest {
                path: format!("s{i}"),
                envelope,
                expected_prev_rev: 0,
            },
            &id,
            "/vault.v1.Vault/Push",
        ))
        .await
        .expect("within quota");
    }
    let over = seal_for(&id, &owner, "s3", 1, b"x");
    let err = c
        .push(signed(
            PushRequest {
                path: "s3".into(),
                envelope: over,
                expected_prev_rev: 0,
            },
            &id,
            "/vault.v1.Vault/Push",
        ))
        .await
        .expect_err("a 4th distinct secret exceeds the quota");
    assert_eq!(err.code(), Code::ResourceExhausted);

    // updating an existing path (new version) is always allowed
    let update = seal_for(&id, &owner, "s0", 2, b"y");
    c.push(signed(
        PushRequest {
            path: "s0".into(),
            envelope: update,
            expected_prev_rev: 1,
        },
        &id,
        "/vault.v1.Vault/Push",
    ))
    .await
    .expect("updating an existing secret is not capped");
}
