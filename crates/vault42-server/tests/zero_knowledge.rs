/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   zero_knowledge.rs                                    :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/11/25 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/11/25 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! v02 — the zero-knowledge proof, end to end, against the SHIPPED BINARY.
//!
//! The conformance battery proves `seal`/`open` in isolation, and `src/e2e.rs` drives the gRPC
//! surface in-process. Neither observes the bytes the server actually leaves behind, and that is
//! what this gate adds: it launches `vault42-server` as a child process on a scratch database,
//! pushes a sentinel plaintext through a real signed client, and then scans
//!
//!   1. every file SQLite wrote — the database and its `-wal`/`-shm` sidecars,
//!   2. everything the server printed, at `RUST_LOG=trace`,
//!   3. the bytes the server served back,
//!
//! for the sentinel. Absence assertions prove nothing on their own, so each has a positive
//! control: the owner fingerprint must be findable in the database, and the startup log line
//! must be findable in the captured output. Both would fail against an empty buffer, which is
//! the failure mode that makes an absence check look like a pass.
//!
//! Server MEMORY is deliberately not asserted. From outside the process there is no honest way
//! to say what is in it, and scanning `/proc/<pid>/mem` would report on allocator junk rather
//! than on the claim. What covers memory is structural: this binary has no decrypting code path
//! and holds no recipient key, so there is nothing to find there.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tonic::transport::Channel;
use vault42_core::{seal, Identity, Kind, Metadata, Recipients, DEFAULT_MODE};
use vault42_proto::vault::v1::vault_client::VaultClient;
use vault42_proto::vault::v1::{GetRequest, PushRequest};

/// The plaintext planted through the whole pipeline. Long and distinctive so a match cannot be
/// coincidence, and never a substring of anything else in the fixture.
const SENTINEL: &[u8] = b"V02-SENTINEL-TOP-SECRET-4f7c9a";

/// A scratch directory holding one run's database and sidecars.
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vault42-v02-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// A port the OS just said was free. The listener is dropped before the server binds, so a
/// concurrent grab is possible in principle and vanishingly unlikely in practice; the retry loop
/// in `wait_ready` turns that race into a hang rather than a false pass, and the panic names it.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    port
}

/// The running server, its captured output, and the handles draining the pipes.
struct Server {
    child: Child,
    log: Arc<Mutex<Vec<u8>>>,
    readers: Vec<std::thread::JoinHandle<()>>,
}

impl Server {
    /// Launch the real binary on `port` against `db`, ungated (this is a local scratch run) and
    /// at `RUST_LOG=trace` so the whole output stream is captured, not just warnings.
    fn spawn(db: &PathBuf, port: u16) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_vault42-server"))
            .env("VAULT42_ALLOW_UNGATED", "1")
            .env("VAULT42_DB", db)
            .env("VAULT42_HOST", "127.0.0.1")
            .env("VAULT42_PORT", port.to_string())
            .env("RUST_LOG", "trace")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn vault42-server");
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut readers = Vec::new();
        for pipe in drain_pipes(&mut child) {
            let sink = log.clone();
            readers.push(std::thread::spawn(move || {
                let mut pipe = pipe;
                let mut chunk = [0u8; 4096];
                while let Ok(read) = pipe.read(&mut chunk) {
                    if read == 0 {
                        break;
                    }
                    sink.lock()
                        .expect("log lock")
                        .extend_from_slice(&chunk[..read]);
                }
            }));
        }
        Self {
            child,
            log,
            readers,
        }
    }

    /// Stop the child and return everything it printed.
    fn into_log(mut self) -> Vec<u8> {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
        let log = self.log.lock().expect("log lock").clone();
        log
    }
}

/// Both output pipes as one `Read + Send` list, so stdout and stderr are drained by the same loop.
///
/// They are different types (`ChildStdout` / `ChildStderr`), which is why this boxes them: an array
/// of the two does not type-check, and draining only one would let the other fill its pipe buffer
/// and block the server.
fn drain_pipes(child: &mut Child) -> Vec<Box<dyn Read + Send>> {
    vec![
        Box::new(child.stdout.take().expect("stdout")) as Box<dyn Read + Send>,
        Box::new(child.stderr.take().expect("stderr")) as Box<dyn Read + Send>,
    ]
}

/// Poll the listener until the server answers, or fail with the output it managed to produce.
async fn wait_ready(port: u16, log: &Arc<Mutex<Vec<u8>>>) {
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let printed = String::from_utf8_lossy(&log.lock().expect("log lock")).into_owned();
    panic!(
        "vault42-server never accepted a connection on 127.0.0.1:{port}; output was:\n{printed}"
    );
}

/// The hex principal id of an identity.
fn principal_of(id: &Identity) -> String {
    hex::encode(vault42_core::fingerprint(&id.author_public().to_bytes()))
}

/// Seal `plaintext` for `id` at `rev`, returning the wire bytes.
fn seal_for(id: &Identity, owner: &str, path: &str, rev: u64, plaintext: &[u8]) -> Vec<u8> {
    let meta = Metadata {
        version: 2,
        secret_id: format!("sid:{owner}:{path}"),
        tenant: "self".into(),
        owner: owner.into(),
        rev,
        content_type: "opaque".into(),
        recovery_optin: false,
        project_id: String::new(),
        relative_path: String::new(),
        kind: Kind::Generic,
        mode: DEFAULT_MODE,
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

/// Current Unix seconds.
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

/// Build a request signed by `id` for `method` (the same scheme the CLI uses).
fn signed<T>(msg: T, id: &Identity, method: &str) -> tonic::Request<T> {
    let ts = now();
    let sig = vault42_core::sign_request(id.signing_key(), format!("{ts}\n{method}").as_bytes());
    let mut req = tonic::Request::new(msg);
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

/// Whether `haystack` contains the contiguous byte sequence `needle`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Every byte SQLite wrote: the database plus its write-ahead log and shared-memory file.
///
/// The sidecars are the point. A row inserted moments before the process is killed lives in the
/// `-wal` file and may never reach the main database, so scanning only the `.db` would report an
/// absence that says nothing about what is stored.
fn stored_bytes(dir: &Path, db: &Path) -> Vec<u8> {
    let mut all = Vec::new();
    for suffix in ["", "-wal", "-shm"] {
        let path = PathBuf::from(format!("{}{suffix}", db.display()));
        if path.exists() {
            all.extend(std::fs::read(&path).expect("read db file"));
        }
    }
    // An empty scan would satisfy every absence assertion below, so refuse to proceed on one.
    assert!(
        !all.is_empty(),
        "no database bytes were written under {}",
        dir.display()
    );
    all
}

/// The gate: push a sentinel, then prove it is absent from the disk, the logs and the wire.
#[tokio::test]
async fn no_sentinel_plaintext_reaches_the_database_the_logs_or_the_wire() {
    let dir = scratch("scan");
    let db = dir.join("vault42.db");
    let port = free_port();
    let server = Server::spawn(&db, port);
    let log = server.log.clone();
    wait_ready(port, &log).await;

    let id = Identity::generate();
    let owner = principal_of(&id);
    let envelope = seal_for(&id, &owner, "api/key", 1, SENTINEL);
    let mut client = VaultClient::new(
        Channel::from_shared(format!("http://127.0.0.1:{port}"))
            .expect("uri")
            .connect_lazy(),
    );

    client
        .push(signed(
            PushRequest {
                path: "api/key".into(),
                envelope: envelope.clone(),
                expected_prev_rev: 0,
            },
            &id,
            "/vault.v1.Vault/Push",
        ))
        .await
        .expect("push");
    let served = client
        .get(signed(
            GetRequest {
                path: "api/key".into(),
                version: 0,
            },
            &id,
            "/vault.v1.Vault/Get",
        ))
        .await
        .expect("get")
        .into_inner();

    let log = server.into_log();
    let disk = stored_bytes(&dir, &db);

    // Positive controls first: each proves the buffer is the thing being described.
    assert!(
        contains(&log, b"vault42-server listening"),
        "the startup line must be in the captured output, or the log scan proves nothing"
    );
    assert!(
        contains(&disk, owner.as_bytes()),
        "the owner fingerprint must be findable in the database, or the disk scan proves nothing"
    );

    assert!(
        !contains(&disk, SENTINEL),
        "the sentinel plaintext is on disk — the server is not zero-knowledge"
    );
    assert!(
        !contains(&log, SENTINEL),
        "the sentinel plaintext was logged — the server is not zero-knowledge"
    );
    assert!(
        !contains(&served.envelope, SENTINEL) && !contains(&served.author_pubkey, SENTINEL),
        "the sentinel plaintext came back over the wire in a field that is not the payload"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The same gate for the shared-environment surface, which stores env secrets by scope rather
/// than by owner and is a separate table, a separate RPC and a separate code path.
#[tokio::test]
async fn no_sentinel_plaintext_reaches_the_env_secret_store() {
    use vault42_proto::vault::v1::{GetEnvSecretRequest, PutEnvSecretRequest, WrapScopeKeyRequest};

    let dir = scratch("env");
    let db = dir.join("vault42.db");
    let port = free_port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_vault42-server"))
        .env("VAULT42_ALLOW_UNGATED", "1")
        .env("VAULT42_DB", &db)
        .env("VAULT42_HOST", "127.0.0.1")
        .env("VAULT42_PORT", port.to_string())
        .env("VAULT42_SCOPE_KEYS_ENABLED", "1")
        .env("RUST_LOG", "trace")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vault42-server");
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut readers = Vec::new();
    for pipe in drain_pipes(&mut child) {
        let sink = log.clone();
        readers.push(std::thread::spawn(move || {
            let mut pipe = pipe;
            let mut chunk = [0u8; 4096];
            while let Ok(read) = pipe.read(&mut chunk) {
                if read == 0 {
                    break;
                }
                sink.lock()
                    .expect("log lock")
                    .extend_from_slice(&chunk[..read]);
            }
        }));
    }
    wait_ready(port, &log).await;

    // A scope keyset sealed to the scope's public key, authored by the caller, plus the caller's
    // own wrap — the minimum the write path authorizes on (R22a).
    let author = Identity::generate();
    let (keyset, scope_secret) = vault42_core::generate_keyset([9u8; 16], 1);
    let scope_id = hex::encode([9u8; 16]);
    let grant = vault42_core::grant_scope_key(
        &scope_secret,
        &author.encryption_public(),
        author.signing_key(),
        vault42_core::GrantTerms {
            scope_id: [9u8; 16],
            epoch: 1,
            role: vault42_core::ScopeRole::Writer,
        },
    )
    .expect("grant");
    let meta = Metadata {
        version: 2,
        secret_id: "env-secret".into(),
        tenant: "self".into(),
        owner: format!("scope:{scope_id}"),
        rev: 1,
        content_type: "env".into(),
        recovery_optin: false,
        project_id: scope_id.clone(),
        relative_path: String::new(),
        kind: Kind::Generic,
        mode: DEFAULT_MODE,
    };
    let recipients = vault42_core::scope_recipients(&keyset, None);
    let envelope = seal(SENTINEL, meta, &recipients, author.signing_key())
        .expect("seal")
        .to_bytes()
        .expect("encode");

    let mut client = VaultClient::new(
        Channel::from_shared(format!("http://127.0.0.1:{port}"))
            .expect("uri")
            .connect_lazy(),
    );
    client
        .wrap_scope_key(signed(
            WrapScopeKeyRequest {
                member_id: principal_of(&author),
                scope_id: scope_id.clone(),
                epoch: 1,
                granted_blob: grant.to_bytes().expect("grant bytes"),
                granter_pubkey: author.author_public().to_bytes().to_vec(),
            },
            &author,
            "/vault.v1.Vault/WrapScopeKey",
        ))
        .await
        .expect("wrap scope key");
    let put = client
        .put_env_secret(signed(
            PutEnvSecretRequest {
                scope_id: scope_id.clone(),
                epoch: 1,
                path: "DATABASE_URL".into(),
                envelope,
                expected_prev_rev: 0,
            },
            &author,
            "/vault.v1.Vault/PutEnvSecret",
        ))
        .await
        .expect("put env secret")
        .into_inner();
    let served = client
        .get_env_secret(signed(
            GetEnvSecretRequest {
                scope_id: scope_id.clone(),
                epoch: 1,
                path: "DATABASE_URL".into(),
                version: 0,
            },
            &author,
            "/vault.v1.Vault/GetEnvSecret",
        ))
        .await
        .expect("get env secret")
        .into_inner();

    let _ = child.kill();
    let _ = child.wait();
    for reader in readers {
        let _ = reader.join();
    }
    let printed = log.lock().expect("log lock").clone();
    let disk = stored_bytes(&dir, &db);

    assert!(
        contains(&printed, b"vault42-server listening"),
        "the startup line must be in the captured output, or the log scan proves nothing"
    );
    assert!(
        contains(&disk, scope_id.as_bytes()),
        "the scope id must be findable in the database, or the disk scan proves nothing"
    );
    assert_eq!(
        served.version, put.version,
        "the read names the same revision"
    );
    assert!(
        !contains(&disk, SENTINEL),
        "the env-secret plaintext is on disk — the shared-environment path is not zero-knowledge"
    );
    assert!(
        !contains(&printed, SENTINEL),
        "the env-secret plaintext was logged"
    );
    assert!(
        !contains(&served.envelope, SENTINEL),
        "the env-secret plaintext came back over the wire"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
