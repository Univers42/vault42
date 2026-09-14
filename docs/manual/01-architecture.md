# 1. Architecture

## 1.1 The pieces

```text
                      ┌─────────────────────────────┐
   42ctl  ──HTTPS────▶│ vault42-authority  :8444    │  accounts · sessions · organisations · teams
  (users)             │ HTTP/JSON, axum             │  groups · projects · environments · grants
     │                │ SQLite  /data/authority.db  │  public keys · contracts · one-time codes
     │                │ key     /data/authority.key │  the CONTRACT SIGNING KEY
     │                └──────────────┬──────────────┘
     │                               │ its public key, copied once at deploy time
     │                               ▼  (VAULT42_CONTRACT_PUBKEY)
     │                ┌─────────────────────────────┐
     └──gRPC/HTTPS───▶│ vault42-server     :8443    │  sealed envelopes · environment wraps
                      │ gRPC (tonic), HTTP/2        │  audit log
                      │ SQLite  /data/vault42.db    │
                      └─────────────────────────────┘
     │
     └──S3/HTTPS─────▶  an object store (optional): encrypted chunks of files above 4 MiB
```

| | vault42-authority | vault42-server |
|---|---|---|
| Binary | `vault42-authority` | `vault42-server` |
| Image | `deploy/Dockerfile.authority` | `deploy/Dockerfile` (also `docker.io/dlesieur/vault42:vX.Y.Z`) |
| Port | 8444, plain HTTP/1.1 | 8443, plain HTTP/2 (h2c) |
| State | `/data/authority.db`, `/data/authority.key` | `/data/vault42.db` |
| Holds a secret? | the contract signing key, password hashes, hashed session and invite tokens | nothing it can open |
| On the request path of | sign-in and every organisation command | every vault and environment command |

Both images are distroless (no shell), run a single binary, and keep everything that matters on
**one volume mounted at `/data`**. Both speak plain protocols and expect **TLS to be terminated in front
of them** — by fly.io's edge, or by a reverse proxy you run (chapter 2).

## 1.2 Trust

- **The server trusts the authority's public key and nothing else from it.** Every vault request carries a
  contract the authority signed; the server verifies it **offline**, with `VAULT42_CONTRACT_PUBKEY`. The
  authority is never contacted on the request path, so it can sleep while the vault is in use.
- **Neither service can read a secret.** Clients seal everything before sending it. The server verifies
  signatures on what it stores and enforces who may write where; it cannot decrypt.
- **The contract signing key is the root of trust.** If `/data/authority.key` is lost, every contract ever
  issued stops verifying and every user must sign in again with a new key pinned on the server. If it is
  stolen, contracts can be forged — though a forged contract still cannot open anybody's secrets.

## 1.3 Order of deployment

**The authority first, then the server.** The server must be started with the authority's public key, and
the authority creates its key pair on first start. A server pinned to a key that does not exist yet
rejects every request while looking perfectly healthy.

## 1.4 Feature switches that decide whether anything works

| Variable | On | Without it |
|---|---|---|
| `VAULT42_CONTRACT_PUBKEY` (server) | every request needs a contract from your authority | the server **refuses to start**, unless `VAULT42_ALLOW_UNGATED=1` says you mean to accept any key |
| `VAULT42_SCOPE_KEYS_ENABLED=1` (server) | shared environments work | every `42ctl env` key, secret and tree command answers `UNIMPLEMENTED` |
| `VAULT42_REGISTER_TOKEN` (authority) | account creation needs the token | anyone who can reach the authority can create an account |
| `VAULT42_OTP_PROOF_SECRET` + `MAIL_FROM` + `MAIL_PASSWORD` (authority) | second factors and keystore escrow work | those features are off; setting only some of the three refuses to start |
| `GITHUB_CLIENT_ID` (authority) | `42ctl auth login --github` works | it answers a named refusal |

Chapter 4 lists every variable.
