# 4. Configuration reference

Both services read their configuration from the environment once, at start. Nothing is read from a file.

## 4.1 vault42-authority

| Variable | Default | Meaning |
|---|---|---|
| `VAULT42_AUTHORITY_HOST` | `0.0.0.0` | address to listen on |
| `VAULT42_AUTHORITY_PORT` | `8444` | port to listen on |
| `VAULT42_AUTHORITY_DB` | `/data/authority.db` | SQLite database |
| `VAULT42_AUTHORITY_KEY` | `/data/contract.key` (`/data/authority.key` in the image) | the contract signing key, created `0600` on first start |
| `VAULT42_CONTRACT_SEED` | — | a hex seed to derive the signing key from instead of the key file; for tests, not production |
| `VAULT42_CONTRACT_TTL_DAYS` | `365` | how long a contract is valid |
| `VAULT42_AUTHORITY_SESSION_TTL_SECS` | `86400` | how long a session is valid |
| `VAULT42_REGISTER_TOKEN` | — | when set, account creation requires this token; unset, sign-up is open |
| `VAULT42_MAX_TENANTS_PER_ACCOUNT` | `8` | tenant names one account may hold |
| `VAULT42_OTP_PROOF_SECRET` | — | enables one-time codes (second factors, keystore escrow); also accepted as `GOTRUE_JWT_SECRET` |
| `VAULT42_OTP_TTL_SECS` | `300` | how long an emailed code is valid |
| `VAULT42_OTP_PROOF_TTL_SECS` | `600` | how long a verified code's proof is valid |
| `MAIL_TRANSPORT` | `smtp` | `smtp`, or `file` to write messages into `MAIL_OUTBOX` instead (testing) |
| `MAIL_OUTBOX` | — | directory for `MAIL_TRANSPORT=file` |
| `MAIL_FROM` | — | sender address, and SMTP user name |
| `MAIL_PASSWORD` | — | SMTP password |
| `MAIL_HOST` | `smtp.titan.email` | SMTP server |
| `MAIL_PORT` | `465` | SMTP port (implicit TLS) |
| `GITHUB_CLIENT_ID` | — | a GitHub OAuth application's client id; enables `42ctl auth login --github` |
| `GITHUB_OAUTH_BASE`, `GITHUB_API_BASE` | `https://github.com`, `https://api.github.com` | GitHub's addresses; changed only to test against a stand-in |
| `RUST_LOG` | `info` in the image | log level |

**Refusals at start.** The authority refuses to start when `VAULT42_OTP_PROOF_SECRET` is set but mail
cannot be delivered (`MAIL_FROM` or `MAIL_PASSWORD` missing with `smtp`), and when it finds a database but
no signing key — which means the key was lost, and minting a new one would silently invalidate every
contract.

**Subcommand.** `vault42-authority backup OUTPUT_PATH` writes a consistent snapshot of the database and
exits (chapter 6).

## 4.2 vault42-server

| Variable | Default | Meaning |
|---|---|---|
| `VAULT42_HOST` | `0.0.0.0` | address to listen on |
| `VAULT42_PORT` | `8443` | port to listen on (gRPC over HTTP/2) |
| `VAULT42_DB` | `/data/vault42.db` | SQLite database |
| `VAULT42_CONTRACT_PUBKEY` | — | the authority's public key, 64 hexadecimal characters: every request must carry a contract it signed. A present but malformed value refuses to start |
| `VAULT42_ALLOW_UNGATED` | off | `1` to run **without** a contract gate, accepting any self-generated key; for laboratories only |
| `VAULT42_SCOPE_KEYS_ENABLED` | off | `1` enables shared environments; without it their RPCs answer `UNIMPLEMENTED` |
| `VAULT42_AUTH_SKEW_SECS` | `120` | how far a request's signed timestamp may be from the server's clock |
| `VAULT42_MAX_SECRETS` | `0` (no limit) | per-owner limit on stored secrets |
| `RUST_LOG` | `info` in the image | log level |

**Refusal at start.** With neither `VAULT42_CONTRACT_PUBKEY` nor `VAULT42_ALLOW_UNGATED=1`, the server
refuses to start. Forgetting the key and meaning to run open used to look identical; now they cannot.

**Legacy.** `VAULT42_STORE=grobase` and the `GROBASE_*`, `JWT_SECRET` and `INTERNAL_SERVICE_TOKEN` variables
select an external grobase control plane and storage backend that this product no longer uses. Leave them
unset.

## 4.3 Clocks

Every request is signed with a timestamp the server accepts within `VAULT42_AUTH_SKEW_SECS`. Keep the
host's clock synchronised (NTP); a client whose clock is off by more than two minutes is refused.
