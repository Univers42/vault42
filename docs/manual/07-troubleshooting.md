# 7. Troubleshooting

## 7.1 A service will not start

| Log says | Cause | Fix |
|---|---|---|
| `VAULT42_CONTRACT_PUBKEY is unset, so no authority would vouch for any caller` | the server has no key and was not told to run open | set `VAULT42_CONTRACT_PUBKEY` from `/v1/contract-key` (chapter 2 §2.5) |
| an error parsing `VAULT42_CONTRACT_PUBKEY` | the value is empty, truncated or not hexadecimal | fetch it again and check it is 64 hexadecimal characters |
| the authority refuses because a database exists but the signing key does not | the key file was lost or the volume mounted wrong | mount the right volume; restore `authority.key` from backup (chapter 6) |
| the authority refuses because second factors cannot deliver mail | `VAULT42_OTP_PROOF_SECRET` set without `MAIL_FROM` / `MAIL_PASSWORD` | set all three, or none |
| `address already in use` | another process holds 8443 or 8444 | change `-p`, or `VAULT42_PORT` / `VAULT42_AUTHORITY_PORT` |

## 7.2 Clients are refused

| 42ctl says | Cause | Fix |
|---|---|---|
| `missing auth metadata`, or every vault command unauthenticated | the user has no contract | `42ctl auth login --tenant NAME` |
| contracts rejected for **every** user after a deploy | the server is pinned to a different key than the authority holds — deployed in the wrong order, or the authority's key changed | re-pin `VAULT42_CONTRACT_PUBKEY` from `/v1/contract-key` and restart the server |
| `UNIMPLEMENTED` from `env` commands | `VAULT42_SCOPE_KEYS_ENABLED` is not `1` on the server | set it and restart |
| `HTTP 401` on `auth signup` | a register token is configured | give the user the token |
| a request refused for its timestamp | the client's or the host's clock is wrong | synchronise both clocks |
| TLS errors reaching the authority | its certificate is not publicly trusted | use a publicly trusted certificate for the authority (chapter 2 §2.7) |
| gRPC errors reaching the server through a proxy | the proxy speaks HTTP/1.1 to the server | proxy with HTTP/2 to the backend: Caddy `h2c://`, nginx `grpc_pass`, fly `h2_backend = true` |
| `HTTP 404` on grants for a project that exists | an authority older than 0.2.2 resolving a project slug another organisation also uses | upgrade the authority |

## 7.3 A deploy failed

| Step | Likely cause |
|---|---|
| *deploy only what vault42-ci passed* | the tag was pushed by hand on a commit CI never passed — let auto-release cut releases |
| *stage the authority's secrets* | only some of the three second-factor secrets are set in the repository |
| *sync the contract key onto the server* | the authority did not come up; read its logs |
| *smoke the live deployment* — `answers as 'X', not the release Y` | the new authority machine did not take the release, and the old one is still serving; read the deploy log and `fly status` |
| *smoke* — `the server answered without a gRPC content-type` | `h2_backend` was lost from `fly.toml` |
