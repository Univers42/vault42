# contracts/ — the protobuf wire spine

`vault/v1` and `authz/v1` are vault42's typed contract (D3). The server implements them with tonic;
the CLI is a tonic client. Codegen runs from `crates/vault42-server/build.rs` (and the cli/ssh
crates) via `tonic-build`/`prost`. `buf lint` + `buf breaking` guard the contract in CI.

- `vault/v1/vault.proto` — the `Vault` service (Push/Get/Fetch/Ls/Share/Rm/Rotate/RotateKeys/
  Import/Export/Audit/Unseal/Whoami) and the single zero-knowledge `Envelope` message.
- `authz/v1/authz.proto` — `Check(principal, action, resource)` and `Grant(...)`; `Check` maps to
  grobase `POST /permissions/decide`.

Populated in **P1**.
