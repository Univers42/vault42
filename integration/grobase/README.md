# grobase substrate for vault42 (apply these to the private grobase)

vault42 reuses grobase as its private REST substrate. These are the **additive,
flag-gated, reversible** grobase-side changes the operator applies — nothing here
deletes or mutates grobase behaviour; unset the flags and grobase is byte-identical.

## 1. Migration

Copy `071_vault42_secrets.sql` into grobase `scripts/migrations/postgresql/` and run
`make migrate` (grobase). It creates the owner-scoped `vault42_secrets` blob table
(zero plaintext columns — the `envelope` is opaque) and `vault42_grants` (TTL RBAC
leases). Idempotent.

## 2. Flags (set on the grobase process)

| Flag | Value | Why |
|---|---|---|
| `SERVICE_TOKEN_MODE` | `hmac` | vault42's hop authenticates by per-request `X-Service-Auth` HMAC; the shared token never transits the wire |
| `INTERNAL_SERVICE_TOKEN` | *(fly secret)* | the HMAC key both sides sign with |
| `SERVICE_AUTH_SKEW_SECS` | `120` | replay window for the signed header |
| `PERMISSION_CONDITIONS_ENABLED` | `true` | `/permissions/decide` evaluates the `time_window` ABAC condition for TTL grants |
| `TENANT_AUDIT_ENABLED` | `true` | the tamper-evident hash chain records vault42 ops |
| `TENANT_HEADER_IDENTITY_HMAC` | `1` | binds the asserted tenant header to the signature |
| `KEY_HASH_PEPPER` | *(fly secret)* | defense-in-depth for API-key hashing |

Every flag is part of grobase's existing flag-gated-OFF set; unset = byte-parity.

## 3. Gate

`bash scripts/verify/m71-grobase-substrate.sh` (needs the grobase stack up). It
round-trips an opaque envelope via `/query/v1`, rejects a missing/expired
`X-Service-Auth`, asserts a cross-owner read returns zero rows, and checks flag-OFF
parity. The Rust signer it exercises is `vault42-grobase::service_auth_header`.
