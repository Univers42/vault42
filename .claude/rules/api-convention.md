---
globs: ["src/apps/**/*.ts", "src/go/control-plane/**/*.go"]
description: REST API conventions — endpoints, auth, owner-scoping, errors
---

# API Conventions

## Shape

- Resource-oriented, plural-noun paths under `/v1/<resource>`; tenant self-serve under `/v1/tenants/me*`.
- Versioned — never break a shipped contract; add, don't mutate.
- JSON in/out; document every public route in `infra/config/openapi/grobase-public.json`.

## Auth & owner-scoping

- A cleartext API key resolves to identity via the control plane (`POST /v1/keys/verify`).
- Owner-scope every read and write per request — never by pool state (this is what lets `SHARE_POOLS` hold 10K tenants on one pool).
- No `{id}` in self-serve paths — resolve the tenant from the credential (no cross-tenant access by construction).

## Flag-gating

- Cloud/enterprise routes mount only under `if envBool("FLAG")` (default false) — a missing var = byte-parity.
- Master AND sub-flag must both be truthy (e.g. `METERING_ENABLED` AND `DATA_PLANE_METERING`); flipping one is a silent no-op.

## Errors

- Correct HTTP status: 402 quota exceeded, 403 ABAC deny, 404 not-found / owner-miss, 429 rate-limit.
- Never leak internals (stack traces, SQL, DSNs) in an error body.

## After changes

- Update the OpenAPI spec and regenerate SDKs (`cd sdks/js && npm run codegen:all`).
- Add or extend a verify gate `scripts/verify/m<NN>-*.sh`.
