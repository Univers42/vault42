# vault42 — Operations Runbook

How to operate, unseal, recover, and rotate. (Deploy topology + fly specifics land with P9; this
grows per phase.)

## Build & test (Docker-first — no host cargo)

```sh
make rust-check    # clippy -D warnings
make rust-test     # cargo test --workspace
make rust-build    # release binaries
make security      # cargo-audit + cargo-deny + gitleaks
make verify        # the v01..vNN gate battery
```

## gitflow

- `develop` is the integration branch; cut `feature/<phase>-<slug>` from it, PR back (squash).
- `release/x.y.0` off `develop` → stabilize → merge to `main` + back to `develop`; tag `vx.y.0`.
- `hotfix/x.y.z` off `main` → `main` + `develop`.
- **No co-author trailer** on any commit. Pushes/tags/deploys are operator-triggered (irreversible).

## Seal / unseal (L2 at-rest, P7/P9)

vault42 boots **SEALED**: it can store/return ciphertext but cannot run unwrap-assisting operations.
The L2 master seed lives in a fly secret (`VAULT42_UNSEAL_SEED`) and auto-unseals at boot. Manual or
Shamir K-of-N unseal is the documented upgrade. To re-seal: restart the process / rotate the seed.

## Recovery — "I lost my passphrase but can log into fly.io" (D5)

Pre-req: the tenant had `recovery_optin = true` when the secrets were written (recovery is **not**
retroactive). Steps:

1. Operator proves fly.io account access (the boot-injected Transit token is present in the running
   server).
2. Generate a fresh client identity (`vault42 init` on the new device).
3. Run the admin-gated `vault42 recover --tenant <t> --user <u>` (passkey step-up if enabled).
4. The server `cmek.Open`s the per-tenant recovery private key (zeroized after the ceremony),
   unwraps each secret's DEK via the recovery `WrappedDek`, re-wraps for the fresh identity, bumps
   `rev`, re-signs as the recovery author, and stores.
5. Adopt the fresh identity; retire the lost one. Every step is recorded in the audit chain.

## Key rotation

- **Service token** (`INTERNAL_SERVICE_TOKEN`): set `INTERNAL_SERVICE_TOKEN_PREV` to the old value,
  deploy the new token to both vault42 and grobase, then clear `_PREV` after the skew window.
- **Secret DEK** (`vault42 rotate <path>`): fresh DEK, re-encrypt, re-wrap for the current recipient
  set, bump `rev`.
- **Identity** (`vault42 rotate-keys`): new keypair, re-wrap all the user's secrets, retire the old.
- **Transit KEK / recovery key**: see fly + Vault Transit; crypto-shred is irreversible — confirm.

## Verify the audit chain

`vault42 audit --verify` (or grobase `GET /v1/audit/tenants/{id}/verify`) recomputes the hash chain
and reports the first broken link. Run after any suspected tampering and as a periodic integrity job.
