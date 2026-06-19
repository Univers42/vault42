# vault42 — HUMAN-ATOMS

The human / money / external-account actions vault42 needs to reach GA. The build can produce every
artifact; these require a person. Legend: 🔵 web/account · ⚪ command a human runs · 📌 irreversible
(held for explicit trigger) · 💰 costs money.

| # | Atom | Kind | Unblocks |
|---|---|---|---|
| 1 | fly.io account + org + billing | 🔵 💰 | any fly deploy (P9) |
| 2 | Confirm region `mad` + allocate apps (public gateway, private grobase) | 🔵 ⚪ | P9 topology |
| 3 | Domain + DNS for the public vault42 gateway | 🔵 💰 ⚪ | public HTTPS endpoint |
| 4 | TLS certificate (fly-managed LE or BYO) → TLS 1.3 | 🔵 ⚪ | testssl.sh PASS, P9 DoD |
| 5 | Provision `fly secrets`: `VAULT42_UNSEAL_SEED`, `VAULT42_RECOVERY_KEY`, `INTERNAL_SERVICE_TOKEN`, `KEY_HASH_PEPPER` | ⚪ 📌 | unseal, HMAC hop, recovery (P3/P9) |
| 6 | HashiCorp Vault Transit (or KMS) setup for the master KEK + recovery escrow | 🔵 ⚪ 💰 | key rotation (P7), recovery (D5) |
| 7 | WireGuard peer/key for operator → grobase private network | ⚪ | operator hop, network policy (P9) |
| 8 | GitHub `Univers42/vault42`: branch protection on `main`, required CI checks, secret scanning | 🔵 | gitflow guardrails (P0) |
| 9 | First `git push` to vault42 `main`/`develop` + release tag `v0.1.0` | ⚪ 📌 | release (held) |
| 10 | fly volume (encrypted, sealed-state mount) | ⚪ 💰 | P9 seal state |
| 11 | Run TLS/SSH validation: `testssl.sh`, `ssh-audit` against live endpoints | ⚪ | P9 DoD proof |
| 12 | Unseal ceremony (provide threshold shares post-deploy) | ⚪ 📌 | first UNSEALED boot |
| 13 | Vendor the full AGPL-3.0 text into `LICENSE` (legal review) | ⚪ | public release |

`FLY_TOKEN` already exists in grobase `.env.local` — reused for deploys, **never printed**.
