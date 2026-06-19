# vault42 — HUMAN-ATOMS

The human / money / external-account actions vault42 needs to reach GA. The build can produce every
artifact; these require a person. Legend: 🔵 web/account · ⚪ command a human runs · 📌 irreversible
(held for explicit trigger) · 💰 costs money. Status: ✅ done · ⬜ remaining · 🟡 partial/changed.

| # | Atom | Kind | Status |
|---|---|---|---|
| 1 | fly.io account + org + billing | 🔵 💰 | ✅ deployed to the `personal` org |
| 2 | Region + app allocation | 🔵 ⚪ | ✅ app `vault42` in `cdg` (Madrid not offered — D10); single public app, no separate private-grobase app (D9) |
| 3 | Domain + DNS for the public endpoint | 🔵 💰 ⚪ | 🟡 using `vault42.fly.dev` (fly-managed); a custom domain is optional |
| 4 | TLS certificate → TLS 1.3 | 🔵 ⚪ | ✅ fly edge cert on `vault42.fly.dev` (auto LE); BYO only if a custom domain is added |
| 5 | `fly secrets` (`INTERNAL_SERVICE_TOKEN`, `KEY_HASH_PEPPER`, unseal/recovery seeds) | ⚪ 📌 | ⬜ NOT required for the standalone MVP (Ed25519 client auth + own SQLite, D9); needed only to wire grobase/recovery |
| 6 | HashiCorp Vault Transit / KMS for KEK + recovery escrow | 🔵 ⚪ 💰 | ⬜ for L2 CMEK (D8) + recovery (D5) — not in the shipped MVP |
| 7 | WireGuard peer for operator → private grobase | ⚪ | ⬜ only when a private grobase is stood up |
| 8 | GitHub branch protection + required CI + secret scanning | 🔵 | ⬜ on first push |
| 9 | First `git push` to `main`/`develop` + tag `v0.1.0` | ⚪ 📌 | ⬜ HELD — never pushed (binding rule); commits are local on `develop` |
| 10 | fly volume (encrypted, sealed-state mount) | ⚪ 💰 | ✅ `vault42_data` (encrypted) in `cdg` at `/data` |
| 11 | `testssl.sh` / `ssh-audit` against live endpoints | ⚪ | ⬜ run at GA hardening |
| 12 | Unseal ceremony (threshold shares) | ⚪ 📌 | ⬜ for the L2 seal model (not in MVP) |
| 13 | Vendor full AGPL-3.0 text into `LICENSE` (legal) | ⚪ | ⬜ before public release |

`FLY_TOKEN` lives in grobase `.env.local` — reused for deploys, **never printed**. The deployed MVP
runs **standalone** (no fly secrets needed): identity is the client's Ed25519 key, storage is the
app's own encrypted-volume SQLite. Atoms 5–7, 12 are for the grobase-substrate / L2-CMEK / recovery
upgrades, which are built and flag-gated but off in the shipped product.
