# Deploying vault42-server on fly, backed by grobase (GrobaseStore)

vault42 stays its **own product** with its own identity, crypto, and business model. grobase
is only its **datastore** (zero-knowledge — it stores opaque sealed blobs it can never
decrypt). This is the "by contract" wiring: grobase provisions vault42's database and emits
the connection config; vault42-server runs as its own scale-to-zero fly app and consumes it.

```
browser ─https─ Vercel (vault42 frontend, if any)        ── stateless client
                     │  gRPC/REST
                     ▼
            vault42-server  (fly app `vault42`, scale-to-zero)   ── THE MOTOR (this repo)
                     │  /query/v1  (per-user JWT, read_scoped)
                     ▼
            grobase-stack  (fly app, Kong → data-plane → `vault42` Postgres DB)  ── THE STORE
```

## Store selection is automatic (no fly.toml edit to switch)

vault42-server picks its backend from env at boot (`crates/vault42-server/src/config.rs`):

| Condition | Backend |
|---|---|
| `VAULT42_STORE=sqlite` | embedded SQLite on the `/data` volume (offline `nano`) |
| `VAULT42_STORE` unset **and** the 5 grobase vars present | **GrobaseStore** (blobs in grobase) |
| `VAULT42_STORE` unset **and** grobase vars absent | SQLite fallback (`/data`) |

`fly.toml` does **not** set `VAULT42_STORE`, so it's in auto mode: **set the grobase secrets
below and it uses GrobaseStore; omit them and it falls back to SQLite.** No code or fly.toml
change is needed to switch.

## The 5 grobase connection vars

grobase emits four of them when it provisions the `vault42` contract
(`infra/config/contracts/vault42.json` → `build/vault42-grobase-store.env`); the fifth
(`JWT_SECRET`) is grobase's shared `GOTRUE_JWT_SECRET`.

| Var | Source | Secret? |
|---|---|---|
| `GROBASE_QUERY_URL` | grobase-stack Kong — `https://grobase-stack.fly.dev` (public) or `http://grobase-stack.flycast:8000` (private fly net, faster/free egress) | no |
| `GROBASE_ANON_KEY` | emitted `vault42-grobase-store.env` | yes |
| `GROBASE_APP_KEY` | emitted (the `vault42-app` API key) | yes |
| `GROBASE_DB_ID` | emitted (the `vault42-pg` mount id) | no |
| `JWT_SECRET` | = grobase's `GOTRUE_JWT_SECRET` | yes |

## Deploy — ordering matters (grobase first, it mints vault42's creds)

```sh
# 0. image — built + pushed by the 42-stack docker build (Docker Hub: $DOCKER_LOGIN/vault42-server)
#    fly can either build from deploy/Dockerfile (fly.toml [build].dockerfile) OR deploy the
#    pushed image directly (use-as-image, no source on the builder):
#      fly deploy -a vault42 --image docker.io/$DOCKER_LOGIN/vault42-server:latest

# 1. grobase-stack must be up and have provisioned the vault42 contract (deploy/fly/boot.sh
#    runs `provision-contract.sh vault42.json` on boot) — this writes build/vault42-grobase-store.env.

# 2. push vault42's grobase creds into fly secrets (sourced from the emitted env + the shared JWT):
source build/vault42-grobase-store.env     # GROBASE_QUERY_URL/ANON_KEY/APP_KEY/DB_ID
fly secrets set -a vault42 \
  GROBASE_QUERY_URL="https://grobase-stack.fly.dev" \
  GROBASE_ANON_KEY="$GROBASE_ANON_KEY" \
  GROBASE_APP_KEY="$GROBASE_APP_KEY" \
  GROBASE_DB_ID="$GROBASE_DB_ID" \
  JWT_SECRET="$GOTRUE_JWT_SECRET"

# 3. (optional) turn the org/team/group + per-environment scope-key feature ON for this app:
#    fly secrets set -a vault42 VAULT42_SCOPE_KEYS_ENABLED=1
#    (default OFF = byte-parity; flip only when you want the scope-key RPCs live.)

# 4. deploy:
fly deploy -a vault42        # builds deploy/Dockerfile, or add --image <dockerhub>/vault42-server:latest
```

When the grobase secrets are set, vault42-server stores every secret in grobase's `vault42`
Postgres DB via `/query/v1` (per-user JWT minting → `read_scoped` owner-scoping); the `/data`
volume becomes unused (it's only the SQLite fallback). grobase never sees a plaintext or a key.

## Why not Vercel
vault42-server is a long-lived gRPC (HTTP/2) daemon — Vercel only runs short, stateless,
request-scoped functions and cannot serve gRPC. fly with `auto_stop_machines` gives the same
"~free when idle" outcome (volume-only cost / cold-start on first request) **and** co-locates
it with grobase-stack for private-network `/query/v1` calls. See the root architecture note in
the grobase repo (`wiki/architecture/service-boundaries.md`).
