# 3. A new deployment on fly.io

This is how the public deployment runs: two scale-to-zero fly.io applications, deployed by GitHub
Actions every time a release is cut. It costs, idle, the two 1 GB volumes and nothing else. Production
was rebuilt from an empty fly.io account this way on 2026-09-13.

## 3.1 Requirements

- A fly.io account and an **organisation** (`personal` is the default one).
- A GitHub repository holding vault42 — this one, or a fork — with Actions enabled.
- Docker and git on the machine you run the first steps from. flyctl need not be installed: it runs from
  its image.

## 3.2 Names

fly.io application names are global. The public deployment uses `vault42-authority` and
`vault42-server`; a new deployment chooses its own and writes them in:

| File | What to change |
|---|---|
| `fly.authority.toml` | `app = "…"`, and `primary_region` |
| `fly.toml` | `app = "…"`, and `primary_region` |
| `.github/workflows/deploy.yml` | `AUTHORITY_URL`, `SERVER_URL`, and the `--app` of every step |
| `.github/workflows/scenario.yml`, `machines.yml` | the URLs and application names |
| `scripts/smoke/post-deploy.sh`, `scripts/ops/fly-machines.sh` | the default URLs and application names |

The rest of this chapter uses `AUTH_APP` and `SERVER_APP` for the two names, and
`https://AUTH_APP.fly.dev`, `https://SERVER_APP.fly.dev` for their addresses.

## 3.3 A deploy token

Create a token able to deploy in the organisation (fly.io dashboard → Tokens, or `fly tokens create
deploy`). Keep it in a file outside the repository and pass it **by name**:

```sh
export FLY_API_TOKEN="$(cat ~/secrets/fly-deploy-token)"
FLY="docker run --rm -e FLY_API_TOKEN flyio/flyctl:v0.4.101"
```

Never write `-e FLY_API_TOKEN=$(…)`: a fly token contains a space, and the shell splits it.

## 3.4 Create the applications and volumes (once)

```sh
$FLY apps create AUTH_APP --org personal
$FLY apps create SERVER_APP --org personal
$FLY volumes create vault42_authority_data --app AUTH_APP --region cdg --size 1 --yes
$FLY volumes create vault42_data --app SERVER_APP --region cdg --size 1 --yes
```

Volume names must match the `[[mounts]] source` in each `fly*.toml`. fly.io volumes are encrypted at rest
and snapshotted daily by default.

## 3.5 The repository's Actions secrets

Settings → Secrets and variables → Actions → *New repository secret*:

| Secret | Needed by | Value |
|---|---|---|
| `FLY_API_TOKEN` | `deploy.yml`, `machines.yml`, `scenario.yml` | the deploy token of §3.3 |
| `GH_PAT` | `auto-release.yml` | a GitHub token with `contents: write` on the repository — the release tag must be pushed with it, because a tag pushed with the workflow's own token starts no deploy |
| `VAULT42_REGISTER_TOKEN` | `deploy.yml` (staged on the authority) | a random string; people signing up need it. Leave unset for open sign-up |
| `MAIL_FROM`, `MAIL_PASSWORD`, `VAULT42_OTP_PROOF_SECRET` | `deploy.yml` (staged on the authority) | an SMTP sender and its password, and `openssl rand -hex 32`. All three, or none |
| `DOCK_PAT` | `docker.yml` | a Docker Hub access token, to publish the server image; optional |

The deploy workflow stages the authority's secrets itself before every release, so they never need to be
set on fly.io by hand — and a re-created application gets them back automatically.

## 3.6 The first deploy

The first deploy has nothing to pin the server to, so run it once from the Actions tab: **deploy** →
*Run workflow* → `both`. The workflow:

1. stages the authority's secrets from the repository's secrets;
2. builds and deploys the authority, labelled with the version;
3. fetches the authority's public key from `https://AUTH_APP.fly.dev/v1/contract-key`, refuses it unless
   it is 64 hexadecimal characters, and stages it on the server as `VAULT42_CONTRACT_PUBKEY`;
4. builds and deploys the server;
5. runs `scripts/smoke/post-deploy.sh`: the authority is healthy and answers `/version` with this release,
   its contract key is well formed, a protected route answers 401, the server speaks gRPC through fly's
   edge and refuses an unauthenticated call;
6. stops both machines again, so they sit at zero until the next request.

The same steps by hand, if the automation is what is broken, are in `RUNBOOK.md`.

## 3.7 From then on

Nothing is manual. Every commit that `vault42-ci` passes on `develop` becomes a release, and the release
deploys itself (chapter 5). Check what production runs:

```sh
curl -fsS https://AUTH_APP.fly.dev/version
```

## 3.8 Pointing 42ctl at it

A 42ctl build points at the public deployment by default. For another deployment:

```sh
$ 42ctl config endpoint --authority https://AUTH_APP.fly.dev --server https://SERVER_APP.fly.dev
```

## 3.9 What it costs

| Resource | Count | Note |
|---|---|---|
| machines | 1 per application, `shared-cpu-1x`, 256 MB | stopped when idle (`auto_stop_machines = "stop"`); a request wakes one in about 1.5 s |
| volumes | 1 GB per application | the only standing charge |
| dedicated IPv4 | 0 | the shared IPv4 and a free IPv6 are used |
| builders | 0 | images are built on the GitHub runner (`--local-only`) |

`42ctl cloud health` and the deploy's smoke test wake the machines; the deploy stops them again.
