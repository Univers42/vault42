# 2. A new deployment with Docker

This chapter builds a complete vault42 deployment on one Linux host with Docker, from nothing. §2.1–2.6
give a working deployment reachable on the host itself; §2.7 puts TLS in front of it so other machines
can use it.

## 2.1 Requirements

- A Linux host (x86_64 or aarch64) with **Docker** 24 or later and **git**, 2 GB of free disk for the
  build, and 1 GB of RAM.
- For other machines to use it: a DNS name pointing at the host, ports 80 and 443 reachable, and a
  certificate that clients trust (§2.7).

## 2.2 Choose a release and build the images

```sh
git clone https://github.com/Univers42/vault42.git
cd vault42
git checkout v0.2.2
docker build -f deploy/Dockerfile.authority -t vault42-authority:v0.2.2 --build-arg VAULT42_GIT_SHA="$(git rev-parse HEAD)" .
docker build -f deploy/Dockerfile -t vault42-server:v0.2.2 .
```

Build from a **release tag** (`git tag --list 'v*'`), never from a moving branch: the tag is what
`/version` reports and what you can roll back to. Each build compiles Rust in a builder stage and takes
several minutes the first time.

The server image is also published for every release as `docker.io/dlesieur/vault42:vX.Y.Z`; the
authority image is not published and is always built.

## 2.3 Network, volumes and the invitation token

```sh
docker network create vault42
docker volume create vault42-authority-data
docker volume create vault42-server-data
REGISTER_TOKEN="$(openssl rand -base64 32 | tr -d '/+=')"
printf '%s\n' "$REGISTER_TOKEN"
```

Keep `REGISTER_TOKEN` in your password manager. Anyone who wants an account on this deployment needs
it (`42ctl auth signup --token`); leaving it unset opens sign-up to anyone who can reach the authority.

> The two volumes are the deployment. `vault42-authority-data` holds the contract signing key: if it is
> lost, every issued contract is void. Back both up (chapter 6) before anybody stores a secret.

## 2.4 Start the authority

```sh
docker run -d --name vault42-authority --network vault42 --restart unless-stopped \
  -v vault42-authority-data:/data \
  -p 127.0.0.1:8444:8444 \
  -e VAULT42_REGISTER_TOKEN="$REGISTER_TOKEN" \
  vault42-authority:v0.2.2
curl -fsS -w '\n' --retry 30 --retry-all-errors --retry-delay 1 http://127.0.0.1:8444/healthz
curl -fsS -w '\n' http://127.0.0.1:8444/version
```

`/healthz` answers `ok` once the authority listens, which takes a moment after `docker run` returns: the
retries wait for it, up to thirty seconds. `/version` answers the release and commit you built. On first
start the authority creates its database and its signing key on the volume.

## 2.5 Start the server, pinned to the authority's key

```sh
KEY="$(curl -fsS http://127.0.0.1:8444/v1/contract-key | sed 's/.*"public_key":"//;s/".*//')"
printf '%s\n' "$KEY" | grep -Eqx '[0-9a-f]{64}' &&
docker run -d --name vault42-server --network vault42 --restart unless-stopped \
  -v vault42-server-data:/data \
  -p 127.0.0.1:8443:8443 \
  -e VAULT42_CONTRACT_PUBKEY="$KEY" \
  -e VAULT42_SCOPE_KEYS_ENABLED=1 \
  vault42-server:v0.2.2
docker logs vault42-server 2>&1 | tail -3
```

**Check the key before using it.** The `grep` lets `docker run` go ahead only with 64 hexadecimal
characters. A failed `curl` would otherwise hand the server an empty value, and it would refuse to start —
or, on an older release, start without checking contracts at all. If nothing starts, print `$KEY` and read
the authority's logs.

## 2.6 Use it from 42ctl, on the same host

```sh
$ 42ctl config profile local
$ 42ctl config endpoint --authority http://127.0.0.1:8444 --server http://127.0.0.1:8443
$ 42ctl keys init
$ 42ctl auth signup --email admin@example.org --token REGISTER_TOKEN
$ 42ctl auth login --password --email admin@example.org --tenant admin
$ printf 'it works' | 42ctl vault set smoke/test
$ 42ctl vault get smoke/test
it works
```

That is a complete deployment: every feature of the 42ctl manual works against it, including shared
environments. Plain `http://` is acceptable only while both ends are on this host.

## 2.7 Serving other machines: TLS

Put a reverse proxy in front of both services. It must speak **HTTP/2 to the server** (gRPC) and present
certificates the clients trust:

- the **server** endpoint is verified against the operating system's trust store, so a certificate from a
  private CA works if every client machine trusts that CA;
- the **authority** endpoint is verified against the public web PKI bundled in 42ctl, so it needs a
  **publicly trusted** certificate, such as one from Let's Encrypt.

With [Caddy](https://caddyserver.com), which obtains Let's Encrypt certificates itself, a `Caddyfile`:

```caddyfile
auth.example.org {
	reverse_proxy vault42-authority:8444
}

vault.example.org {
	reverse_proxy h2c://vault42-server:8443
}
```

```sh
docker run -d --name vault42-proxy --network vault42 --restart unless-stopped \
  -p 80:80 -p 443:443 \
  -v "$PWD/Caddyfile":/etc/caddy/Caddyfile:ro \
  -v vault42-caddy-data:/data \
  public.ecr.aws/docker/library/caddy:2
```

Then remove the `-p 127.0.0.1:…` publications from both services (they are reachable on the `vault42`
network), and on every client:

```sh
$ 42ctl config endpoint --authority https://auth.example.org --server https://vault.example.org
```

With nginx instead, proxy the authority with `proxy_pass http://vault42-authority:8444;` and the server
with `grpc_pass grpc://vault42-server:8443;` inside an `http2`-enabled `server` block.

## 2.8 Optional features

Add these to the authority's `docker run` (chapter 4 explains each):

```sh
  -e MAIL_FROM=vault@example.org -e MAIL_PASSWORD=… -e MAIL_HOST=smtp.example.org -e MAIL_PORT=465 \
  -e VAULT42_OTP_PROOF_SECRET="$(openssl rand -hex 32)" \
  -e GITHUB_CLIENT_ID=Iv1.… \
```

The three second-factor variables go together: the authority refuses to start with only some of them. An
object store for large files needs no server configuration at all; users configure it in their profiles.

## 2.9 Upgrading

Build the new release's images (§2.2), then replace the containers in the same order, **authority first**,
reusing the same volumes. The signing key stays on the volume, so the server's `VAULT42_CONTRACT_PUBKEY`
does not change. Take a backup first (chapter 6). Migrations run at start and are forward-only: to roll
back, restore the backup taken before the upgrade.
