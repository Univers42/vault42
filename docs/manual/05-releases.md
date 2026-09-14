# 5. Releases and deploys

## 5.1 A merge is a release

```text
 pull request ──merge──▶ develop
                           │
                  vault42-ci passes (fmt, clippy, tests, gate battery)
                           │
                  auto-release.yml
                     ├─ scripts/ops/release-version.sh next      → 0.2.3
                     ├─ commit "release: v0.2.3" (Cargo.toml, Cargo.lock)
                     ├─ tag v0.2.3, push develop + tag together (GH_PAT)
                     ├─ fast-forward main
                     └─ publish the GitHub Release, with generated notes
                           │ the tag push starts
            ┌──────────────┴───────────────┐
      deploy.yml                      docker.yml
      ├─ re-check CI passed           └─ docker.io/dlesieur/vault42:v0.2.3, signed
      ├─ deploy authority, then server (images labelled v0.2.3)
      ├─ smoke test: /version must answer 0.2.3 and this commit
      └─ stop the machines
```

Every commit CI passes on `develop` becomes the next **patch** version and is deployed. A red commit is
never released; a tag pushed by hand on a commit CI did not pass is refused by the deploy.

## 5.2 A minor or major version

The version in `Cargo.toml` is the next release's when no tag names it yet. To release `0.3.0` instead of
the next patch, raise it in the pull request:

```sh
sh scripts/ops/release-version.sh set 0.3.0
git commit -am "release: prepare 0.3.0"
```

The first green CI after the merge releases `v0.3.0`. The script refuses a version below the highest
existing release.

## 5.3 What is running

```sh
curl -fsS https://vault42-authority.fly.dev/version
```

answers `{"commit":"…","version":"0.2.3"}`. The fly image of each application is labelled with the same
version (`fly status --app vault42-server`, `42ctl cloud status`).

## 5.4 Deploying by hand

From the Actions tab, **deploy** → *Run workflow*, with `both`, `authority` or `server`. A manual deploy of
a commit that is not a release tag is labelled with its commit (`v0.2.3-g1a2b3c4`), so it can never pass
for a release. Only a deploy that includes the authority checks `/version`.

## 5.5 Rolling back

Deploy the previous tag: *Run workflow* on the tag `v0.2.2`. Database migrations are forward-only, so a
rollback across a migration needs the backup taken before it (chapter 6).

## 5.6 What the pipeline needs

The repository secrets of chapter 3 §3.5. Without `GH_PAT`, auto-release fails rather than pushing a tag
that would deploy nothing; without `FLY_API_TOKEN`, deploys fail.
