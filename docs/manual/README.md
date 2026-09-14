# The vault42 Operator's Manual

**Building, configuring, releasing and running a vault42 deployment.**

This edition documents vault42 0.2.2 and later releases until it says otherwise. The users' half — how
people use a deployment through `42ctl` — is [The 42ctl Manual](https://github.com/Univers42/42ctl/tree/main/docs/manual).

| | Chapter | What it answers |
|---|---|---|
| 1 | [Architecture](01-architecture.md) | The two services, what each stores, what each trusts, how they are wired |
| 2 | [A new deployment with Docker](02-deploy-docker.md) | From an empty Linux host to a working vault, step by step |
| 3 | [A new deployment on fly.io](03-deploy-fly.md) | From an empty fly.io account to the automated pipeline production uses |
| 4 | [Configuration reference](04-configuration.md) | Every environment variable of both services, with its default and its consequence |
| 5 | [Releases and deploys](05-releases.md) | How a merge becomes a version and the version reaches production |
| 6 | [Operations](06-operations.md) | Health and version, backups and restores, the deployment's own secrets, upgrades, cost |
| 7 | [Troubleshooting](07-troubleshooting.md) | A service that will not start, a client that is refused |

## Conventions

A line beginning with `$ ` in a command block is typed; other lines are output. CAPITALISED words are
placeholders: `REGISTER_TOKEN`, `AUTH_HOST`. `example.org` names stand for your own domain.

> A block like this is a warning: an action that cannot be undone, or a mistake that fails silently.

## How this manual is kept true

Chapter 2 §2.2–2.6 and the Docker backups of chapter 6 §6.2 are **executed as written**: 42ctl's
`qa/live/self-host.sh` extracts their shell blocks from the release under test, runs them on an empty
machine, drives the 42ctl walkthrough (that manual's chapter 13) through the deployment they built, then
takes the backups and checks the deployment still serves. The **walkthrough** workflow in the 42ctl
repository runs it.

Not executed: the TLS proxies of §2.7, the optional features of §2.8, chapter 3 beyond what production's
own pipeline does on every release, restores, and contract-key rotation, which chapter 6 says has no
tested procedure.

Where this manual and a comment in the code disagree, the code is right and the manual has a bug:
report it.
