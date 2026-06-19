---
globs: ["**/*.go"]
description: Go packages are organised by domain/capability, not by type; minimal exports
---

# Go Package Design — package by domain, not by type

A package is **one responsibility / one domain concept**, not a folder of
related file-types. This governs how the Go code in this repo is organised.

## Package by feature/domain

Never group by type:

```
✗  models/   services/   utils/   helpers/   interfaces/   structs/
```

Group by capability/domain — each package owns *everything* about its concept:

```
✓  tenants/   provision/   metering/   audit/   sso/   pg/   httpx/
```

```
tenants/
├── tenants.go        // the Tenant type + its domain logic
├── repository.go     // persistence for tenants
├── service.go        // tenant operations
```

The test: **"if I removed this package, what capability disappears?"**
`payment` → payment processing disappears. `utils` → ??? — that's the smell.

## Banned package names (junk drawers)

`utils` · `common` · `helpers` · `misc` · `shared` · `base` · `core` (when used
as a catch-all). They have no single responsibility, so they accrete unrelated
functions until nobody knows where anything lives. A helper belongs in the
domain package whose concept it serves; a genuinely cross-cutting concern
(HTTP plumbing, the DB pool, observability) is its **own named domain package**
(`httpx`, `pg`, `observability`), not a `shared` dump.

The Go stdlib is the model: `fmt`, `net/http`, `encoding/json`, `database/sql`,
`crypto/tls` — each name states one specific responsibility.

## Minimal exports (~80 / 20)

Export only what another package must call. Most of a package is unexported.

```go
package user

type User struct { … }   // exported — other packages need the type
type repository struct{} // unexported — an implementation detail
func Create(…) {}        // exported — the package's API
func validate(…) {}      // unexported — internal
```

- Capital letter = part of the contract you must keep stable. Keep that surface
  small; it's the package's promise.
- Prefer unexported by default; promote to exported only when a real
  cross-package caller appears. Deletion over addition still applies.
- One concept → one source of truth. A type/constant/helper is defined in its
  owning package and imported, never copied.

## After

- No package named `utils`/`common`/`helpers`/`misc`/`shared`/`base`.
- Each package answers the "what capability disappears" test in one sentence.
- The exported surface is small and each exported name has ≥1 external caller.
