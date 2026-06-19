---
globs: ["**/*.go", "**/*.ts", "**/*.tsx", "**/*.rs", "**/*.c", "**/*.h", "**/*.sh"]
description: Global mutable state is banned in every technology
---

# No Global Variables (all technologies)

Global mutable state is banned. A package-level / file-level / module-level
**variable** is not allowed in any language. State is passed in, owned by a
value, and made explicit — never reached for through a global.

## Why

- Globals are invisible inputs: a function that reads one isn't honest about
  what it depends on.
- They couple test order, defeat parallelism, and hide data races.
- They make ownership and lifetime impossible to reason about locally.

## The rule

- **No package-level `var`** (Go), no module-level mutable binding (TS `let`/
  mutable `const` objects used as state), no file-scope mutable statics (C),
  no `static mut` / mutable `lazy_static` (Rust).
- Configuration, clients, pools, counters, caches, clocks, and limiters are
  **dependency-injected**: a field on the struct/object that uses them,
  constructed once at the composition root (`main`, a `New…` constructor) and
  threaded down.

## The only exceptions — and how to express what looks like a global

| Looks like a global | Do this instead |
|---|---|
| **Compile-time embedded asset** (`//go:embed`) | Allowed — the compiler *requires* a package var. Keep it unexported, read-only. |
| **Sentinel error** (`var ErrX = errors.New(…)`) | A **const error type**: `type cfgErr string; func (e cfgErr) Error() string { return string(e) }` then `const ErrX cfgErr = "…"`. Still matches `errors.Is`; no `var`. |
| **Compiled regexp** | A **struct field** compiled in the constructor, or a `sync.OnceValue` accessor — never a bare package var, never compiled per-call (perf). |
| **Fixed lookup set/table** | A **switch-based predicate function** (`func isAllowed(s string) bool { switch s { … } }`) — no `var`, no map alloc, faster for small N. A large data table becomes a struct field built once in a constructor. |
| **True constant** (number, string, enum) | `const`. |
| **Singleton dependency** (metrics sink, DB pool, logger) | Inject it. One process may still construct exactly one at `main`, but it travels as a parameter/field, not a package var. |

## After

- Grep for `^var ` / `^\tvar ` (Go), module-scope `let`/`var` (TS), `static`
  (C), `static mut` / `lazy_static!` / `once_cell` globals (Rust). The only
  hits allowed are `//go:embed` targets.
- Errors still satisfy `errors.Is`; regexes still compile once; behavior and
  performance are unchanged. De-globalizing is a structural change, never a
  behavioral one.
