---
globs: ["**/*.go", "**/*.rs", "**/*.ts", "**/*.tsx", "**/*.c", "**/*.h", "**/*.sh", "**/*.mjs", "**/*.py"]
description: Comments live ABOVE the function, never inside its body
---

# Function comments — above, never inside (all technologies)

A function body carries **NO prose comments**. Every explanation a function needs
lives in **ONE doc comment directly ABOVE its declaration**. The body is code only.

## Why

- A comment inside a body is a confession the code isn't clear there — fix the
  code (rename, extract a named helper, restructure) instead of narrating it.
- One doc block above the signature is the single place a reader looks; in-body
  asides drift from the code they describe and outlive it.
- Tooling renders the doc-above (`godoc`, `rustdoc`, TSDoc/JSDoc); it never
  renders an in-body comment.

## The rule

- **No comment inside a function body.** Not above a statement, not trailing a
  line, not between blocks. If you reach for one, that is the signal to SPLIT the
  body into named helpers (each within the tech's line limit) whose *names* carry
  the meaning the comment would have.
- **All commentary goes in the doc comment above the declaration**, written
  documentation-style (the doxygen spirit): a one-line summary of what the
  function does, then — only when the signature isn't self-evident — what each
  parameter means, what it returns, and what it errors/panics on.
  - **Go:** the doc block MUST start with the identifier name (`// Foo does …`)
    so `godoc`/`go vet` recognise it; doxygen-style `@param`/`@return` lines may
    follow *inside that same block* when they add real clarity.
  - **Rust:** `///` item docs. **TS/JS:** `/** … */` (TSDoc/JSDoc). **C:** a
    block comment above the function. **Shell/Python:** a comment block above the
    function. Same discipline everywhere.
- No commented-out code, ever — delete it, git remembers.

## The only tolerated in-body comments

These are structured single-line **intent tags**, not prose, so they stay:

- `// ponytail: …` — a deliberate simplification ([`minimalism-markers.md`](minimalism-markers.md)).
- `// perf: …` — performance overriding minimalism on a hot path ([`minimalism-ladder.md`](minimalism-ladder.md)).
- `// SAFETY: …` — the mandatory invariant note above a Rust `unsafe` block ([`refactor-rust.md`](refactor-rust.md)).
- `// sec: …` — **(vault42 extension)** marks a line that upholds a security
  invariant (zeroization, verify-before-decrypt, an AAD binding, owner-scoping).
  vault42 is a zero-knowledge vault; the build contract requires these to be
  greppable. Same discipline as `// perf:`: a fixed intent tag, not prose.

Nothing else qualifies. A tag earns its place by being a fixed, greppable marker
of intent — not an explanation of what the next line does.

## Formatting — run the language's stricter formatter ("prettier")

After writing/refactoring, normalise layout with more than the default formatter:

- **Go: `gofumpt`** — a stricter, behaviour-preserving superset of `gofmt`.
  Prefer it over plain `gofmt`: `gofumpt -l -w .` (run in the toolchain
  container, Docker-first). `golines -w .` additionally wraps over-long lines and
  struct-literal call sites if any linger after gofumpt.
- **Rust:** `cargo fmt`. **TS/JS:** `prettier`. **C:** keep the norm + a
  consistent `clang-format`. **Shell:** stay POSIX; `shfmt -p` if available.

## After

- Grep any changed function body for a comment leader (`//`, `/*`, `#`): the only
  hits allowed are the three intent tags above. Everything else moved to the doc
  block or was deleted by splitting the function.
- Every public/exported function has a doc comment above it; the body is code.
- The formatter ran clean (`gofumpt -l` prints nothing for Go).
