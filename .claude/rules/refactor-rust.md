---
globs: ["**/*.rs"]
description: Rust refactoring rules
---

# Rust Refactoring

## Idioms

- Max 40 lines per function
- Use Result<T, E> everywhere, no unwrap() outside tests
- Prefer &str over String in function parameters
- Derive only what you use
- No .clone() to satisfy the borrow checker — fix the ownership
- If a struct has more than 5 fields, consider splitting
- Impl blocks: public methods first, then private, then trait impls

## Patterns

- Builder pattern for anything with 3+ optional config fields
- Newtype pattern over type aliases for domain types
- thiserror for library errors, anyhow for binary errors

## After refactoring

- `cargo clippy -- -D warnings` — zero warnings
- `cargo test` — zero failures
- `cargo fmt --check` — already formatted
- No unsafe without a SAFETY comment explaining the invariant

## Rust-specific ladder extensions

- Rung 2: `std::collections`, `std::fs`, `std::io` before any crate.
- Rung 3: derive macros over a hand-impl when semantics match.
- Rung 4: already have `serde`? Use `serde_json`, not a hand-parser.
- No newtype wrapper unless it prevents a real misuse (not a theoretical one).
- No trait with one implementor unless it's a port boundary.

## Rust performance guardrails

- Ladder says "stdlib" but:
  - `String::from` + `push_str` in a loop? `with_capacity` upfront.
  - `Vec::push` in a loop? `reserve` upfront.
  - `HashMap` for small N (< 20)? A `Vec` of tuples + linear scan is faster.
  - `format!()` on a hot path? Write to a reusable buffer.
- Ladder says "one-liner" but:
  - `.collect::<Vec<_>>()` intermediate? Iterate without collecting.
  - `.clone()` to satisfy borrows? Restructure lifetimes.
  - `Box<dyn Trait>` on a hot path? Monomorphize with generics.
- `#[inline]` on small hot functions that cross crate boundaries.
- Avoid `Arc<Mutex<>>` on hot paths — consider lock-free or per-thread state.
- `&[u8]` over `&str` when you don't need UTF-8 validation on the fast path.
