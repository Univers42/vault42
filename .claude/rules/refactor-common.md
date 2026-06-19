---
description: Universal refactoring rules — applies to all technologies
alwaysApply: true
---

# Refactoring — Common Ground (42 philosophy)

## Structural invariants

- One function does one thing. If you need "and" to describe it, split it.
- No function exceeds the technology's line limit (see tech-specific rules)
- No file exceeds 300 lines. If it does, it's at least two modules.
- No more than 4 parameters per function. Beyond that, use a struct/object.
- Max nesting depth: 3 levels. If deeper, extract a helper.
- No dead code. No commented-out code. No TODO without a linked issue.
- No prose comments inside a function body — all commentary lives in a doc comment
  ABOVE the declaration (doxygen-style). The only in-body comments tolerated are the
  `// ponytail:`/`// perf:`/`// SAFETY:` intent tags. See [`comments.md`](comments.md).

## Naming

- Names describe behavior, not implementation
- No single-letter names outside loop indices and math formulas
- Consistent vocabulary — don't mix "fetch/get/retrieve" in the same codebase
- Acronyms follow the tech convention (e.g., HTTP in Go, http in Rust)

## Error handling

- Every fallible operation is handled explicitly
- No silent swallows — log, propagate, or convert, never ignore
- Error messages include: what failed, why, what the caller can do

## Memory and resources

- Every allocation has a clear owner and a clear free path
- No leaks — memory, file descriptors, goroutines, subscriptions, all of it
- Validate with the appropriate tool (valgrind, go vet, clippy, etc.)

## Dependencies

- No unnecessary imports. Remove every unused one.
- Prefer standard library over external dependency
- If a dependency is used for one function, inline it

## Testing

- Refactoring does not change behavior — tests must pass before AND after
- If no tests exist for the refactored code, write them FIRST
- Edge cases: empty input, max input, null/nil/undefined, concurrent access

## Commits

- Atomic: one logical change per commit
- Message format: `refactor(<scope>): <what> — <which rule>`
- Never mix refactoring with feature work in the same commit

## 42 spirit

- Simplest solution that works. No premature abstraction.
- If you can delete code instead of refactoring it, delete it.
- The best refactor is the one that reduces total line count.
- Nothing is lost, everything transforms — extract reusable pieces.
