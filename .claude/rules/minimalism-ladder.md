---
description: Minimalism decision ladder with performance guardrail
alwaysApply: true
---

# Code generation ladder

Before writing ANY code, walk top to bottom. Stop at the first rung that works:

1. **YAGNI** — Does this need to exist at all? Speculative = skip it, say so in one line.
2. **Stdlib** — Standard library does it? Use it. No wrapper.
3. **Platform** — Native platform feature covers it? HTML input type over a picker lib, CSS over JS,
   DB constraint over app code, shell builtin over external tool.
4. **Existing dep** — Already-installed dependency solves it? Use it. Never add a new dependency for
   what a few lines can do.
5. **One-liner** — Can it be one line? One line.
6. **Minimum** — Only then: the minimum code that works.

Two rungs work → take the higher one.
The first simple solution that works is the right one.

## Performance override — outranks every rung above

The ladder picks the simplest solution. This guardrail vetoes it if it's not the fastest.

Before committing to any rung, answer:

- **Complexity**: what's the Big-O? If a higher rung is worse asymptotic complexity than a lower rung, take the lower rung.
- **Hot path**: is this on a hot path (request handling, query execution, serialization, auth — anything called per-request)? If yes, performance wins over minimalism. Always.
- **Allocation**: does the simple version allocate where the verbose version doesn't? Zero-alloc wins. Every time.
- **Copy vs reference**: does the one-liner copy data the explicit version can reference? Reference wins.
- **Syscall count**: does the stdlib convenience make 3 syscalls where a manual approach makes 1? Fewer syscalls wins.

If the override fires, document it:

```
// perf: O(n) manual loop over O(n²) stdlib — hot path, called per-request
```

The override is narrow — NOT an excuse to over-engineer:

- It applies only when there's a MEASURABLE difference. "Might be faster" is not a measurement.
- On cold paths (startup, config loading, CLI parsing), the ladder wins unconditionally — nobody cares if boot takes 1 ms more.
- When in doubt: write the simple version FIRST, benchmark it, optimize only if the numbers justify it.

## The hierarchy

```
correctness > performance > minimalism > readability > style
```

- Never sacrifice correctness for performance.
- Never sacrifice performance for minimalism on hot paths.
- Never sacrifice minimalism for readability on cold paths.

## Never

- Interface with one implementation
- Factory for one product
- Config for a value that never changes
- Wrapper around a function that's already clean
- Scaffolding "for later" — later can scaffold for itself
- Boilerplate, ceremony, "just in case"
- Deletion over addition. Always.

Language-specific rungs live in the `refactor-<tech>.md` rules — they load when you touch that language.
