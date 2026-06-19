---
globs: ["**/*.c", "**/*.h"]
description: C refactoring rules — 42 norminette compliance
---

# C Refactoring — Norminette Strict

## Norm compliance (non-negotiable)

- Max 25 lines per function body (excluding braces)
- Max 4 parameters per function
- Max 5 variable declarations per function
- Max 5 functions per file
- Tabs for indentation, not spaces
- Opening brace on its own line for functions
- No inline variable declaration (declare at top of scope)
- No for loops — use while
- No switch/case
- No ternary operators
- No multi-line macros unless absolutely necessary
- 42 header at top of every file

## After refactoring

- Run `norminette` on every changed file
- Zero errors, zero warnings — no exceptions
- Run under valgrind: zero leaks, zero errors
- Check with `-Wall -Wextra -Werror` — zero warnings

## C-specific patterns

- Use ft\_\* library functions where they exist, don't duplicate
- Static functions for file-internal helpers
- Header guards: `#ifndef FILENAME_H` format
- Structs typedef'd once in the header, not repeated
- Pointer ownership documented in a comment at declaration
- free() immediately followed by NULL assignment
- Every malloc checked, every open checked, every write checked

## C-specific ladder extensions

- Rung 2 (stdlib): libc covers it? Use it — no hand-rolled reimplementation, unless a 42 project explicitly forbids libc (then `ft_*` per the norm above).
- Rung 3 (platform): a POSIX API covers it? Use it over hand-rolled.
- Rung 5 (one-liner): a macro is not a one-liner. Write the function.
- `malloc` for 3 items on a known-short path? Stack array.

## C performance guardrails

- Ladder says "stdlib does it" but:
  - `strlen()` in a loop? Cache the length.
  - `strcat()` in a loop? Track the tail pointer.
  - `realloc()` per element? Geometric growth.
  - `qsort()` with `strcmp`? Consider radix sort for large N.
- Ladder says "one-liner" but:
  - One-liner that branches unpredictably? Branchless version on a hot path.
  - One-liner with division? Multiply by the inverse if called millions of times.
- Stack over heap for anything with a known bounded size.
- Array-of-structs over struct-of-arrays unless the profiler says otherwise.
- `memcpy`/`memmove` over byte loops — the compiler knows SIMD, you don't.
