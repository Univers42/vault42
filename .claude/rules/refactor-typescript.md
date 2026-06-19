---
globs: ["**/*.ts", "**/*.tsx"]
description: TypeScript refactoring rules
---

# TypeScript Refactoring

## Idioms

- Max 40 lines per function
- No `any` — use `unknown` + type guard if truly dynamic
- No enums — use const objects with `as const`
- Prefer type over interface unless extending
- No barrel exports (index.ts re-exporting everything)
- Named exports only, no default exports
- Nullish coalescing (??) over logical OR (||) for defaults

## React-specific (when in .tsx)

- Components under 100 lines including JSX
- No business logic in components — extract to hooks or utils
- useMemo/useCallback only when profiler proves a need
- Props interface named <ComponentName>Props
- No prop drilling beyond 2 levels — use context or composition

## After refactoring

- `tsc --noEmit` — zero errors
- `eslint . --max-warnings 0` — zero warnings
- All tests pass

## TS-specific ladder extensions

- Rung 2: `Array.prototype` methods over lodash for map/filter/reduce.
- Rung 3: `<input type="date">` over a date-picker lib, CSS grid over a layout lib, `<dialog>` over a modal lib.
- Rung 4: already have zod? Use it — don't hand-roll validation.
- Rung 5: `Object.fromEntries`, `structuredClone`, the `URL` constructor — one-liners people forget exist.
- No `React.memo` unless the profiler proves a re-render problem.

## TS performance guardrails

- Ladder says "stdlib" but:
  - `Array.filter().map()` chains? A single `reduce` or `for` loop avoids the intermediate array.
  - `JSON.parse/stringify` for deep clone? `structuredClone` is faster — but keep a reference if you can.
  - spread for large objects? `Object.assign` or a manual copy.
- Ladder says "one-liner" but:
  - `new RegExp()` inside a loop? Compile once outside.
  - template literal in a tight loop? String concatenation can be faster.
  - optional chaining 10 levels deep? Destructure once at entry.
- `WeakMap`/`WeakRef` for caches that shouldn't prevent GC.
- Avoid closures capturing large scopes on hot paths.
- TypedArrays (`Uint8Array`, `Float64Array`) over regular arrays for numeric-heavy work.
