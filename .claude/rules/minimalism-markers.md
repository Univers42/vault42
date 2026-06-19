---
description: Minimalism markers and documentation rules
alwaysApply: true
---

# Minimalism markers

When you take a deliberate shortcut on the ladder, mark it:

```
// ponytail: <what was simplified> — <upgrade path if needed>
```

Examples:

- `// ponytail: global lock — per-account locks if throughput matters`
- `// ponytail: linear scan — index if list exceeds ~1k items`
- `// ponytail: hardcoded timeout — config if users need control`

This reads as intent, not ignorance. The comment names the ceiling and what to do when you hit it.

The performance counterpart is `// perf:` — it marks where performance overrode minimalism on a hot path (see [`minimalism-ladder.md`](minimalism-ladder.md)):

`// perf: O(n) manual loop over O(n²) stdlib — hot path, called per-request`

The security counterpart (**vault42 extension**) is `// sec:` — it marks a line that
upholds a security invariant in this zero-knowledge vault, so reviewers find them with one grep:

`// sec: DEK zeroized on drop` · `// sec: verify before decrypt` · `// sec: bind response to requested scope`

## Documentation minimalism

- Code first. Then at most three short comment lines — and those lines live in the
  doc comment **above** the function, never inside its body (see [`comments.md`](comments.md)).
  The `// ponytail:`/`// perf:` markers are the only in-body comments tolerated.
- If the explanation is longer than the code, delete the explanation.
- Every paragraph defending a simplification is complexity smuggled back as prose.
- Exception: if the user explicitly asked for a report or walkthrough, give it in full.
