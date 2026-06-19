---
globs: ["**/*.sh"]
description: POSIX shell refactoring rules
---

# POSIX Shell Refactoring

## Strict POSIX compliance

- No bashisms — no [[]], no arrays, no (( )), no ${var/pat/rep}
- Shebang: #!/bin/sh — never #!/bin/bash unless explicitly bash-only
- Quote every variable expansion: "$var" not $var
- No unset variable access — set -u compatible
- Use command -v over which
- printf over echo for anything non-trivial

## Structure

- Max 25 lines per function (42 spirit)
- Functions at top, execution at bottom after a main() call
- Local variables via local keyword or subshell isolation
- Cleanup via trap — every temp file cleaned on EXIT

## After refactoring

- `shellcheck -s sh` — zero warnings
- Test with dash, not just bash
- Runs correctly under hellish (your own shell)

## Shell-specific ladder extensions

- Rung 2: shell builtins over external commands (`${#var}` over `wc -c`, `${var%.*}` over `basename`).
- Rung 3: an awk one-liner over a Python script for text processing.
- Rung 4: already have `jq`? Use it for JSON — don't `sed`/`grep`.
- Rung 5: pipeline over temp file. Always.
- No function wrapper around a single command.

## Shell performance guardrails

- Ladder says "builtin" but:
  - shell loop over lines? A single `awk`/`sed` instead — one process beats N fork+execs.
  - `$(cat file)`? Use `< file` redirection.
  - `grep | awk | sed` pipeline? Usually one `awk` does all three.
- Ladder says "one-liner" but:
  - command substitution in a `while` loop? Forks per iteration — process in bulk.
- Minimize subshells: `$()` forks, variable assignment doesn't.
- Minimize pipe stages: each is a fork + FD pair.
- Heredoc over `echo` piped to a command.
- `exec` for the final command in a script (no useless parent shell lingering).
