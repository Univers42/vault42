# Verify gates — the discipline, not the list

Every rule here was written by a gate that lied. They are in the order they were learned.

`scripts/verify/run-gate-battery.sh [--fast|--all|<gate>...] [--strict]`.

`--fast` is the per-PR subset, listed in `FAST_GATES`; register a new fast gate there explicitly.
`--all` runs every `v*-*.sh`. `m71-grobase-substrate.sh` does not match that glob and only runs when
named. Eleven gates pass under `--all --strict` today: v01, v12, v16-v21, v25-v27.

**Gates SKIP rather than fail when a prerequisite is missing**, so a fresh machine would report
success having run nothing. Pass `--strict` to turn any SKIP into a failure; CI must use it. Gates
are invoked with `sh`, and `/bin/sh` is bash on this box, so test a new gate under `dash` before
trusting it.

A gate asserts on the tested command's **exit status**, never on a grep for a test count. Both
existing forms of that mistake have been fixed and must not come back: a count drifts, and a
`cmd; grep; chown` chain inside one `sh -c` returns `chown`'s status and discards the assertion.

**Prove a new gate can fail before trusting it.** Break the thing it guards, watch it exit non-zero,
restore, watch it pass. This has caught two false passes: v01 could not fail at all, and v26's first
version passed with its load-bearing check deleted because each route-level assertion happened to be
covered by a different protection. A gate that has never failed is a claim, not a check.

**An absence assertion must prove its haystack.** `assert!(!haystack.contains(needle))` passes when
the haystack is empty, so it must be preceded by a positive control asserting that something which
MUST be there is found. The QA session's zero-knowledge checks were vacuous for their whole life
because a helper copied only the `.db` while WAL kept the rows in the `-wal` beside it; they would
have passed identically had the server written plaintext to disk. `envelope_on_the_wire_has_no_plaintext`
had the same hole here, and its name claimed a wire it never touched.

**Nothing in the battery runs a binary's startup path unless a gate does it explicitly.** Every
authority gate drives the in-process harness, which builds `Authority` directly and never calls
`main`, and v12 supplies a seed which takes a different branch. So `serve`'s ordering was untested
by ten green gates until v27, and a fail-closed check that made every first start impossible shipped
through CI. Cover the entrypoint, not just the routes.

An assertion driven through a route may be satisfied by something other than the rule you meant to
test. When a rule has no reachable route that isolates it, reach past the routes: `Store::call` is
`pub(crate)`, so a test can strip one row and assert the rule directly. `e2e_offboard.rs`'s
`a_grant_never_authorizes_a_non_member` is the pattern.
