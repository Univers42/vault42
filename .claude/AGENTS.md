# vault42 — agent notes

vault42 is its own repo; it cannot rely on grobase's `.claude/`. The binding code-gen rules in
`.claude/rules/` are **vendored copies** of grobase's rules (pinned to a grobase commit; refresh
manually if grobase's evolve). They apply to all vault42 code.

Always-binding for this repo (even one-off edits):

1. **Security ≈ correctness sit at the top:** `security ≈ correctness > performance > minimalism >
   readability > style`. Record trade-offs in `DECISIONS.md`.
2. **Never roll your own crypto primitives** — compose audited RustCrypto crates (see `DECISIONS.md`
   D6). If a construction has no audited implementation, stop and flag it.
3. **Plaintext and key material are radioactive** — never logged, never written unencrypted, never in
   errors/traces/shell history. Zeroize all key/plaintext buffers. Mark every line upholding a
   security invariant with a `// sec:` tag (greppable), alongside the `// ponytail:` / `// perf:` /
   `// SAFETY:` tags from `rules/minimalism-markers.md` and `rules/comments.md`.
4. **grobase stays private; vault42 is the only public surface.** If vault42 needs a security
   capability grobase lacks, add it to grobase as a reusable feature — don't patch the gap inside
   vault42 (exception: the SSH transport, which is a vault42 surface by decision D-SSH).
5. **TDD:** no crypto/protocol/auth/RBAC code lands without a failing test first. Property tests and
   fuzz targets are part of "the test." There is no separate "TDD builder" agent — use the grobase
   `security` / `reviewer` agents + the `write-test` skill + the `harden` workflow.
6. **Confirm irreversible ops** (push, tag, deploy, `fly secrets set`, crypto-shred) — explicit
   operator trigger. **No co-author trailer** on commits.
7. **Docker-first** — no host cargo for lifecycle; everything via the `Makefile`.
