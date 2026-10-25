# Task Checklist (copy into every task / PR body)

Canonical rules: `PROJECT_RULES.md`. Execution guide: `docs/SELF-ATTACK.md`.

## Before writing code

- [ ] Scope written: what changes, what does **not** change.
- [ ] Risks named: auth, tenancy, input parsing, concurrency, secrets, perf.
- [ ] Test plan written: unit + integration + e2e (+ adversarial if
      security-sensitive, + many-users if shared state).

## While building

- [ ] Unit test for every branch/decision.
- [ ] Integration test for every boundary (CLI, git diff, file, artifact).
- [ ] E2E test runs the real entrypoint in a temp repo.
- [ ] Adversarial test: malformed/hostile input, path tricks, prompt
      injection, oversized input, failure paths.
- [ ] Many-users test: >= 8 parallel calls, disjoint inputs, no bleed,
      identical-to-serial results.
- [ ] Bounded-time test for any algorithmic change.

## Before saying "done"

- [ ] `python -m pytest tests/ -q` (full suite) is green.
- [ ] `python benchmarks/run.py --verify` has no F1 regression (rule changes).
- [ ] `ruff check` and `ruff format --check` are clean.
- [ ] `python scripts/quality_gate.py --base <base>` is green.
- [ ] Self-attack executed: `python scripts/self_attack.py --quick --json`.
- [ ] I personally attacked the change (not only ran tests) and recorded
      what held / what failed.
- [ ] Docs + CHANGELOG updated; unexecuted claims labelled `UNVERIFIED`.
- [ ] No secrets, tokens, cookies, or other users' PII in code, logs,
      comments, tests, reports, or diffs.
- [ ] Commit message states what was **proven**, not just what changed.

## Never accept

- "All tests pass" as the whole argument.
- Mocks/stubs in shipped paths.
- Downgrading a gate verdict to make CI green.
- Deleting or weakening a test to pass.
- A concurrency claim tested sequentially.
