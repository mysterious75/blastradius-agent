# PROJECT_RULES.md — how work gets accepted in this repo

> Read this **before starting any task**. These rules are enforced by
> `scripts/quality_gate.py` in CI. A task is not "done" because code was
> written or tests are green — it is done when this document's checklist
> passes **and** the work survived a self-attack pass.

## 0. Non-negotiables

1. **Never claim, always prove.** No "verified", "fixed", "exploitable",
   or "secure" without executed evidence. Untestable → write `UNVERIFIED`.
2. **Fail closed.** Unsupported language, shape, sandbox, or bytecode is
   `INCONCLUSIVE` → blocks. Never downgrade to "probably fine".
3. **No fake functionality.** No stubs, mocks-only paths, or hardcoded
   verdicts in shipped code. Fixtures are allowed only in tests.
4. **Authorized targets only.** Repo scanning, sandbox execution, and any
   network probe must stay inside written permission / `blastradius scope`.
5. **Secrets never leave the machine.** No credentials, tokens, cookies,
   or other users' PII in code, tests, logs, comments, reports, or diffs.
6. **The agent's own claim is not evidence.** A passing run proves the
   run; it does not prove the design. The checklist and the self-attack
   are what create acceptance.

## 1. Test pyramid — required for every change

Every behavioural change ships **three tiers**, not one:

| Tier | What it proves | Where |
|---|---|---|
| **Unit** | Pure logic: parsing, classification, formatting, policy. Fast, offline, no I/O where possible. | `tests/test_<module>.py` |
| **Integration** | Module boundaries: CLI args → pipeline, git diff → scan scope, file → artifact, redaction, retries. | marked `@pytest.mark.integration` |
| **E2E** | The user-facing path end-to-end: `python -m <entrypoint>` in a real temp git repo, artifacts on disk, exit code. | marked `@pytest.mark.e2e` |

Additional rules:

- **Security-sensitive code** (`sandbox/`, `verified_pr/`, `patcher/`,
  `ci/`, `api/`, `hunter/`, `net/`, `scripts/pr_scan.py`,
  `scripts/self_attack.py`) also ships at least one **adversarial** test
  (`@pytest.mark.adversarial`): hostile input, malformed repo, traversal,
  injection, race, or resource exhaustion.
- **Shared-state / concurrency code** ships a many-users test: at least 8
  concurrent invocations over disjoint inputs, asserting per-input results,
  no cross-contamination, deterministic output, and bounded runtime (see
  `tests/test_scan_concurrency.py`).
- **Algorithmic changes** ship a bounded-time regression test when the
  complexity could regress (e.g. an 8k-line input must finish in seconds,
  not minutes; see `tests/test_scan_performance.py`).
- Tests must be **offline by default**. Network, Docker, or real GitHub
  calls are opt-in and skipped when unavailable — never silently passed.
- A bug fix ships the **regression test that fails before the fix**.
- Do not delete or weaken an existing test to make a change pass. If a
  test encoded wrong behaviour, change it in a separate, explained commit.
- Test names state the guarantee (`test_gate_blocks_unfixed_finding`),
  not the implementation (`test_line_42`).

## 2. Definition of Done (checklist)

Copy this into the task/PR body and tick every box with evidence:

- [ ] Scope written: what changes, what does **not** change.
- [ ] Unit tests added/updated (and a failing regression test for bugs).
- [ ] Integration test added/updated for every boundary touched.
- [ ] E2E test added/updated for every user-facing path touched.
- [ ] Adversarial test added for security-sensitive paths.
- [ ] Many-users test added for shared state / concurrency (>= 8 parallel,
      isolated inputs, deterministic).
- [ ] Bounded-time regression test added for algorithmic changes.
- [ ] `python -m pytest tests/ -q` green (full suite, not a subset).
- [ ] `python benchmarks/run.py --verify` shows no F1 regression
      (scanner/rule changes only).
- [ ] `ruff format --check` + `ruff check` clean.
- [ ] `python scripts/quality_gate.py --base <base>` green.
- [ ] Self-attack run recorded (hostile + concurrent) with no leak,
      no crash, and the expected verdicts.
- [ ] I tried to break my own change as a hostile user before accepting it;
      every failure found is now a regression test.
- [ ] Docs/CHANGELOG updated; known limits labelled `UNVERIFIED`.
- [ ] No secrets/PII in the diff; redaction verified if outputs changed.
- [ ] Commit message says **what is proven**, not just what changed.

## 3. Mandatory self-attack (after every task)

Running the tests is the start, not the end. Before declaring done:

1. **Become the attacker.** Ask: "How would I make this gate say MERGE
   when it must BLOCK? How would I make it crash, hang, or leak?"
2. **Abuse the inputs** — binary, huge single line, unicode/path
   injection, prompt injection in comments, symlinked/duplicated files,
   truncated archives, empty repos.
3. **Simulate many users at once** — run N independent gate invocations
   in parallel against separate repos; assert no cross-contamination
   (comments/logs/artifacts), deterministic verdicts, no shared-state
   bleed, and bounded runtime.
4. **Check the boring failure modes** — exit codes, timeout, temp-file
   cleanup, artifact names, stdout redaction, Windows/POSIX paths.
5. **Record the result** — what was attacked, what held, what failed.
   A failure becomes a regression test before it becomes a fix.

Commands:

```bash
python scripts/self_attack.py --json            # hostile + concurrency
python scripts/self_attack.py --quick --json    # fast subset (CI/tests)
```

## 4. Review discipline

- The author of a change is not its only reviewer. Run the adversarial
  pass as if a hostile contributor wrote the change, then fix what it
  finds.
- Prefer **one bounded, verifiable claim** over a broad marketing claim.
- When something is not executed (Bitbucket cloud, non-Python replay,
  live KEV inside Actions), it stays `UNVERIFIED` until a run exists.
- Keep the gate content-based: a finding is excused only by proof, never
  by a whitelist entry, comment text, or a passing unrelated test.

## 5. Enforcement

| Layer | Mechanism |
|---|---|
| Local | `PROJECT_RULES.md` + this checklist + `scripts/quality_gate.py` |
| CI | `.github/workflows/quality-gate.yml` (gate + self-attack) |
| Review | PR template checklist + adversarial evidence in the body |

The gate is a floor, not a ceiling. Passing it does not replace thinking;
it only prevents the same class of "done" that has no tests behind it.
