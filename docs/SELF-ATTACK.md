# Self-attack playbook — break your own work before someone else does

This is the execution guide behind `PROJECT_RULES.md` §3. It is written for
an AI coding agent: the goal is to make the agent **stop trying to finish**
and start trying to **falsify** its own claims.

> Mindset: "The tests I wrote prove my happy path. My job now is to find the
> input, ordering, or concurrency that makes this gate lie."

## 1. Attack personas (wear each hat for 10 minutes)

| Persona | Question | Typical break |
|---|---|---|
| Hostile PR author | "Can my patch get MERGE while the vuln stays?" | Synthetic-only confirmation, KEV mismatch, diff-scope escape |
| Lazy maintainer | "What breaks on an empty/odd repo?" | Crash instead of BLOCK, wrong exit code |
| Supply-chain attacker | "Can I smuggle code or a secret into logs/comments?" | Untrusted filename in Markdown, echoed env, PII in SARIF |
| Load generator | "What if 20 PRs arrive at once?" | Shared temp dir, cross-repo artifact bleed, lock starvation |
| Impatient user | "What happens on timeout/kill?" | Orphaned processes, partial artifacts counted as success |
| Platform | "Windows vs Linux paths, unicode, CRLF?" | Git paths with `\`, mojibake, path traversal |

## 2. Input matrix (minimum)

For every user-facing entrypoint (e.g. `python -m blastradius.verified_pr`):

- empty repo, repo with no diff, repo with only binary files
- one 15 MB single-line file; one deeply nested path
- unicode filename (`évil_名前.py`), space, quotes, `..%2f`-style names
- prompt-injection text in comments/docstrings (must never reach an LLM
  as instructions; if no LLM key, it must be inert)
- fixture password/canary token present in the tree — it must appear
  **zero** times in comments, SARIF, stdout/stderr, and artifacts
- symlink / junction pointing outside the repo (if the platform allows)
- malformed diff, deleted-file-only diff, rename-only diff
- base ref that does not exist (must fail closed, not MERGE)

Expected outcome for every security gate: **block** (exit 1) for a real
finding, **exit 0** only for a genuinely clean diff, and never a traceback
as the primary output.

## 3. Concurrency simulation ("many users at once")

- Run **N ≥ 4** independent gate invocations simultaneously, each on its
  own copy of a repo, with **distinct** vulnerable files and **distinct**
  canary strings.
- Invariants:
  1. each process exits with the verdict for *its own* repo;
  2. each comment/artifact contains only its own file names and canary;
  3. no shared temp/out directory collision (`--out` may be identical in
     different working dirs — test both);
  4. runtime stays bounded (no lock convoy), memory does not grow with N;
  5. a killed run leaves no artifact that a later run mistakes for proof.
- Fast mode uses `--no-retest` to test the gate path; full mode includes
  re-testing. Record which mode was used.
- **Scanner changes**: also run two repos with disjoint filenames through
  `CVEHunter.scan_repo` from >= 8 threads and assert each result equals its
  serial baseline with no foreign paths (`tests/test_scan_concurrency.py`).
  This catches thread-local/cache bleed that gate-level tests miss.

## 4. Evidence format (paste into the PR body)

```
Self-attack: <commit> | mode: full|quick
Cases: empty, binary, huge-line, unicode, prompt-injection, canary,
       missing-base, rename-only, concurrency x N
Held:  ...
Failed: ...            # each becomes a regression test
Leaks: 0 canary occurrences in comments/SARIF/stdout/artifacts
Runtime: ...           # and peak RSS if measured
UNVERIFIED: ...        # anything not executed
```

A self-attack with **zero failures** is suspicious for a first pass —
re-read the code as the attacker before believing it.

## 5. Anti-patterns (do not accept)

- "All tests pass" as the whole argument.
- Adversarial tests that only test the friendly path.
- Concurrency tested sequentially.
- A gate that returns MERGE on an unsupported language/shape.
- Redaction tested with a value that never appears unredacted anyway.
- Marking something `UNVERIFIED` and then shipping language that implies
  it is verified.
