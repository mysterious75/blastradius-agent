## What this changes / what it does not

<!-- One paragraph. State the boundary of the change. -->

## Definition of Done (see PROJECT_RULES.md)

- [ ] Scope written above (including what does **not** change)
- [ ] Unit tests added/updated (regression test first for a bug fix)
- [ ] Integration test added/updated for every boundary touched
- [ ] E2E test added/updated for every user-facing path touched
- [ ] Adversarial test added for security-sensitive paths
- [ ] `python -m pytest tests/ -q` green
- [ ] `python benchmarks/run.py --verify` no F1 regression (scanner changes)
- [ ] `ruff format --check` + `ruff check` clean
- [ ] `python scripts/quality_gate.py --base origin/main` green
- [ ] `python scripts/self_attack.py` held (attach JSON/summary)
- [ ] Docs + CHANGELOG updated; unknowns labelled `UNVERIFIED`
- [ ] No secrets/PII; redaction verified if outputs changed

## Self-attack evidence

```
mode: full | quick
cases: ...
held:  ...
failed: ...
leaks: 0 canary occurrences
UNVERIFIED: ...
```

## Proof (not claims)

<!-- Commands + results + artifact paths. "Tests pass" alone is not proof. -->
