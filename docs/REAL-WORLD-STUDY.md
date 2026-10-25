# Real-world precision study (20 OSS Python repositories)

Status: **candidate study, not exploit-verified.** This measures the static
candidate generator (`CVEHunter.scan_repo` + `fp_filter`), not the full
`scan -> prove -> patch -> verify` gate. No finding below was sent to the
sandbox validator, so every "kept" item is a *candidate* and every removal is
a *rejected candidate*, not a proven false negative.

Date: 2026-10-25. Scanner: `blastradius-agent` commit on
`launch/dryrun-docker` + the fixes in this change.

## Method

- 20 popular Python frameworks/SDKs cloned at their default branch
  (`D:\deepseek\research\realworld\repos`), scanned with default settings
  (min confidence 0.7, 19 repos in the delta table; `pypa/pip` excluded from
  the delta because its generated `idna/uts46data.py` exposed a separate
  performance defect described below).
- Every candidate was read by hand against the surrounding function. A
  candidate was counted as **rejected** when the sink argument was a literal,
  a configuration value, a read, a same-origin/browser-side call, or when an
  authorization check guarded the object access.
- No ground truth exists for missed vulnerabilities (FN), so recall is
  **not** reported. The hand review only judges candidates the scanner
  emitted.

Reproduce:

```powershell
python D:\deepseek\research\realworld\scan_v5.py
Get-Content D:\deepseek\research\realworld\results\scan-summary-v5.json
```

## Result

| Iteration | Change focus | Raw | Kept after `fp_filter` |
|---|---|---:|---:|
| v1 | baseline | 234 | **182** |
| v2 | source boundaries, XSS/SSTI/CRLF literal guards | 114 | **88** |
| v3 | argument-context and safe-API guards | 58 | **36** |
| v4 | IDOR scoping, name-based taint tightening | 43 | **24** |
| v5 | performance + regression tests (same rules) | 43 | **24** |

**87% of v1 candidates removed without losing any benchmark case**
(16/16, F1 1.000, 12/16 sandbox-proven).

### Surviving 24 candidates

| Repo | Count | Type | Disposition |
|---|---:|---|---|
| `wagtail/wagtail` | 19 | XSS | Admin UI renders same-origin, caller-supplied HTML through `h()`/`mark_safe`; candidate, likely by-design |
| `wagtail/wagtail` | 2 | IDOR | Generic `copy.py` / `find_object` helpers; base-class flow, no concrete route |
| `celery/celery` | 1 | deserialization | `pickle.loads(payload)` on an internal worker channel; candidate |
| `netbox/netbox` | 1 | XSS | `document.write(html)` in a plugin-rendered report; candidate |
| `pallets/werkzeug` | 1 | XSS | `tmp.innerHTML = data` in the debugger console; candidate |

None of these is claimed as a vulnerability. They stay in the review queue
until the validator can prove reachability and impact.

## False-positive classes fixed

1. **Substring sources** — `prepared_request.body` matched `request.body`.
   Fixed with identifier boundaries on every source pattern.
2. **Sink argument ignored** — every sink in a file containing one source was
   flagged. Fixed by requiring a data-bearing right-hand side and by
   resolving constants/literals/reads before scoring.
3. **Header/config CRLF** — `headers={"X": value}` with config values or
   numeric lengths was reported as header injection. Fixed with literal,
   length, and value-side-only guards.
4. **Instrumentation XSS** — `eval()` in debugger/agent code, literal
   `innerHTML`, `document.write` of static strings, and same-origin HTML
   escape helpers. Fixed by narrowing sinks and adding safe-API patterns.
5. **Template false positives** — `string.Template.substitute`,
   `Template(loader=...)`, and literal templates scored as SSTI. Fixed by
   stripping string literals before sink matching and adding safe loaders.
6. **Prototype reads** — `Object.prototype` comparisons and `hasOwnProperty`
   guards counted as pollution. Fixed to require an assignment/write.
7. **Traversal on internal file handles** — `sendfile` (socket-to-file) was
   treated as a path sink. Removed.
8. **IDOR on routing helpers** — `request.view_args` alone, or any `.get()`
   in a file with an `id`, was enough. Fixed: an indexed id source, an object
   access that consumes id/pk/uuid, and no authorization check.
9. **Name-only taint** — `host`, `url`, `data`, `path`, `filename` were
   treated as user-controlled on sight (certbot's `requests.get(url)`,
   Celery path helpers). Fixed: only strong names
   (`payload`, `user_input`, `untrusted`, `tainted`, `attacker`) taint by
   name; everything else needs an assignment-chain source. This is a
   deliberate precision/recall trade: weaker names now require proof.

## Performance defect found and fixed

`pypa/pip`'s generated `src/pip/_vendor/idna/uts46data.py` (16.9k lines,
0.25 MB) took **~920 s**; cProfile showed **1252 s**, 875M calls, and 853M
`re.search` calls from `_find_func_start`, which rescanned upward for every
sink candidate on every line (O(n²)). Two fixes:

- Prefix index of "nearest function start at or before line i", cached per
  thread and keyed by list identity (strong reference prevents id reuse).
- Skip the taint cap check entirely when a rule already scored `0.0`.

Result: that file now scans in **~3.0 s**, and all 432 Python files in pip
scan in **27 s** with 0 candidates. Bounded-time and 8-thread isolation tests
are in `tests/test_scan_performance.py` and `tests/test_scan_concurrency.py`.

## Limitations

- Candidate precision only; no exploit replay, no ground-truth recall.
- Single language (Python), single run per repository, default rules only.
- `fp_filter` is a heuristic: a dropped true positive would not be visible
  in this study.
- The 24 survivors are unprioritized; several are likely framework-internal
  by design. Do not cite this document as a vulnerability list.

## Next

1. Hand-label a 100-candidate sample (including v1 output) to report
   precision with a confidence interval, not just counts.
2. Add a JavaScript/TypeScript + Go corpus; current rules are Python-heavy.
3. Track removal reasons in the JSON summary so future rule changes can be
   diffed per class instead of re-triaged from scratch.
