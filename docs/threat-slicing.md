# Threat-Model & Thin-Slice Audit

The slice agent audits a repository in two steps instead of asking one model to
"find all vulnerabilities" in the whole tree.

1. **Threat model** - inspect the repository structure, entry points and prior
   advisories (for example `SECURITY.md` or `docs/advisories/*.md`) and produce
   a one-page threat model with trust boundaries, crown jewels, attacker models
   and priority bug classes. Without an LLM, deterministic rules build the same
   document.
2. **Thin slices** - split source files into four bounded slices: `auth`,
   `serialization`, `jwt_crypto` and `file_sandbox`. Each slice is audited with
   red-team framing: assume an exploitable bug exists, list the invariants, and
   try to violate them.

Every candidate is passed through the existing sandbox verifier. A finding is
reported as confirmed only when the verifier returns an executed
`CONFIRMED_EXPLOITABLE` marker; everything else stays a candidate or a
rejection.

## Run it

```bash
# Deterministic scanner fallback (offline, no API key)
python -m blastradius.agents.sliced_cli --target ./repo

# LLM threat model + adversarial slice prompts
python -m blastradius.agents.sliced_cli --target ./repo --llm
```

Outputs go to `reports/threat-slicing/` by default:

- `threat-model.md` - the one-page model
- `sliced-audit.json` - slices, candidates, confirmations, sandbox evidence

## Untrusted repository content

Repository READMEs, comments and string literals are attacker-influenced. Every
file passed to the model is wrapped by
`blastradius.agents.untrusted_content.UntrustedContent`:

- control characters are stripped and the payload is size-limited;
- the payload is JSON, with `</` escaped so it cannot close a prompt tag;
- the block is labelled `UNTRUSTED_REPOSITORY_DATA` and the system prompt says
  the content is evidence, never instructions;
- injection markers are recorded in the report as `injection_flags`.

The agent never executes repository code. Sandbox verification uses the
existing synthetic exploit templates, so a malicious README cannot turn into a
tool call or shell command.

## Benchmark precision floor

`benchmarks/run.py` accepts both a recall/F1 gate and a false-positive floor:

```bash
python benchmarks/run.py --min-f1 0.5 --min-precision 0.5
```
