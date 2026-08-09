# Security Policy

BlastRadius is an autonomous security scanning agent. This policy covers
vulnerabilities **in BlastRadius itself** (the code in this repository) — not
in the targets it scans.

## Supported versions

| Version | Supported |
|---|---|
| 1.x (main) | ✅ |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.** Report
privately instead:

- **Email:** security@blastradius.dev *(placeholder — replace with a real
  address before public release)*

Please include:

1. Affected version / commit
2. Steps to reproduce (minimal, self-contained)
3. Proof-of-concept or exploit code (if any)
4. Impact assessment (what an attacker can do)
5. Suggested fix, if you have one

You will receive an acknowledgment within **3 business days** and a
preliminary assessment within **10 business days**.

## Disclosure policy

- We follow a **90-day coordinated disclosure** timeline, aligned with
  industry best practice.
- We will work on a fix and prepare a patched release as soon as possible.
- We will credit you for the discovery (unless you prefer to remain
  anonymous).
- If we cannot fix the issue within 90 days, we will disclose the
  vulnerability with whatever mitigation guidance we can provide, and you are
  free to publish your research after that point.
- For issues already fixed in an unannounced release, we ask that you wait for
  the public release before publishing details.

### Scope

In scope: the BlastRadius codebase (`blastradius/`, `scripts/`, CI configs).

Out of scope (report these to the affected project instead):

- Vulnerabilities in target applications scanned by BlastRadius
- Vulnerabilities in Prometheus scanners (report to the Prometheus project)
- Misconfigurations in your own environment

## Hall of Fame

We are grateful to everyone who helps make BlastRadius safer. Thank you!

| Reporter | Date | Issue | Reward |
|---|---|---|---|
| — | — | — | — |
