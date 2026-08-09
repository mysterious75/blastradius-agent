# Vulnerability Disclosure: SQLI in test_hunter_cli_uses_display0

- **Date:** 2026-08-09
- **Severity:** CRITICAL | **CVSS estimate:** 9.8 | **CWE:** CWE-89
- **Affected file:** `C:\Users\Admin\AppData\Local\Temp\pytest-of-Admin\pytest-127\test_hunter_cli_uses_display0\app.py` line 1
- **Confidence:** 0.9

## Vulnerability description

SQL injection: user-controlled input is concatenated into a SQL statement, allowing an attacker to alter the query or extract data.

## Proof of Concept

```text
query = "SELECT * FROM users WHERE name = '" + name + "'"
```

Code context:

```text
query = "SELECT * FROM users WHERE name = '" + name + "'"
```

## Sandbox validation

CONFIRMED_EXPLOITABLE

```
CONFIRMED_EXPLOITABLE
[VULNERABLE] SQL injection: payload reached the query unescaped
SELECT * FROM users WHERE name = '' OR '1'='1 --'

```

> Note: the PoC is reconstructed from the static finding. It proves the
> pattern is exploitable; a live exploit against the real deployment must be
> confirmed manually before any disclosure.

## Suggested patch

Use parameterized queries / prepared statements for ALL database interactions. Never concatenate user input into SQL.

## Responsible disclosure

Coordinate with the maintainers (security contact / GitHub Security Advisory)
and wait for the fix before public disclosure.
