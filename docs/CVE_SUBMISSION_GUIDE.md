# Flask-Admin DOM XSS — CVE Submission Guide

## What was found

BlastRadius discovered a DOM XSS vulnerability in
flask-admin v2.2.0 (latest as of 2026-08-09):

**File:** `static/admin/js/rediscli.js` lines 27 and 37
**Type:** DOM-based Cross-Site Scripting (XSS)
**CVSS:** 6.1 (Medium) — AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)

## Why submit it

- Not previously reported (verified: no GHSA, no CVE, no GitHub issue)
- Present in latest release v2.2.0
- DOM-level confirmed via PoC
- flask-admin has history of CVEs (CVE-2018-16516)
- Responsible disclosure = your name on a real CVE

## How to submit (step by step)

### Step 1: Go to

https://github.com/pallets-eco/flask-admin/security/advisories/new

### Step 2: Fill the form

**Title:** DOM XSS in Redis console (rediscli.js) via unsanitized .html()

**Severity:** Moderate

**Description:** (copy this)

```
Flask-admin's Redis management console (`/admin/rediscli/`)
is vulnerable to DOM-based Cross-Site Scripting via
`static/admin/js/rediscli.js`.

Two sinks are affected:
- Line 27: The Redis command typed by the user is
  passed directly to jQuery's `.html()` without escaping.
- Line 37: The server response from POST /run/ is
  passed directly to jQuery's `.html()` without escaping.

Payload: <img src=x onerror="alert(document.domain)">

**Impact:** An attacker who can influence the Redis
server response or share a crafted Redis console
session can execute arbitrary JavaScript in the
admin's browser, potentially stealing session cookies
or performing admin actions.

**Affected version:** v2.2.0 (latest)
**Fix:** Replace `.html(response)` with `.text(response)`
on lines 27 and 37 of rediscli.js.
```

**Affected versions:** <= 2.2.0
**Patched version:** (leave blank — not yet patched)

### Step 3: Submit

Click "Submit vulnerability report"
You will receive a confirmation email.

### Step 4: Wait

Maintainers typically respond in 7-30 days.
Do NOT publicly disclose until they patch or 90 days pass.

### Step 5: After fix

- Request CVE ID via https://cveform.mitre.org
- Add to README CVE Hall of Fame
- Write blog post
