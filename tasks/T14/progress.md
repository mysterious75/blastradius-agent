# T14 — Read HackerOne report 1154542 and extract lessons for the tool

## Status
DONE (report fully retrieved + lessons extracted)

## What was retrieved
Full disclosure of HackerOne report **1154542** via the public, unauthenticated
endpoint `https://hackerone.com/reports/1154542.json` (full JSON incl.
`vulnerability_information`, metadata, attachments).

- **Title**: "RCE when removing metadata with ExifTool"
- **Program**: GitLab (gitlab.com, structured scope URL, max sev critical)
- **Reporter**: vakzz (William Bowling)
- **Bug class**: Code Injection (CWE-94)
- **Severity**: critical | **Bounty**: $20,000
- **Submitted** 2021-04-07, **Disclosed** 2021-05-14, Closed/Resolved
- Known as **CVE-2021-22204** (GitLab Workhorse / ExifTool DjVu RCE)

### Core vuln (verbatim essence)
GitLab Workhorse passes uploaded `jpg|jpeg|tiff` files to ExifTool to strip
non-whitelisted EXIF tags. ExifTool sniffs *content* not extension, so a renamed
file can hit ANY ExifTool parser (not just JPEG/TIFF). The **DjVu** annotation
parser `eval`s annotation tokens to "convert C escape sequences"; a
**backslash+newline** bypasses the escaping validation, letting an attacker close
the string and inject arbitrary Perl (e.g. `qx{...}`), giving RCE.

PoC payload:
```
(metadata
	(Copyright "\
" . qx{echo vakzz >/tmp/vakzz} . \
" b ") )
```
Steps: attach `echo_vakzz.jpg` to a snippet description on gitlab.com; file
`/tmp/vakzz` appears on server. A second variant yielded a shell on
`web-09-sv-gprd` as `git` (uid 500), with full shell transcript in the report.

### Impact statement
"Anyone with the ability to upload an image that goes through the GitLab
Workhorse could achieve RCE via a specially crafted file." (GitLab 13.10.2-ee)

## Lessons for BlastRadius Agent (tool takeaways)

1. **Extension checks are not content checks.** Restricting an input pipe by
   file extension (jpg/jpeg/tiff) is trivially bypassed when the downstream
   parser auto-detects by magic bytes. Scanners should flag
   "extension-only filtering feeding a multi-format parser" as a weakness —
   and verify content (magic bytes) before trusting extension gates.

2. **`eval`/execute on parser input = code injection sink.** ExifTool's DjVu
   module `eval`'s annotation tokens; the "validation" (escape checks) is a
   string-level allowlist that fails on multi-char edge cases (backslash +
   newline). For the tool: flag any parser/validator that interprets input
   strings (SQL, shell, Perl, regex) where sanitization is regex/escape based
   rather than structural/parameterized.

3. **Attack surface expansion pattern.** Workhorse routed *any* upload through
   a Swiss-army-knife parser. Lesson for blast-radius modeling: a single
   powerful dependency (ExifTool supporting dozens of formats) dramatically
   widens reachability; the fix was to restrict to only the needed modules
   (TIFF/JPEG) and validate input is a real image first. Tool should recommend
   allowlisting parser modules + pre-validation.

4. **Proof-of-exploit hygiene (matches tool's [VULNERABLE] philosophy).**
   Reporter shipped two PoCs: a *harmless marker* (`echo vakzz >/tmp/vakzz`)
   and a reverse shell, plus a full transcript (uid, hostname, `ps auxww`,
   env info). Safe PoC first, destructive proof second, full evidence
   transcript attached. This validates the BlastRadius "prove in sandbox,
   keep execution marker" doctrine.

5. **Impact framing for severity.** The report explicitly scopes "anyone able
   to upload an image → RCE" — a crisp reachability statement that justifies
   Critical. Tool severity rationale should adopt this "any user who can reach
   sink X → capability Y" phrasing.

6. **Pin versions + environment.** Report includes GitLab 13.10.2-ee version,
   revision, and environment info — makes verification/remediation auditable.
   Findings should always record the exact affected version/commit.

7. **Bug+expected-behavior structure.** Report clearly separates "current bug
   behavior" vs "expected correct behavior" with 3 concrete remediation
   suggestions. Good template for the tool's remediation guidance output.

## Reference
- Report JSON: https://hackerone.com/reports/1154542.json
- Page (JS shell, og:description only): https://hackerone.com/reports/1154542
- Wayback CDX has ~20+ snapshots 2021-05-14 → 2022-01 (all JS shells)
