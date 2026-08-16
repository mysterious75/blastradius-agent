# HackerOne Report #590020 — CRLF Injection in urllib

- **Program:** unknown
- **Severity:** medium
- **Weakness:** CRLF Injection (n/a)
- **State:** Closed
- **Reporter:** push0ebp
- **Reported:** n/a
- **Disclosed:** 2020-05-06T02:15:20.166Z
- **Bounty:** n/a

## Full disclosure

Hi. I found CRLF Injection a few months ago.
Please refer my bug issue.
https://bugs.python.org/issue35906

Thank you

## Impact

lead to SSRF. 
e.g. can exploit a internal redis server to send arbitrary packet data including ascii and non-ascii.
