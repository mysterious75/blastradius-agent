# HackerOne Report #1962645 — [accounts.reddit.com] Redirect parameter allows for XSS

- **Program:** unknown
- **Severity:** high
- **Weakness:** Cross-site Scripting (XSS) - Generic (n/a)
- **State:** Closed
- **Reporter:** dvorakxl
- **Reported:** n/a
- **Disclosed:** 2023-05-18T13:46:49.459Z
- **Bounty:** 5000.0

## Full disclosure

## Summary:
Hello team! I was tampering with the dest parameter in accounts.reddit.com and found out it is vulnerable to Cross Site Scripting once the victim performs the log in.

## Steps To Reproduce:
  1. Enter to the following link: ```https://accounts.reddit.com/?dest=javascript:alert(document.domain)```
  - If not signed in, the user will be promped to log in and after doing so XSS will excecute

{F2315850}
  - If user is logged into his account, following the link will also make the XSS pop up

{F2315847}

## Impact

An attacker could trick users into executing XSS, executing code and stealing their cookies only by them logging in.
