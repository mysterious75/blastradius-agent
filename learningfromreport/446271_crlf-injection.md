# HackerOne Report #446271 — CRLF injection

- **Program:** unknown
- **Severity:** medium
- **Weakness:** n/a (n/a)
- **State:** Closed
- **Reporter:** s3c
- **Reported:** n/a
- **Disclosed:** 2019-12-25T16:08:10.950Z
- **Bounty:** n/a

## Full disclosure

Hello twiiter security team,


on the domain ads.twitter.com http response splitting is vulnerability.


PoC:
https://ads.twitter.com/subscriptions/mobile/landing?ref=gl-tw-tw-promote-mode?t=%0d%0atest:tested

## Impact

an attacker can set new header
