# HackerOne Report #826026 — Use-After-Free In IPV6_2292PKTOPTIONS leading To Arbitrary Kernel R/W Primitives

- **Program:** unknown
- **Severity:** high
- **Weakness:** Use After Free (n/a)
- **State:** Closed
- **Reporter:** theflow0
- **Reported:** n/a
- **Disclosed:** 2020-07-06T19:12:54.099Z
- **Bounty:** 10000.0

## Full disclosure

## Summary

Due to missing locks in option `IPV6_2292PKTOPTIONS` of `setsockopt` , it is possible to race and free the `struct ip6_pktopts ` buffer, while it is being handled by `ip6_setpktopt`. This structure contains pointers (`ip6po_pktinfo`) that can be hijacked to obtain arbitrary kernel R/W primitives. As a consequence, it is easy to have kernel code execution. This vulnerability is reachable from WebKit sandbox and is available in the latest FW, that is 7.02.

## Attachment

Attached is a Proof-Of-Concept that achieves a Local Privilege Escalation on FreeBSD 9 and FreeBSD 12.

## Impact

- In conjunction with a WebKit exploit, a fully chained remote attack can be achieved.
- It is possible to steal/manipulate user data.
- Dump and run pirated games.
