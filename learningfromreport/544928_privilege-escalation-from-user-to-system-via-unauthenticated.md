# HackerOne Report #544928 — Privilege Escalation From user to SYSTEM via unauthenticated command execution 

- **Program:** unknown
- **Severity:** critical
- **Weakness:** Command Injection - Generic (n/a)
- **State:** Closed
- **Reporter:** b0yd
- **Reported:** n/a
- **Disclosed:** 2019-11-08T16:37:35.196Z
- **Bounty:** n/a

## Full disclosure

The vulnerability, or feature depending how you look at it, is the ability to execute commands using the 
evostream API interface that is exposed on localhost:7440. Since the evostream service is running as SYSTEM a user can use the launchprocess command,  http://docs.evostream.com/2.0/launchProcess.html, to execute any binary with supplied arguments. The only thing that is keeping this "feature" from allowing remote code execution is the fact that it listens on localhost only. However, if it were couple with an SSRF, an attacker could achieve full remote code execution.

## Impact

The ability to run arbitrary commands as SYSTEM from any user.
