"""BlastRadius dynamic web testing package.

Black-box checks against a live target: crawl, HTTP interception proxy,
browser session, and behavioral checks (reflected XSS, open redirect,
security headers, CORS, exposed files, directory listing).

Entry points:
    python -m blastradius.web --target http://localhost:8000
    from blastradius.web.scanner import DynamicWebScanner
    from blastradius.web.proxy import HTTPProxy
"""

from blastradius.web.browser import BrowserSession, Page
from blastradius.web.proxy import HTTPProxy, TrafficRecord
from blastradius.web.scanner import DynamicFinding, DynamicWebScanner

__all__ = [
    "BrowserSession",
    "Page",
    "HTTPProxy",
    "TrafficRecord",
    "DynamicFinding",
    "DynamicWebScanner",
]
