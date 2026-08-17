"""Subdomain-takeover fingerprinting for the dynamic web scanner.

Detects dangling DNS: a hostname that still resolves but serves an
*unclaimed* third-party service's error page (deregistered S3 bucket,
unused GitHub Pages site, expired Heroku app, ...). An attacker who
registers the same service account can claim the host. Matches are
candidate-only — a body fingerprint is strong evidence but not proof of a
live takeover.

The caller passes a URL it already crawled and vetted as same-origin; this
module never resolves or enumerates new hostnames.
"""

import re
from typing import Dict, List

# Vendored fingerprint table (~12 takeover-prone services). Each entry:
# {service, domain, body_regex} where body_regex matches the error page a
# *dangling* (unclaimed) endpoint returns.
FINGERPRINTS: List[Dict[str, str]] = [
    {
        "service": "AWS S3",
        "domain": "s3.amazonaws.com",
        "body_regex": r"The specified bucket does not exist",
    },
    {
        "service": "GitHub Pages",
        "domain": "github.io",
        "body_regex": r"There isn't a GitHub Pages site here",
    },
    {
        "service": "Heroku",
        "domain": "herokuapp.com",
        "body_regex": r"No such app",
    },
    {
        "service": "Azure",
        "domain": "azurewebsites.net",
        "body_regex": r"404 Web Site not found",
    },
    {
        "service": "Surge",
        "domain": "surge.sh",
        "body_regex": r"project not found",
    },
    {
        "service": "ReadTheDocs",
        "domain": "readthedocs.io",
        "body_regex": r"[Pp]roject does not exist",
    },
    {
        "service": "Fastly",
        "domain": "fastly.net",
        "body_regex": r"Fastly error: unknown domain",
    },
    {
        "service": "Shopify",
        "domain": "myshopify.com",
        "body_regex": r"Sorry, this shop is currently unavailable",
    },
    {
        "service": "Bitbucket",
        "domain": "bitbucket.io",
        "body_regex": r"Repository not found",
    },
    {
        "service": "Pantheon",
        "domain": "pantheonsite.io",
        "body_regex": r"404 error unknown site",
    },
    {
        "service": "Tumblr",
        "domain": "tumblr.com",
        "body_regex": r"There's nothing here",
    },
    {
        "service": "WordPress",
        "domain": "wordpress.com",
        "body_regex": r"Do you want to register",
    },
]


def check_takeover(url: str, browser) -> List[Dict[str, str]]:
    """Test ``url`` against every takeover fingerprint.

    ``url`` must already be a same-origin URL vetted by the caller — this
    function only fetches the given URL; it never resolves or enumerates
    hostnames. Returns one ``{service, evidence}`` dict per fingerprint
    whose error page matched the response body.
    """
    matches: List[Dict[str, str]] = []
    for fp in FINGERPRINTS:
        try:
            page = browser.get(url)
        except Exception:
            # Network/HTTP errors tell us nothing about the service state.
            continue
        if re.search(fp["body_regex"], page.text, re.IGNORECASE):
            matches.append(
                {
                    "service": fp["service"],
                    "evidence": (
                        f"body matches {fp['service']} dangling-domain marker "
                        f"`{fp['body_regex']}` ({fp['domain']}) on {url}"
                    ),
                }
            )
    return matches
