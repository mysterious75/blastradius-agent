"""BrowserSession — cookie-aware HTTP client with redirects and form support.

Stdlib only (urllib + http.cookiejar). Handles GET/POST, keeps a cookie jar,
follows redirects, and submits form-urlencoded bodies — enough to drive the
dynamic web scanner and to replay traffic through the HTTPProxy.

Optional Playwright is NOT required; if ``playwright`` is installed the
session can drive a real browser via ``playwright_browser()`` (lazy import,
never a hard dependency).
"""

import http.cookiejar
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class Page:
    """A fetched page."""

    url: str
    status: int
    headers: Dict[str, str]
    text: str
    final_url: str = ""
    cookies: List[Tuple[str, str]] = field(default_factory=list)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Raises HTTPError on 3xx instead of following — for redirect probes."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class BrowserSession:
    """Cookie-aware HTTP client (stdlib)."""

    def __init__(
        self,
        timeout: int = 10,
        proxy: Optional[str] = None,
        user_agent: str = "BlastRadiusWeb/1.0",
        follow_redirects: bool = True,
    ):
        self.timeout = timeout
        self.user_agent = user_agent
        self.follow_redirects = follow_redirects
        self.cookie_jar = http.cookiejar.CookieJar()
        handlers = [urllib.request.HTTPCookieProcessor(self.cookie_jar)]
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        handlers.append(
            urllib.request.HTTPRedirectHandler() if follow_redirects else _NoRedirectHandler()
        )
        self.opener = urllib.request.build_opener(*handlers)

    # ------------------------------------------------------------------
    # Requests
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        url: str,
        data: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Page:
        req_headers = {"User-Agent": self.user_agent}
        req_headers.update(headers or {})
        request = urllib.request.Request(url, data=data, headers=req_headers, method=method)
        try:
            with self.opener.open(request, timeout=self.timeout) as resp:
                text = resp.read().decode("utf-8", errors="replace")
                return Page(
                    url=url,
                    status=resp.status,
                    headers=dict(resp.headers),
                    text=text,
                    final_url=resp.geturl(),
                    cookies=[(c.name, c.value) for c in self.cookie_jar],
                )
        except urllib.error.HTTPError as exc:
            if not self.follow_redirects and 300 <= exc.code < 400:
                # Return the 3xx itself so redirect checks can read Location.
                return Page(
                    url=url,
                    status=exc.code,
                    headers=dict(exc.headers),
                    text="",
                    final_url=url,
                    cookies=[],
                )
            raise

    def get(self, url: str, params: Optional[Dict[str, str]] = None) -> Page:
        if params:
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}{urllib.parse.urlencode(params)}"
        return self._request("GET", url)

    def post(self, url: str, data: Dict[str, str]) -> Page:
        body = urllib.parse.urlencode(data).encode()
        return self._request(
            "POST",
            url,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    def text(self, url: str) -> str:
        return self.get(url).text

    # ------------------------------------------------------------------
    # Forms
    # ------------------------------------------------------------------

    def submit_form(self, action: str, inputs: Dict[str, str], method: str = "POST") -> Page:
        """Submit a form (from scanner-discovered inputs) with given values."""
        if method.upper() == "GET":
            return self.get(action, params=inputs)
        return self.post(action, inputs)

    # ------------------------------------------------------------------
    # Optional real-browser path (playwright installed)
    # ------------------------------------------------------------------

    def playwright_browser(self):
        """Return a Playwright chromium page if playwright is installed, else None."""
        try:
            from playwright.sync_api import sync_playwright  # type: ignore

            pw = sync_playwright().start()
            browser = pw.chromium.launch(headless=True)
            return browser.new_page()
        except Exception:
            return None
