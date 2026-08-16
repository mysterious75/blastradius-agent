"""LLMClient — OpenAI-compatible chat client with provider fallback chain.

All network calls go through the injectable ``http`` callable so the client is
fully testable offline. Models are NEVER validated client-side: any model ID a
provider accepts (including ones not in the registry) is forwarded as-is, so
a user's API key works with any model they want.
"""

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Dict, List, Optional

from blastradius.providers.registry import PROVIDER_PRIORITY, PROVIDER_REGISTRY
from blastradius.providers.rate_limiter import RateLimitedError


def _is_transient(exc: Exception) -> bool:
    """Whether an error is worth retrying: network blips, timeouts, 5xx, limits.

    Auth/config errors (401/403/404) are NOT transient — retrying them only
    burns time, so they fail fast to the next provider. HTTPError must be
    checked BEFORE the OSError branch (HTTPError subclasses OSError in urllib).
    """
    if isinstance(exc, RateLimitedError):
        return True
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code >= 500 or exc.code in (408, 425)
    if isinstance(exc, (TimeoutError, ConnectionError, OSError)):
        return True  # urllib URLError / socket timeouts / connection resets
    return False


class LLMUnavailableError(RuntimeError):
    """Raised when no provider can complete a chat call (all failed)."""


def _default_http(url: str, headers: Dict, payload: dict, timeout: int) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        # curl-like UA: some LLM gateways 403 the default Python-urllib agent
        headers={"Content-Type": "application/json", "User-Agent": "curl/8.6.0", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            raise RateLimitedError(f"rate limited (429): {url}") from exc
        raise


def provider_key_set(name: str) -> bool:
    """Whether the provider has a usable credential (env key or fixed local key)."""
    cfg = PROVIDER_REGISTRY[name]
    if cfg.get("api_key"):
        return True  # local providers (ollama/lmstudio) always "have a key"
    env_key = cfg.get("key_env")
    return bool(env_key and os.getenv(env_key))


def provider_api_key(name: str) -> Optional[str]:
    """Resolve the API key for a provider (env var or fixed local key)."""
    cfg = PROVIDER_REGISTRY[name]
    if cfg.get("api_key"):
        return cfg["api_key"]
    env_key = cfg.get("key_env")
    return os.getenv(env_key) if env_key else None


def provider_model(name: str, override: Optional[str] = None) -> str:
    """Default model for a provider: explicit override > env > first registry model."""
    if override:
        return override
    env_model = os.getenv("BLASTRADIUS_MODEL", "").strip()
    if env_model:
        return env_model
    models = PROVIDER_REGISTRY[name].get("models") or []
    return models[0] if models else "default"


class LLMClient:
    """Chat completions client with automatic provider selection + fallback."""

    def __init__(
        self,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        http: Optional[Callable] = None,
        timeout: int = 30,
        verbose: bool = True,
        limiter=None,
        tracker=None,
    ):
        from blastradius.providers.cost_tracker import cost_tracker
        from blastradius.providers.rate_limiter import RateLimiter

        self.provider = provider
        self.model = model
        self.http = http or _default_http
        self.timeout = timeout
        self.verbose = verbose
        self.limiter = limiter or RateLimiter()
        self.tracker = tracker if tracker is not None else cost_tracker
        # Explicit model that is not in the given provider's list still works:
        # the registry is only used for base_url/key resolution.

    # ------------------------------------------------------------------
    # Provider chain
    # ------------------------------------------------------------------

    def _chain(self) -> List[str]:
        """Providers to try, in order: explicit > auto-selected > rest by priority."""
        if self.provider and self.provider in PROVIDER_REGISTRY:
            chain = [self.provider]
            for name in PROVIDER_PRIORITY:
                if name not in chain and provider_key_set(name):
                    chain.append(name)
            return chain
        selected = _auto_select_name()
        chain = [selected] if selected else []
        for name in PROVIDER_PRIORITY:
            if name not in chain and provider_key_set(name):
                chain.append(name)
        return chain

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def chat(self, messages: List, system_prompt: str = "") -> str:
        """Send messages and return the assistant reply.

        Per provider: rate-limited and retried on TRANSIENT errors (429, 5xx,
        timeouts, connection resets) with exponential backoff; auth/config
        errors (4xx) fail fast to the next provider; circuit-breaker providers
        are skipped when DOWN. The first success wins. Raises
        LLMUnavailableError when every provider fails (callers fall back to
        rule-based logic).
        """
        failures = []
        for name in self._chain():
            if self.limiter.is_open(name):
                failures.append(f"{name}: circuit open (down)")
                continue
            model = provider_model(name, self.model)
            for attempt in range(4):  # 1 + 3 retries on transient errors
                self.limiter.wait_if_needed(name)
                try:
                    reply = self._chat_with(name, model, messages, system_prompt)
                    self.limiter.record_success(name)
                    return reply
                except Exception as exc:
                    if _is_transient(exc) and attempt < 3:
                        time.sleep(self.limiter.backoff_sleep(attempt))
                        continue
                    self.limiter.record_failure(name)
                    if isinstance(exc, RateLimitedError):
                        failures.append(f"{name}: rate limited (retries exhausted)")
                    else:
                        failures.append(f"{name}: {exc}")
                    break
        raise LLMUnavailableError("; ".join(failures) or "no provider configured")

    def test_connection(self) -> bool:
        """Minimal round-trip ("say hi"); True when any provider responds."""
        try:
            self.chat(["hi"], system_prompt="Reply with OK.")
            return True
        except LLMUnavailableError:
            return False

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _chat_with(self, name: str, model: str, messages: List, system_prompt: str) -> str:
        cfg = PROVIDER_REGISTRY[name]
        url = cfg["base_url"].rstrip("/") + "/chat/completions"
        payload = self._build_payload(model, messages, system_prompt)
        headers = {"Authorization": f"Bearer {provider_api_key(name)}"}
        headers.update(cfg.get("extra_headers") or {})

        start = time.monotonic()
        data = self.http(url, headers, payload, self.timeout)
        if self.verbose:
            print(f"Using provider: {name} / {model} ({(time.monotonic() - start) * 1000:.0f}ms)")
        usage = data.get("usage") or {}
        self.tracker.track_usage(
            name,
            model,
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
        )
        self.limiter.track(name, usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0))
        return data["choices"][0]["message"]["content"]

    @staticmethod
    def _build_payload(model: str, messages: List, system_prompt: str) -> Dict:
        if isinstance(messages, str):
            messages = [messages]
        msgs = []
        if system_prompt:
            msgs.append({"role": "system", "content": system_prompt})
        for m in messages:
            if isinstance(m, str):
                msgs.append({"role": "user", "content": m})
            else:
                msgs.append(m)
        return {"model": model, "messages": msgs}


def _auto_select_name() -> Optional[str]:
    """Best available provider name, honoring BLASTRADIUS_PROVIDER override.

    Local providers (ollama/lmstudio) are only picked when explicitly
    overridden — with zero cloud keys, auto-select returns None so callers
    fall back to rule-based logic.
    """
    override = os.getenv("BLASTRADIUS_PROVIDER", "").strip()
    if override in PROVIDER_REGISTRY:
        return override
    for name in PROVIDER_PRIORITY:
        if provider_key_set(name) and PROVIDER_REGISTRY[name].get("key_env"):
            return name
    return None
