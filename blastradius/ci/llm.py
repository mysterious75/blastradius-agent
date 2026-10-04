"""Provider-neutral LLM interface for the CI gate.

The core engine depends only on :class:`LLMProvider`. Adapters implement the
wire protocol; the first adapters are Anthropic (Messages API) and a generic
OpenAI-compatible one layered over the existing
:mod:`blastradius.providers` client (no behavior change there).

Design rules enforced here:
- bounded timeouts, retries with backoff, no unbounded hangs;
- auth/config errors fail fast (never retried into a ban);
- malformed responses raise :class:`MalformedResponse` (fail-closed);
- repository content is untrusted: prompts wrap it in delimiters with an
  explicit instruction hierarchy, and responses are structurally validated.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

from blastradius.ci.redact import redact_secrets


class ProviderError(RuntimeError):
    """Base class for LLM provider failures."""


class ProviderTimeout(ProviderError):
    """The provider did not answer within budget."""


class ProviderAuthError(ProviderError):
    """Missing/invalid credentials or configuration (never retried)."""


class MalformedResponse(ProviderError):
    """The provider answered, but the payload is unusable (never retried)."""


@dataclass
class ReviewRequest:
    """One bounded review call."""

    system: str
    user: str
    max_tokens: int = 2000
    timeout: int = 60
    max_retries: int = 2
    metadata: Dict[str, Any] = field(default_factory=dict)


class LLMProvider(ABC):
    """Generic reviewer interface. Core engine depends only on this."""

    name: str = "base"

    @abstractmethod
    def review(self, request: ReviewRequest) -> str:
        """Return the model's raw text reply; raise ProviderError on failure."""


def _sleep_backoff(attempt: int) -> None:
    time.sleep(min(2.0 * (2**attempt), 10.0))


def _default_http_json(
    url: str, headers: Dict[str, str], payload: Dict[str, Any], timeout: int
) -> Dict[str, Any]:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise ProviderAuthError(f"HTTP {exc.code} from provider") from exc
        if exc.code == 429:
            raise ProviderError(f"HTTP 429 rate limited: {url}") from exc
        if exc.code >= 500:
            raise ProviderError(f"HTTP {exc.code} provider error") from exc
        raise ProviderError(f"HTTP {exc.code} provider error") from exc
    except TimeoutError as exc:
        raise ProviderTimeout(f"provider timed out after {timeout}s") from exc
    except OSError as exc:
        raise ProviderError(f"provider transport error: {exc}") from exc


class AnthropicAdapter(LLMProvider):
    """Anthropic Messages API reviewer (stdlib HTTP, injectable transport).

    Speaks the Messages API directly (``POST {base}/messages`` with
    ``x-api-key`` + ``anthropic-version``) so the gate adds no new
    dependencies; semantics match the official SDK's messages endpoint.
    Configuration comes from the environment (never hardcoded):

    - ``ANTHROPIC_API_KEY`` (required)
    - ``BLASTRADIUS_AI_MODEL`` (preferred) or ``BLASTRADIUS_MODEL``
    - ``BLASTRADIUS_AI_BASE_URL`` (default https://api.anthropic.com)
    """

    name = "anthropic"
    DEFAULT_BASE_URL = "https://api.anthropic.com"
    DEFAULT_MODEL = "claude-sonnet-4-5"
    API_VERSION = "2023-06-01"

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        http: Optional[Callable] = None,
        timeout: int = 60,
    ):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "")
        self.model = (
            model
            or os.getenv("BLASTRADIUS_AI_MODEL", "").strip()
            or os.getenv("BLASTRADIUS_MODEL", "").strip()
            or self.DEFAULT_MODEL
        )
        self.base_url = (
            base_url or os.getenv("BLASTRADIUS_AI_BASE_URL", "").strip() or self.DEFAULT_BASE_URL
        ).rstrip("/")
        self.http = http or _default_http_json
        self.timeout = timeout

    def review(self, request: ReviewRequest) -> str:
        if not self.api_key:
            raise ProviderAuthError("ANTHROPIC_API_KEY is not set")
        payload = {
            "model": self.model,
            "max_tokens": max(1, min(request.max_tokens, 8000)),
            "system": request.system,
            "messages": [{"role": "user", "content": request.user}],
        }
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": self.API_VERSION,
        }
        timeout = min(request.timeout, 300)
        last_exc: Optional[Exception] = None
        for attempt in range(max(0, request.max_retries) + 1):
            try:
                data = self.http(f"{self.base_url}/messages", headers, payload, timeout)
                return self._extract_text(data)
            except (ProviderAuthError, MalformedResponse):
                raise
            except (ProviderTimeout, TimeoutError) as exc:
                last_exc = ProviderTimeout(f"anthropic timed out: {exc}")
            except ProviderError as exc:
                last_exc = exc
            except Exception as exc:  # defensive: transport returned garbage
                last_exc = ProviderError(f"anthropic transport failure: {exc}")
            if attempt < request.max_retries:
                _sleep_backoff(attempt)
        raise last_exc or ProviderError("anthropic review failed")

    @staticmethod
    def _extract_text(data: Any) -> str:
        """Pull assistant text from a Messages response; strict validation."""
        if not isinstance(data, dict) or not isinstance(data.get("content"), list):
            raise MalformedResponse("anthropic response has no content list")
        texts = [
            block.get("text", "")
            for block in data["content"]
            if isinstance(block, dict) and block.get("type") == "text"
        ]
        reply = "\n".join(t for t in texts if t).strip()
        if not reply:
            raise MalformedResponse("anthropic response has no text content")
        if data.get("stop_reason") not in (None, "end_turn", "stop_sequence", "max_tokens"):
            raise MalformedResponse(
                f"anthropic stop_reason is not usable: {data.get('stop_reason')}"
            )
        return reply


class OpenAICompatibleAdapter(LLMProvider):
    """Generic OpenAI-compatible reviewer layered over the existing client.

    Reuses :class:`blastradius.providers.client.LLMClient` (registry,
    fallback chain, rate limiting). Lets future providers plug in without
    touching the core engine.
    """

    name = "openai-compatible"

    def __init__(
        self,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        timeout: int = 60,
        client: Any = None,
    ):
        self.provider = provider
        self.model = model
        self.timeout = timeout
        self._client = client

    def review(self, request: ReviewRequest) -> str:
        try:
            from blastradius.providers.client import LLMClient, LLMUnavailableError
        except Exception as exc:  # pragma: no cover - import-time guard
            raise ProviderError(f"provider client unavailable: {exc}") from exc
        client = self._client or LLMClient(
            provider=self.provider,
            model=self.model,
            timeout=min(request.timeout, 300),
            verbose=False,
        )
        try:
            reply = client.chat(
                [{"role": "user", "content": request.system + "\n\n" + request.user}]
            )
        except LLMUnavailableError as exc:
            raise ProviderError(f"no provider could complete review: {exc}") from exc
        except Exception as exc:
            raise ProviderError(f"review call failed: {redact_secrets(str(exc))}") from exc
        if not (reply or "").strip():
            raise MalformedResponse("provider returned an empty reply")
        return reply
