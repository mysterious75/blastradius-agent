"""auto_select — pick the best available LLM provider from the environment.

Priority: opencode_zen > opencode_go > deepseek > openai > anthropic > others.
Honors BLASTRADIUS_PROVIDER / BLASTRADIUS_MODEL overrides. Model names are
never validated: if the requested model belongs to no known provider, the
selected provider's endpoint is used and the model is passed through as-is
(OpenAI-compatible servers validate model IDs themselves).
"""

import os
from typing import Dict, Optional

from blastradius.providers.client import _auto_select_name, provider_model
from blastradius.providers.registry import PROVIDER_PRIORITY, PROVIDER_REGISTRY


def auto_select(verbose: bool = True) -> Optional[Dict[str, str]]:
    """Return {'provider': name, 'model': model} for the best available provider.

    Returns None when no provider is configured (callers fall back to
    rule-based logic). ``verbose`` prints the selection.
    """
    name = _auto_select_name()
    if name is None:
        return None

    # If the user forced a model that belongs to a known provider, prefer that
    # provider so the model string is native (e.g. a Claude model + Claude key).
    forced_model = os.getenv("BLASTRADIUS_MODEL", "").strip()
    if forced_model:
        for candidate in PROVIDER_PRIORITY:
            if forced_model in (PROVIDER_REGISTRY[candidate].get("models") or []):
                if _auto_select_name() != candidate and os.getenv("BLASTRADIUS_PROVIDER", "").strip():
                    break  # explicit provider override wins
                name = candidate
                break

    model = provider_model(name)
    if verbose:
        print(f"Using provider: {name} / {model}")
    return {"provider": name, "model": model}
