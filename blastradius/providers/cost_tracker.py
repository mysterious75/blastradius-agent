"""CostTracker — approximate LLM cost accounting (stdlib only)."""

from typing import Dict, Tuple

# (provider, model-prefix) -> (input USD per 1M tokens, output USD per 1M tokens)
COST_PER_1M: Dict[Tuple[str, str], Tuple[float, float]] = {
    ("openai", "gpt-4o"): (2.50, 10.00),
    ("anthropic", "claude-sonnet-4-6"): (3.00, 15.00),
    ("deepseek", "deepseek-chat"): (0.14, 0.28),
    ("opencode_zen", "deepseek-v4-flash"): (0.00, 0.00),
    ("groq", "llama-3.1-70b-versatile"): (0.59, 0.79),
}
DEFAULT_INPUT, DEFAULT_OUTPUT = 1.00, 3.00


class CostTracker:
    """Accumulates token usage and estimates cost per model."""

    def __init__(self):
        self.usage: Dict[Tuple[str, str], list] = {}

    def track_usage(self, provider: str, model: str,
                    input_tokens: int = 0, output_tokens: int = 0) -> None:
        key = (provider, model)
        bucket = self.usage.setdefault(key, [0, 0])
        bucket[0] += max(0, input_tokens)
        bucket[1] += max(0, output_tokens)

    def _rates(self, provider: str, model: str) -> Tuple[float, float]:
        for (prov, prefix), rates in COST_PER_1M.items():
            if prov == provider and model.startswith(prefix):
                return rates
        return (DEFAULT_INPUT, DEFAULT_OUTPUT)

    def get_session_cost(self) -> Dict:
        total = 0.0
        breakdown = {}
        for (provider, model), (in_tok, out_tok) in self.usage.items():
            in_rate, out_rate = self._rates(provider, model)
            cost = in_tok / 1_000_000 * in_rate + out_tok / 1_000_000 * out_rate
            breakdown[f"{provider}/{model}"] = round(cost, 6)
            total += cost
        return {"total_usd": round(total, 6), "breakdown": breakdown}

    def get_monthly_estimate(self, sessions_per_month: int = 30) -> Dict:
        session = self.get_session_cost()["total_usd"]
        return {
            "monthly_usd": round(session * sessions_per_month, 4),
            "sessions_per_month": sessions_per_month,
        }


# Shared instance used by LLMClient and the `cost` CLI.
cost_tracker = CostTracker()
