"""Rate limiter + cost tracker tests — no network, time mocked."""

import pytest

from blastradius.providers.client import LLMClient, LLMUnavailableError
from blastradius.providers.cost_tracker import CostTracker, cost_tracker
from blastradius.providers.rate_limiter import RateLimitedError, RateLimiter


# --- token bucket ------------------------------------------------------------


def test_wait_if_needed_no_sleep_within_burst(monkeypatch):
    sleeps = []
    monkeypatch.setattr("blastradius.providers.rate_limiter.time.sleep", lambda s: sleeps.append(s))
    limiter = RateLimiter(rates={"test": 2})  # 2 req/s
    for _ in range(2):
        assert limiter.wait_if_needed("test") == 0.0
    assert sleeps == []


def test_wait_if_needed_sleeps_when_exhausted(monkeypatch):
    sleeps = []
    monkeypatch.setattr("blastradius.providers.rate_limiter.time.sleep", lambda s: sleeps.append(s))
    limiter = RateLimiter(rates={"test": 2})
    limiter.wait_if_needed("test")
    limiter.wait_if_needed("test")
    limiter.wait_if_needed("test")  # third request must wait
    assert sleeps and sleeps[0] > 0


def test_backoff_sequence():
    limiter = RateLimiter()
    assert [limiter.backoff_sleep(i) for i in range(4)] == [1, 2, 4, 8]
    assert limiter.backoff_sleep(9) == 8  # capped


def test_circuit_breaker_opens_after_5_failures(monkeypatch):
    clock = [0.0]
    limiter = RateLimiter(now=lambda: clock[0])
    for _ in range(5):
        limiter.record_failure("openai")
    assert limiter.is_open("openai") is True

    clock[0] += 301  # after 5 minutes
    assert limiter.is_open("openai") is False


def test_success_resets_failures():
    limiter = RateLimiter()
    limiter.record_failure("openai")
    limiter.record_success("openai")
    for _ in range(4):
        limiter.record_failure("openai")
    assert limiter.is_open("openai") is False  # counter reset by success


def test_usage_tracking():
    limiter = RateLimiter()
    limiter.track("deepseek", input_tokens=100, output_tokens=50, cost=0.001)
    limiter.track("deepseek", input_tokens=10, output_tokens=10)
    assert limiter.requests_made["deepseek"] == 2
    assert limiter.tokens_used["deepseek"] == 170
    assert limiter.cost_estimate == pytest.approx(0.001)


# --- LLMClient integration ---------------------------------------------------


def test_chat_retries_on_429_then_succeeds(monkeypatch):
    sleeps = []
    monkeypatch.setattr("blastradius.providers.client.time.sleep", lambda s: sleeps.append(s))
    attempts = {"n": 0}

    def flaky_http(url, headers, payload, timeout):
        attempts["n"] += 1
        if attempts["n"] <= 2:
            raise RateLimitedError("429")
        return {"choices": [{"message": {"content": "ok"}}]}

    client = LLMClient(provider="deepseek", model="deepseek-chat", http=flaky_http, verbose=False)
    assert client.chat(["hi"]) == "ok"
    assert attempts["n"] == 3
    assert sleeps == [1.0, 2.0]  # backoff 1s then 2s


def test_chat_429_exhausts_retries_then_falls_back(monkeypatch):
    monkeypatch.setattr("blastradius.providers.client.time.sleep", lambda s: None)

    def always_429(url, headers, payload, timeout):
        raise RateLimitedError("429")

    client = LLMClient(provider="deepseek", model="deepseek-chat", http=always_429, verbose=False)
    with pytest.raises(LLMUnavailableError, match="rate limited"):
        client.chat(["hi"])


def test_chat_skips_circuit_open_provider(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "ds")
    monkeypatch.setenv("OPENAI_API_KEY", "oa")
    seen = []

    def http(url, headers, payload, timeout):
        seen.append(url)
        if "deepseek.com" in url:
            raise RuntimeError("down")
        return {"choices": [{"message": {"content": "from openai"}}]}

    client = LLMClient(provider="deepseek", http=http, verbose=False)
    for _ in range(5):  # trip the deepseek breaker
        try:
            client.chat(["x"])
        except LLMUnavailableError:
            pass
    # now the breaker should be open for deepseek in a fresh client sharing state? no —
    # each client has its own limiter; instead verify the limiter tripped on one client.
    assert client.limiter.is_open("deepseek") is True
    seen.clear()
    client.chat(["x"])  # deepseek is open -> skipped, openai used directly
    assert not any("deepseek" in u for u in seen)
    assert any("openai.com" in u for u in seen)


# --- cost tracker ------------------------------------------------------------


def test_cost_tracking_math():
    tracker = CostTracker()
    tracker.track_usage("openai", "gpt-4o", input_tokens=1_000_000, output_tokens=1_000_000)
    report = tracker.get_session_cost()
    assert report["total_usd"] == pytest.approx(12.50, abs=1e-4)
    assert report["breakdown"]["openai/gpt-4o"] == pytest.approx(12.5, abs=1e-4)


def test_cost_tracking_deepseek_cheap():
    tracker = CostTracker()
    tracker.track_usage("deepseek", "deepseek-chat", input_tokens=1_000_000, output_tokens=1_000_000)
    assert tracker.get_session_cost()["total_usd"] == pytest.approx(0.42, abs=1e-4)


def test_cost_tracking_default_rates():
    tracker = CostTracker()
    tracker.track_usage("mystery", "x-model", input_tokens=1_000_000, output_tokens=1_000_000)
    assert tracker.get_session_cost()["total_usd"] == pytest.approx(4.00, abs=1e-4)


def test_cost_tracking_opencode_free():
    tracker = CostTracker()
    tracker.track_usage("opencode_zen", "deepseek-v4-flash", input_tokens=500_000,
                        output_tokens=500_000)
    assert tracker.get_session_cost()["total_usd"] == 0.0


def test_monthly_estimate():
    tracker = CostTracker()
    tracker.track_usage("openai", "gpt-4o", input_tokens=100_000, output_tokens=100_000)
    estimate = tracker.get_monthly_estimate(sessions_per_month=30)
    session = tracker.get_session_cost()["total_usd"]
    assert estimate["monthly_usd"] == pytest.approx(session * 30, abs=1e-3)


def test_cost_cli(monkeypatch, capsys):
    from blastradius.providers.cli import main as providers_main

    cost_tracker.usage.clear()
    cost_tracker.track_usage("deepseek", "deepseek-chat", input_tokens=1_000_000,
                             output_tokens=1_000_000)
    try:
        rc = providers_main(["cost"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Session cost" in out
        assert "deepseek/deepseek-chat" in out
        assert "Monthly estimate" in out
        assert "0.42" in out
    finally:
        cost_tracker.usage.clear()


def test_chat_records_usage(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "ds")

    def http(url, headers, payload, timeout):
        return {"choices": [{"message": {"content": "ok"}}],
                "usage": {"prompt_tokens": 500, "completion_tokens": 300}}

    tracker = CostTracker()
    client = LLMClient(provider="deepseek", http=http, verbose=False, tracker=tracker)
    client.chat(["hi"])
    assert tracker.usage[("deepseek", "deepseek-chat")] == [500, 300]
