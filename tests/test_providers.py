"""Universal provider system tests — all network calls mocked, no real keys."""

import json

import pytest

from blastradius.providers.client import (
    LLMClient,
    LLMUnavailableError,
    provider_key_set,
)
from blastradius.providers.registry import PROVIDER_PRIORITY, PROVIDER_REGISTRY
from blastradius.providers.selector import auto_select

ALL_KEY_ENVS = sorted(
    {cfg["key_env"] for cfg in PROVIDER_REGISTRY.values() if cfg.get("key_env")}
    | {"BLASTRADIUS_PROVIDER", "BLASTRADIUS_MODEL", "OPENCODE_MODEL", "OPENCODE_BASE_URL"}
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for key in ALL_KEY_ENVS:
        monkeypatch.delenv(key, raising=False)


def _ok_http(content="hello"):
    def http(url, headers, payload, timeout):
        return {"choices": [{"message": {"content": content}}]}
    return http


def _raise_http(exc=None):
    def http(url, headers, payload, timeout):
        raise exc or RuntimeError("boom")
    return http


# --- registry ----------------------------------------------------------------


def test_registry_has_15_providers():
    assert set(PROVIDER_REGISTRY) == {
        "openai", "anthropic", "deepseek", "opencode_zen", "opencode_go",
        "openrouter", "qwen", "kimi", "groq", "together", "mistral",
        "google", "xai", "ollama", "lmstudio",
    }
    for name, cfg in PROVIDER_REGISTRY.items():
        assert cfg["base_url"], name
        assert cfg["models"], name
    # priority must cover every provider exactly once
    assert sorted(PROVIDER_PRIORITY) == sorted(PROVIDER_REGISTRY)


def test_local_providers_always_configured():
    assert provider_key_set("ollama") is True
    assert provider_key_set("lmstudio") is True


# --- auto_select -------------------------------------------------------------


def test_auto_select_none_without_keys():
    assert auto_select(verbose=False) is None


def test_auto_select_priority_opencode_wins(monkeypatch):
    monkeypatch.setenv("OPENCODE_API_KEY", "oc")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "ds")
    sel = auto_select(verbose=False)
    assert sel["provider"] == "opencode_zen"
    assert sel["model"] == "deepseek-v4-flash"


def test_auto_select_deepseek_when_opencode_absent(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "ds")
    monkeypatch.setenv("OPENAI_API_KEY", "oa")
    sel = auto_select(verbose=False)
    assert sel["provider"] == "deepseek"


def test_auto_select_provider_override(monkeypatch):
    monkeypatch.setenv("OPENCODE_API_KEY", "oc")
    monkeypatch.setenv("BLASTRADIUS_PROVIDER", "groq")
    sel = auto_select(verbose=False)
    assert sel["provider"] == "groq"


def test_auto_select_unknown_model_passes_through(monkeypatch):
    # a brand-new model the user wants — never in our registry — must still resolve
    monkeypatch.setenv("OPENCODE_API_KEY", "oc")
    monkeypatch.setenv("BLASTRADIUS_MODEL", "deepseek-v4-ultra")
    sel = auto_select(verbose=False)
    assert sel["provider"] == "opencode_zen"
    assert sel["model"] == "deepseek-v4-ultra"


def test_auto_select_model_matches_other_provider(monkeypatch):
    # model known to another provider -> that provider is preferred
    monkeypatch.setenv("OPENCODE_API_KEY", "oc")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "ds")
    monkeypatch.setenv("BLASTRADIUS_MODEL", "deepseek-chat")
    sel = auto_select(verbose=False)
    assert sel["provider"] == "deepseek"
    assert sel["model"] == "deepseek-chat"


# --- LLMClient ---------------------------------------------------------------


def test_chat_success():
    captured = {}

    def http(url, headers, payload, timeout):
        captured["url"] = url
        captured["headers"] = headers
        captured["payload"] = payload
        return {"choices": [{"message": {"content": "patched!"}}]}

    client = LLMClient(provider="openai", model="gpt-4o", http=http, verbose=False)
    reply = client.chat(["fix it"], system_prompt="be brief")

    assert reply == "patched!"
    assert captured["url"] == "https://api.openai.com/v1/chat/completions"
    assert captured["payload"]["model"] == "gpt-4o"
    assert captured["payload"]["messages"][0] == {"role": "system", "content": "be brief"}
    assert captured["payload"]["messages"][1] == {"role": "user", "content": "fix it"}
    assert "Bearer" in captured["headers"]["Authorization"]


def test_chat_unknown_model_forwarded_verbatim():
    captured = {}

    def http(url, headers, payload, timeout):
        captured["payload"] = payload
        return {"choices": [{"message": {"content": "ok"}}]}

    client = LLMClient(provider="deepseek", model="totally-new-model-2027", http=http, verbose=False)
    client.chat(["hi"])
    assert captured["payload"]["model"] == "totally-new-model-2027"


def test_chat_fallback_chain(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "ds")
    monkeypatch.setenv("OPENAI_API_KEY", "oa")
    seen = []

    def http(url, headers, payload, timeout):
        seen.append(url)
        if "deepseek.com" in url:
            raise RuntimeError("deepseek down")
        return {"choices": [{"message": {"content": "from openai"}}]}

    client = LLMClient(provider="deepseek", model="deepseek-chat", http=http, verbose=False)
    reply = client.chat(["hi"])
    assert reply == "from openai"
    assert any("deepseek.com" in u for u in seen)
    assert any("openai.com" in u for u in seen)


def test_chat_no_keys_raises():
    client = LLMClient(http=_raise_http(), verbose=False)
    with pytest.raises(LLMUnavailableError):
        client.chat(["hi"])


def test_test_connection():
    assert LLMClient(http=_ok_http(), verbose=False).test_connection() is True
    assert LLMClient(http=_raise_http(), verbose=False).test_connection() is False


# --- PatchGenerator integration ----------------------------------------------


def test_patch_generator_uses_provider_config(monkeypatch):
    captured = {}

    def fake_http(self, payload):
        captured["payload"] = payload
        return {"choices": [{"message": {"content": json.dumps({
            "patched_code": "def target(u):\n    return 'x'",
            "explanation": "e",
        })}}]}

    monkeypatch.setattr("blastradius.patcher.generator.PatchGenerator._http_post", fake_http)
    from blastradius.hunter.scanner import Finding
    from blastradius.patcher.generator import PatchGenerator

    gen = PatchGenerator(api_key="sk-test", provider="deepseek", model="deepseek-reasoner")
    finding = Finding(file="a.py", line=1, vuln_type="sqli", payload="x", confidence=1.0)
    patch = gen.generate_patch(finding)

    assert patch.source == "api"
    assert captured["payload"]["model"] == "deepseek-reasoner"
    # no hardcoded OpenCode URL anywhere in the generator
    import inspect

    assert "opencode.ai" not in inspect.getsource(PatchGenerator._http_post)
