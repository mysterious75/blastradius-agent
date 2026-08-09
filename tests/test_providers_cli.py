"""Provider CLI tests — no network, no real keys."""

import pytest

from blastradius.providers.cli import cmd_list, cmd_set, main
from blastradius.providers.registry import PROVIDER_REGISTRY


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    from blastradius.providers.registry import PROVIDER_REGISTRY as R

    for cfg in R.values():
        if cfg.get("key_env"):
            monkeypatch.delenv(cfg["key_env"], raising=False)
    monkeypatch.delenv("BLASTRADIUS_PROVIDER", raising=False)
    monkeypatch.delenv("BLASTRADIUS_MODEL", raising=False)


def test_cli_list_shows_all_providers(capsys):
    rc = main(["list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Provider" in out and "Models" in out and "Key" in out and "Status" in out
    for name in PROVIDER_REGISTRY:
        assert name in out
    assert "no key" in out  # no env keys set


def test_cli_set_writes_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    rc = main(["set", "--provider", "deepseek", "--model", "deepseek-chat"])
    assert rc == 0
    env = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "BLASTRADIUS_PROVIDER=deepseek" in env
    assert "BLASTRADIUS_MODEL=deepseek-chat" in env


def test_cli_set_default_model(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    rc = main(["set", "--provider", "groq"])
    assert rc == 0
    env = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "BLASTRADIUS_PROVIDER=groq" in env
    assert "BLASTRADIUS_MODEL=llama-3.1-70b-versatile" in env


def test_cli_set_unknown_provider(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    rc = main(["set", "--provider", "nope"])
    assert rc == 1
    assert "unknown provider" in capsys.readouterr().out
    assert not (tmp_path / ".env").exists()


def test_cli_set_preserves_existing_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("AUTH_TOKEN=keep\n", encoding="utf-8")
    main(["set", "--provider", "xai", "--model", "grok-4.5"])
    env = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "AUTH_TOKEN=keep" in env
    assert "BLASTRADIUS_PROVIDER=xai" in env


def test_cli_test_reports_ok_and_no_key(capsys, monkeypatch):
    monkeypatch.setenv("OPENCODE_API_KEY", "oc")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "ds")
    from blastradius.providers.client import LLMClient

    def fake_chat(self, messages, system_prompt=""):
        if self.provider in ("opencode_zen", "deepseek"):
            return "OK"
        raise RuntimeError("unreachable")

    monkeypatch.setattr(LLMClient, "chat", fake_chat)
    rc = main(["test"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "✅ opencode_zen" in out
    assert "✅ deepseek" in out
    assert "❌ anthropic" in out
    assert "No API key" in out
    assert "Connected" in out


def test_cli_list_key_status(capsys, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "oa")
    rc = cmd_list(None)
    assert rc == 0
    out = capsys.readouterr().out
    lines = {line.split()[0]: line for line in out.splitlines() if line.strip()}
    assert "ready" in lines["openai"]
    assert "no key" in lines["anthropic"]
    assert "local" in lines["ollama"]
