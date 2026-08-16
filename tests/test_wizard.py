"""Setup wizard tests — questionary absent, input() fallback exercised."""

import pytest

from blastradius.cli import wizard
from blastradius.cli.wizard import (
    _checkbox,
    _confirm,
    _int,
    _select,
    _text,
    main as wizard_main,
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv("BLASTRADIUS_ENV_FILE", raising=False)


def _write(tmp_path, content):
    path = tmp_path / ".env"
    path.write_text(content, encoding="utf-8")
    return path


# --- prompt helpers (input() fallback) ---------------------------------------


def test_text_fallback(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda prompt="": "hello")
    assert _text("Label") == "hello"


def test_text_fallback_default(monkeypatch):
    answers = iter(["", "x"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    assert _text("Label", default="keep") == "keep"  # blank keeps default
    assert _text("Label", default="keep") == "x"


def test_select_fallback(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda prompt="": "2")
    assert _select("Pick", ["a", "b", "c"], default="a") == "b"
    assert "1. a" in capsys.readouterr().out


def test_checkbox_fallback(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda prompt="": "1,3")
    assert _checkbox("Pick many", ["a", "b", "c"]) == ["a", "c"]


def test_checkbox_fallback_empty(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda prompt="": "")
    assert _checkbox("Pick many", ["a", "b"]) == []


def test_confirm_fallback(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    assert _confirm("Sure?") is True
    monkeypatch.setattr("builtins.input", lambda prompt="": "")
    assert _confirm("Sure?", default=False) is False


def test_int_fallback(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda prompt="": "42")
    assert _int("How many?", default=10) == 42
    monkeypatch.setattr("builtins.input", lambda prompt="": "not-a-number")
    assert _int("How many?", default=10) == 10


# --- wizard flow --------------------------------------------------------------


def test_wizard_writes_env(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTRADIUS_ENV_FILE", str(tmp_path / ".env"))
    (tmp_path / ".env").write_text("AUTH_TOKEN=keep\n", encoding="utf-8")

    monkeypatch.setattr(
        wizard,
        "_checkbox",
        lambda message, choices: ["deepseek"] if "providers" in message.lower() else ["slack"],
    )
    monkeypatch.setattr(wizard, "_password", lambda message: "sk-deepseek-1")
    monkeypatch.setattr(wizard, "_text", lambda message, default="": "https://hooks.slack.com/x")
    monkeypatch.setattr(wizard, "_select", lambda message, choices, default=None: "daily")
    monkeypatch.setattr(wizard, "_int", lambda message, default: 5)
    monkeypatch.setattr(wizard, "_confirm", lambda message, default=True: False)

    assert wizard_main() == 0
    env = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "DEEPSEEK_API_KEY=sk-deepseek-1" in env
    assert "SLACK_WEBHOOK_URL=https://hooks.slack.com/x" in env
    assert "HUNT_SCHEDULE=daily" in env
    assert "HUNT_MAX_TARGETS=5" in env
    assert "AUTH_TOKEN=keep" in env  # preserved


def test_wizard_no_providers(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTRADIUS_ENV_FILE", str(tmp_path / ".env"))
    monkeypatch.setattr(wizard, "_checkbox", lambda message, choices: [])
    monkeypatch.setattr(wizard, "_select", lambda message, choices, default=None: "disabled")
    monkeypatch.setattr(wizard, "_int", lambda message, default: 10)
    monkeypatch.setattr(wizard, "_confirm", lambda message, default=True: False)

    assert wizard_main() == 0
    env = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "HUNT_SCHEDULE=disabled" in env
    assert "DEEPSEEK_API_KEY" not in env


def test_wizard_test_scan_prompt(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTRADIUS_ENV_FILE", str(tmp_path / ".env"))
    monkeypatch.setattr(wizard, "_checkbox", lambda message, choices: [])
    monkeypatch.setattr(wizard, "_select", lambda message, choices, default=None: "disabled")
    monkeypatch.setattr(wizard, "_int", lambda message, default: 10)

    calls = {}

    def fake_confirm(message, default=True):
        calls["message"] = message
        return False  # do NOT actually run the hunt

    monkeypatch.setattr(wizard, "_confirm", fake_confirm)

    class _NoSubprocess:
        @staticmethod
        def run(*args, **kwargs):
            raise AssertionError("test scan should not run when declined")

    monkeypatch.setattr(wizard, "subprocess", _NoSubprocess)

    assert wizard_main() == 0
    assert "WebGoat" in calls["message"]


# --- setup_github_app still works with wizard helpers -------------------------


def test_setup_github_app_uses_wizard_helpers(tmp_path, monkeypatch, capsys):
    from scripts import setup_github_app

    monkeypatch.chdir(tmp_path)
    answers = iter(["123", "-----BEGIN KEY-----\nline", "whsec", "sk-oc"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    monkeypatch.setattr(setup_github_app, "test_webhook_connectivity", lambda: None)

    assert setup_github_app.main() == 0
    env = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "GITHUB_APP_ID=123" in env
    assert "BEGIN KEY" in env
    assert "OPENCODE_API_KEY=sk-oc" in env
