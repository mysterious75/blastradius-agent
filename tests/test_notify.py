"""Notifier tests — all channels mocked, no network."""

import pytest

from blastradius.db.database import SQLiteDB
from blastradius.hunter.scanner import Finding
from blastradius.notify.notifier import Notifier


def make_finding(vuln_type="sqli"):
    return Finding(file="/tmp/repo/flask_admin/rediscli.js", line=27,
                   vuln_type=vuln_type, payload="x", confidence=0.95,
                   severity="HIGH", cwe="CWE-79", description="d", remediation="r")


def make_patch_result(needs_human=False):
    class PR:
        pass

    PR.needs_human = needs_human
    return PR()


class FakeHttp:
    def __init__(self):
        self.calls = []

    def __call__(self, url, payload, headers=None):
        self.calls.append({"url": url, "payload": payload, "headers": headers})
        return 200


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for key in (
        "SLACK_WEBHOOK_URL", "DISCORD_WEBHOOK_URL", "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_CHAT_ID", "SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS",
        "NOTIFY_EMAIL", "GITHUB_TOKEN", "BLASTRADIUS_ISSUES_REPO",
    ):
        monkeypatch.delenv(key, raising=False)


def test_no_channels_configured():
    n = Notifier(db=None)
    assert n.configured_channels() == []
    assert n.notify_finding(make_finding()) == []


def test_slack_channel(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/x")
    fake = FakeHttp()
    n = Notifier(http=fake, db=None)
    assert n.configured_channels() == ["slack"]
    n.notify_finding(make_finding())
    call = fake.calls[0]
    assert call["url"] == "https://hooks.slack.com/x"
    assert "[SQLI] confirmed" in call["payload"]["text"]
    assert "rediscli.js:27" in call["payload"]["text"]


def test_discord_embed_colors(monkeypatch):
    monkeypatch.setenv("DISCORD_WEBHOOK_URL", "https://discord.com/x")
    fake = FakeHttp()
    n = Notifier(http=fake, db=None)
    n.notify_finding(make_finding(), make_patch_result(needs_human=False))
    assert fake.calls[0]["payload"]["embeds"][0]["color"] == 0xFF4444  # red

    fake.calls.clear()
    n.notify_finding(make_finding(), make_patch_result(needs_human=True))
    assert fake.calls[0]["payload"]["embeds"][0]["color"] == 0xD29922  # yellow


def test_telegram_channel(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "bot123")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "chat-1")
    fake = FakeHttp()
    n = Notifier(http=fake, db=None)
    n.notify_finding(make_finding())
    call = fake.calls[0]
    assert call["url"] == "https://api.telegram.org/botbot123/sendMessage"
    assert call["payload"]["chat_id"] == "chat-1"
    assert "BlastRadius" in call["payload"]["text"]


def test_email_channel(monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "smtp.test.com")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_USER", "u")
    monkeypatch.setenv("SMTP_PASS", "p")
    monkeypatch.setenv("NOTIFY_EMAIL", "a@b.com")

    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            sent["host"] = host

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self):
            sent["tls"] = True

        def login(self, user, pw):
            sent["login"] = (user, pw)

        def sendmail(self, frm, to, msg):
            sent["from"] = frm
            sent["to"] = to
            sent["body"] = msg

    monkeypatch.setattr("blastradius.notify.notifier.smtplib.SMTP", FakeSMTP)
    n = Notifier(http=FakeHttp(), db=None)
    n.notify_finding(make_finding())
    assert sent["host"] == "smtp.test.com"
    assert sent["tls"] is True
    assert sent["to"] == ["a@b.com"]
    assert "BlastRadius Alert: SQLI" in sent["body"]


def test_github_channel(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_x")
    monkeypatch.setenv("BLASTRADIUS_ISSUES_REPO", "me/issues")
    fake = FakeHttp()
    n = Notifier(http=fake, db=None)
    n.notify_finding(make_finding(), make_patch_result(needs_human=True))
    call = fake.calls[0]
    assert call["url"] == "https://api.github.com/repos/me/issues/issues"
    assert call["payload"]["labels"] == ["security-finding", "needs-review"]
    assert "Bearer ghp_x" in call["headers"]["Authorization"]


def test_graceful_skip_when_unconfigured(monkeypatch):
    fake = FakeHttp()
    n = Notifier(http=fake, db=None)
    assert n.configured_channels() == []
    n.notify_finding(make_finding())
    assert fake.calls == []


def test_all_channels_fire_together_and_log(monkeypatch, tmp_path):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/x")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "bot1")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "c1")
    fake = FakeHttp()
    db = SQLiteDB(db_path=str(tmp_path / "n.db"))
    n = Notifier(http=fake, db=db)
    errors = n.notify_finding(make_finding())
    assert errors == []
    assert len(fake.calls) == 2  # slack + telegram
    with db._connect() as conn:
        rows = conn.execute("SELECT * FROM providers_log").fetchall()
    providers = {r["provider"] for r in rows}
    assert "notify:slack" in providers and "notify:telegram" in providers


def test_channel_error_is_reported():
    def boom(url, payload, headers=None):
        raise RuntimeError("nope")

    n = Notifier(http=boom, db=None)
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/x")
    try:
        errors = n.notify_finding(make_finding())
        assert errors and "slack" in errors[0]
    finally:
        monkeypatch.undo()
