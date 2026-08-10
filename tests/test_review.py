"""LLM review tool tests — chat mocked, no network."""

from pathlib import Path

from blastradius.review import _chunks, _parse_findings, review_repo


class FakeClient:
    def __init__(self, reply="NO_ISSUES"):
        self.reply = reply
        self.calls = 0

    def chat(self, messages, system_prompt=""):
        self.calls += 1
        return self.reply


def test_chunks_respect_size_cap():
    text = ("x" * 100 + "\n") * 3000  # ~300KB
    chunks = _chunks(text)
    assert len(chunks) > 1
    for chunk, _ in chunks:
        assert len(chunk.encode("utf-8")) < 50 * 1024


def test_parse_findings_maps_lines():
    reply = "FILE:3 | HIGH | unchecked unwrap on attacker input\nFILE:10 | MEDIUM | oob index\n"
    findings = _parse_findings(reply, Path("/repo/a.cc"), start_line=100)
    assert findings[0]["line"] == 102  # 100 + 3 - 1
    assert findings[1]["line"] == 109
    assert findings[0]["severity"] == "HIGH"


def test_parse_findings_ignores_no_issues_and_malformed():
    reply = "NO_ISSUES\nfoo\nFILE:2 | LOW | reason\n"
    findings = _parse_findings(reply, Path("/repo/a.cc"), start_line=1)
    assert len(findings) == 1


def test_review_repo_collects_findings(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "core.cc").write_text("void f() {\n  x.unwrap();\n}\n", encoding="utf-8")
    (src / "core_test.cc").write_text("void f() { x.unwrap(); }\n", encoding="utf-8")  # skipped
    client = FakeClient("FILE:2 | HIGH | unchecked unwrap")
    findings = review_repo(str(tmp_path), limit=10, client=client)
    assert len(findings) == 1
    assert findings[0]["file"].endswith("core.cc")
    assert findings[0]["line"] == 2
    assert client.calls == 1  # test file was not sent


def test_review_repo_no_issues(tmp_path):
    (tmp_path / "a.cc").write_text("int f() { return 1; }\n", encoding="utf-8")
    client = FakeClient()
    assert review_repo(str(tmp_path), limit=10, client=client) == []


def test_review_passes_timeout_to_client(monkeypatch, tmp_path):
    (tmp_path / "a.cc").write_text("int f() { return 1; }\n", encoding="utf-8")
    captured = {}

    def fake_llm_client(**kwargs):
        captured.update(kwargs)
        return FakeClient()

    monkeypatch.setattr("blastradius.review.LLMClient", fake_llm_client)
    review_repo(str(tmp_path), limit=1, timeout=180)
    assert captured["timeout"] == 180


def test_review_skips_bare_test_dir(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "core.cc").write_text("void f() { x.unwrap(); }\n", encoding="utf-8")
    (src / "test").mkdir(parents=True)
    (src / "test" / "x.cc").write_text("void f() { x.unwrap(); }\n", encoding="utf-8")
    client = FakeClient("FILE:1 | HIGH | unchecked unwrap")
    findings = review_repo(str(tmp_path), limit=10, client=client)
    assert len(findings) == 1
    assert Path(findings[0]["file"]).name == "core.cc"  # bare test/ dir file was skipped
    assert "test" not in Path(findings[0]["file"]).parts
    assert client.calls == 1


def test_review_parallel_runs_concurrently(tmp_path):
    import threading
    import time

    state = {"active": 0, "max_active": 0, "lock": threading.Lock()}

    class SlowClient:
        def chat(self, messages, system_prompt=""):
            with state["lock"]:
                state["active"] += 1
                state["max_active"] = max(state["max_active"], state["active"])
            time.sleep(0.05)
            with state["lock"]:
                state["active"] -= 1
            return "FILE:1 | HIGH | unchecked unwrap"

    for i in range(6):
        (tmp_path / f"f{i}.cc").write_text("void f() { x.unwrap(); }\n", encoding="utf-8")
    findings = review_repo(str(tmp_path), limit=10, client=SlowClient(), workers=4)
    assert len(findings) == 6
    assert state["max_active"] > 1  # chunks overlapped


def test_review_retries_transient_failure(tmp_path):
    class FlakyClient:
        def __init__(self):
            self.calls = 0

        def chat(self, messages, system_prompt=""):
            self.calls += 1
            if self.calls == 1:
                raise TimeoutError("transient")
            return "FILE:1 | HIGH | unchecked unwrap"

    (tmp_path / "a.cc").write_text("void f() { x.unwrap(); }\n", encoding="utf-8")
    client = FlakyClient()
    findings = review_repo(str(tmp_path), limit=1, client=client)
    assert len(findings) == 1  # retried and succeeded


def test_review_stops_after_failure_streak(tmp_path):
    class DeadClient:
        def chat(self, messages, system_prompt=""):
            raise TimeoutError("down")

    for i in range(10):
        (tmp_path / f"f{i}.cc").write_text("void f() { x.unwrap(); }\n", encoding="utf-8")
    # 10 files, each chunk fails twice (retry) — must stop early via the streak guard
    findings = review_repo(str(tmp_path), limit=10, client=DeadClient(), workers=4)
    assert findings == []
