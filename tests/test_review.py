"""LLM review tool tests — chat mocked, no network."""

from pathlib import Path

from blastradius.review import (
    _chunks,
    _parse_findings,
    review_repo,
    verify_finding,
)


class FakeClient:
    def __init__(self, reply="NO_ISSUES", verify_reply="CONFIRMED: matches the code"):
        self.reply = reply
        self.verify_reply = verify_reply
        self.calls = 0

    def chat(self, messages, system_prompt=""):
        self.calls += 1
        content = messages[0]["content"]
        if content.startswith("VERIFY THIS CLAIM"):
            return self.verify_reply
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
    assert findings[0]["verified"] is True
    assert client.calls == 2  # 1 scan chunk + 1 verification call


def test_review_drops_rejected_findings(tmp_path):
    (tmp_path / "a.cc").write_text(
        "void f() {\n  return paf.promise.exclusiveJoin(onAbort().then([] { KJ_UNREACHABLE; }));\n}\n",
        encoding="utf-8",
    )
    client = FakeClient(
        "FILE:3 | CRITICAL | KJ_UNREACHABLE on abort",
        verify_reply="REJECTED: deliberate abort path, no user-controlled boundary crossing",
    )
    findings = review_repo(str(tmp_path), limit=10, client=client)
    assert findings == []  # verification gate rejected the by-design abort flag


def test_verify_finding_confirmed_and_rejected():
    finding = {"file": "/repo/a.cc", "line": 5, "severity": "HIGH", "reason": "UAF"}
    confirmed = verify_finding(finding, "x\ny\nz\nw\nv\n", FakeClient(verify_reply="CONFIRMED: real"))
    assert confirmed["verified"] is True
    rejected = verify_finding(
        finding, "x\n", FakeClient(verify_reply="REJECTED: hardening only")
    )
    assert rejected["verified"] is False
    # fail-closed: unparseable / missing verification replies count as rejected
    unparseable = verify_finding(finding, "x\n", FakeClient(verify_reply="maybe?"))
    assert unparseable["verified"] is False


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
    assert client.calls == 2  # 1 scan chunk + 1 verification call


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
            if messages[0]["content"].startswith("VERIFY THIS CLAIM"):
                return "CONFIRMED: matches"
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
            if messages[0]["content"].startswith("VERIFY THIS CLAIM"):
                return "CONFIRMED: matches"
            return "FILE:1 | HIGH | unchecked unwrap"

    (tmp_path / "a.cc").write_text("void f() { x.unwrap(); }\n", encoding="utf-8")
    client = FlakyClient()
    findings = review_repo(str(tmp_path), limit=1, client=client)
    assert len(findings) == 1  # retried, then the finding passed verification


def test_review_stops_after_failure_streak(tmp_path):
    class DeadClient:
        def chat(self, messages, system_prompt=""):
            raise TimeoutError("down")

    for i in range(10):
        (tmp_path / f"f{i}.cc").write_text("void f() { x.unwrap(); }\n", encoding="utf-8")
    # 10 files, each chunk fails twice (retry) — must stop early via the streak guard
    findings = review_repo(str(tmp_path), limit=10, client=DeadClient(), workers=4)
    assert findings == []
