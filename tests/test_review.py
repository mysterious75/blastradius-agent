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
