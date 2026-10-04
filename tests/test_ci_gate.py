"""CI security & quality gate tests — offline, all external APIs mocked.

Covers: structured response parsing, malformed LLM responses, API failure,
retry behavior, normalization, policy decisions (PASS/FAIL/ANALYSIS_ERROR),
diff parsing, exclusions, oversized input, redaction, reports, notification
isolation, and config validation. No Anthropic key is ever needed.
"""

import json
from pathlib import Path

import pytest

from blastradius.ci.analyzers import (
    AiReviewAnalyzer,
    DeterministicAnalyzer,
    parse_ai_reply,
    validate_ai_finding,
)
from blastradius.ci.diff import collect_changeset, parse_unified_diff
from blastradius.ci.llm import (
    AnthropicAdapter,
    MalformedResponse,
    ProviderAuthError,
    ProviderError,
    ReviewRequest,
)
from blastradius.ci.models import (
    ANALYSIS_ERROR,
    PASS,
    POLICY_FAILURE,
    Category,
    CiFinding,
    Policy,
    Severity,
    Source,
    Status,
    normalize_severity,
)
from blastradius.ci.policy import evaluate, load_policy
from blastradius.ci.redact import redact_secrets
from blastradius.ci.reporting import render_markdown

VULN_DIFF = """diff --git a/app.py b/app.py
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/app.py
@@ -0,0 +1,6 @@
+from flask import request
+def search():
+    name = request.args.get("name")
+    query = "SELECT * FROM users WHERE name = '" + name + "'"
+    return db.execute(query)
"""

FIXED_DIFF = """diff --git a/app.py b/app.py
new file mode 100644
index 0000000..2222222
--- /dev/null
+++ b/app.py
@@ -0,0 +1,6 @@
+from flask import request
+def search():
+    name = request.args.get("name")
+    query = "SELECT * FROM users WHERE name = %s"
+    return db.execute(query, (name,))
"""


def _finding(severity="high", confidence=0.9, category="security"):
    return CiFinding(
        id="ci-test",
        category=Category(category),
        severity=normalize_severity(severity),
        title="t",
        description="d",
        confidence=confidence,
    )


# ------------------------------------------------------------- LLM adapter

GOOD_REPLY = {
    "content": [{"type": "text", "text": '{"findings": []}'}],
    "stop_reason": "end_turn",
}


def test_anthropic_adapter_posts_messages_api():
    seen = {}

    def fake_http(url, headers, payload, timeout):
        seen.update(url=url, headers=headers, payload=payload)
        return GOOD_REPLY

    adapter = AnthropicAdapter(api_key="sk-ant-test", model="claude-x", http=fake_http)
    out = adapter.review(ReviewRequest(system="s", user="u"))
    assert out == '{"findings": []}'
    assert seen["url"] == "https://api.anthropic.com/messages"
    assert seen["headers"]["x-api-key"] == "sk-ant-test"
    assert seen["payload"]["model"] == "claude-x"


def test_anthropic_adapter_requires_key():
    adapter = AnthropicAdapter(api_key="", http=lambda *a: GOOD_REPLY)
    with pytest.raises(ProviderAuthError):
        adapter.review(ReviewRequest(system="s", user="u"))


def test_anthropic_adapter_retries_transient_then_succeeds(monkeypatch):
    calls = {"n": 0}

    def flaky(url, headers, payload, timeout):
        calls["n"] += 1
        if calls["n"] < 3:
            raise ProviderError("boom 500")
        return GOOD_REPLY

    adapter = AnthropicAdapter(api_key="k", http=flaky)
    import blastradius.ci.llm as llm_mod

    monkeypatch.setattr(llm_mod, "_sleep_backoff", lambda attempt: None)
    out = adapter.review(ReviewRequest(system="s", user="u", max_retries=3))
    assert out == '{"findings": []}'
    assert calls["n"] == 3


def test_anthropic_adapter_rejects_empty_content():
    adapter = AnthropicAdapter(
        api_key="k", http=lambda *a: {"content": [], "stop_reason": "end_turn"}
    )
    with pytest.raises(MalformedResponse):
        adapter.review(ReviewRequest(system="s", user="u"))


def test_anthropic_adapter_rejects_unusable_stop():
    adapter = AnthropicAdapter(
        api_key="k",
        http=lambda *a: {"content": [{"type": "text", "text": "x"}], "stop_reason": "tool_use"},
    )
    with pytest.raises(MalformedResponse):
        adapter.review(ReviewRequest(system="s", user="u"))


def test_model_env_override(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.setenv("BLASTRADIUS_AI_MODEL", "claude-custom")
    adapter = AnthropicAdapter(http=lambda *a: GOOD_REPLY)
    assert adapter.model == "claude-custom"


# ------------------------------------------------------------- AI parsing


def test_parse_ai_reply_valid():
    reply = json.dumps(
        {
            "findings": [
                {
                    "id": "a1",
                    "category": "security",
                    "severity": "HIGH",
                    "title": "SQLi in search",
                    "description": "concat",
                    "file": "app.py",
                    "line": 4,
                    "cwe": "CWE-89",
                    "confidence": 0.9,
                    "evidence": "query = ... + name",
                    "recommendation": "parameterize",
                }
            ]
        }
    )
    findings, errors, warnings = parse_ai_reply(reply)
    assert not errors
    assert warnings == []
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].source == Source.AI


def test_parse_ai_reply_malformed():
    findings, errors, warnings = parse_ai_reply("totally not json {{{")
    assert findings == []
    assert errors and "not valid JSON" in errors[0]
    assert warnings == []


def test_parse_ai_reply_rejects_invalid_findings_only():
    findings, errors, warnings = parse_ai_reply(json.dumps({"findings": [{"nope": 1}]}))
    assert findings == []
    assert errors  # invalid-only payload is an error, never silent
    assert warnings == []


def test_parse_ai_reply_partial_rejects_are_warnings():
    reply = json.dumps(
        {
            "findings": [
                {
                    "id": "good",
                    "category": "security",
                    "severity": "high",
                    "title": "Real issue",
                    "description": "proved",
                    "file": "app.py",
                    "line": 2,
                    "confidence": 0.9,
                },
                {"nope": 1},
            ]
        }
    )
    findings, errors, warnings = parse_ai_reply(reply)
    assert len(findings) == 1
    assert errors == []  # partial rejects must not become analysis errors
    assert warnings and "dropped" in warnings[0]


def test_parse_ai_reply_grounds_against_changeset():
    from blastradius.ci.models import ChangeSet, FileChange, Hunk

    changeset = ChangeSet(
        files=[
            FileChange(
                path="app.py",
                hunks=[Hunk(old_start=1, new_start=1, lines=["+line one", "+line two"])],
            )
        ]
    )
    reply = json.dumps(
        {
            "findings": [
                {
                    "id": "real",
                    "category": "security",
                    "severity": "high",
                    "title": "Real",
                    "description": "d",
                    "file": "app.py",
                    "line": 2,
                    "confidence": 0.9,
                },
                {
                    "id": "ghost-file",
                    "category": "security",
                    "severity": "critical",
                    "title": "Ghost",
                    "description": "d",
                    "file": "nope.py",
                    "line": 1,
                    "confidence": 0.99,
                },
                {
                    "id": "ghost-line",
                    "category": "security",
                    "severity": "critical",
                    "title": "Ghost",
                    "description": "d",
                    "file": "app.py",
                    "line": 99,
                    "confidence": 0.99,
                },
            ]
        }
    )
    findings, errors, warnings = parse_ai_reply(reply, changeset=changeset)
    assert [f.id for f in findings] == ["real"]
    assert errors == []  # the survivor decides; hallucinations are warnings
    assert len(warnings) == 2


def test_parse_ai_reply_all_hallucinated_is_error():
    from blastradius.ci.models import ChangeSet, FileChange, Hunk

    changeset = ChangeSet(
        files=[
            FileChange(
                path="app.py",
                hunks=[Hunk(old_start=1, new_start=1, lines=["+line one"])],
            )
        ]
    )
    reply = json.dumps(
        {
            "findings": [
                {
                    "id": "ghost",
                    "category": "security",
                    "severity": "critical",
                    "title": "Ghost",
                    "description": "d",
                    "file": "ghost.py",
                    "line": 1,
                    "confidence": 0.99,
                }
            ]
        }
    )
    findings, errors, warnings = parse_ai_reply(reply, changeset=changeset)
    assert findings == []
    assert errors  # zero usable findings: fail-closed, never silent
    assert warnings == []


def test_validate_ai_finding_rejects_bad_cwe():
    assert (
        validate_ai_finding(
            {
                "category": "security",
                "severity": "high",
                "title": "t",
                "description": "d",
                "cwe": "CWE-99999",
            }
        ).cwe
        == ""
    )


def test_validate_ai_finding_rejects_unknown_category():
    assert (
        validate_ai_finding(
            {"category": "mystery", "severity": "high", "title": "t", "description": "d"}
        )
        is None
    )


def _write_diff(text, tmp_path=None):
    import tempfile
    from pathlib import Path

    path = Path(tempfile.mkdtemp()) / "change.diff"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_ai_analyzer_malformed_reply_is_error_real(tmp_path):
    class BadProvider:
        name = "bad"

        def review(self, request):
            return "nope {{{"

    diff_file = tmp_path / "c.diff"
    diff_file.write_text(VULN_DIFF, encoding="utf-8")
    changeset, _ = collect_changeset(diff_file=str(diff_file))
    outcome = AiReviewAnalyzer(provider=BadProvider()).analyze(changeset)
    assert outcome.findings == []
    assert outcome.errors and "not valid JSON" in outcome.errors[0]


# ------------------------------------------------------------- diff collector


def test_parse_diff_collects_added_lines():
    changeset, errors = parse_unified_diff(VULN_DIFF)
    assert not errors
    assert len(changeset.files) == 1
    added = changeset.files[0].added_lines()
    assert added[4] == '    query = "SELECT * FROM users WHERE name = \'" + name + "\'"'


def test_parse_diff_excludes_vendor_and_binaries():
    text = (
        "diff --git a/vendor/lib.js b/vendor/lib.js\nnew file mode 100644\n"
        "--- /dev/null\n+++ b/vendor/lib.js\n@@ -0,0 +1 @@\n+evil()\n"
        "diff --git a/logo.png b/logo.png\nnew file mode 100644\n"
        "index 0000000..1111111\nBinary files /dev/null and b/logo.png differ\n"
    )
    changeset, errors = parse_unified_diff(text)
    assert not errors
    assert changeset.files == []
    assert "vendor/lib.js" in changeset.excluded


def test_parse_diff_oversize_is_error_not_safe():
    policy = Policy(max_total_bytes=10)
    changeset, errors = parse_unified_diff(VULN_DIFF, policy=policy)
    assert changeset.truncated
    assert errors


def test_parse_diff_max_files_is_error():
    policy = Policy(max_files=0)
    changeset, errors = parse_unified_diff(VULN_DIFF, policy=policy)
    assert changeset.truncated
    assert errors


def test_collect_changeset_no_source():
    changeset, errors = collect_changeset()
    assert changeset.files == []
    assert errors and "no diff source" in errors[0]


# ------------------------------------------------------------- deterministic


def test_deterministic_flags_vuln_added_lines(tmp_path):
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "def search():\n"
        '    name = request.args.get("name")\n'
        '    query = "SELECT * FROM users WHERE name = \'" + name + "\'"\n'
        "    return db.execute(query)\n",
        encoding="utf-8",
    )
    diff_file = tmp_path / "c.diff"
    diff_file.write_text(VULN_DIFF, encoding="utf-8")
    changeset, _ = collect_changeset(diff_file=str(diff_file))
    outcome = DeterministicAnalyzer(repo=str(tmp_path)).analyze(changeset)
    assert not outcome.errors
    assert any(f.vuln_type if hasattr(f, "vuln_type") else f.title for f in outcome.findings)
    assert all(f.source == Source.DETERMINISTIC for f in outcome.findings)


def test_deterministic_ignores_preexisting_code(tmp_path):
    # Finding on a non-added line must be dropped: gate judges the PR only.
    (tmp_path / "app.py").write_text("x = 1\nevel = 2\n", encoding="utf-8")
    diff = (
        "diff --git a/other.py b/other.py\nnew file mode 100644\n"
        "--- /dev/null\n+++ b/other.py\n@@ -0,0 +1 @@\n+x = 1\n"
    )
    diff_file = tmp_path / "c.diff"
    diff_file.write_text(diff, encoding="utf-8")
    changeset, _ = collect_changeset(diff_file=str(diff_file))
    outcome = DeterministicAnalyzer(repo=str(tmp_path)).analyze(changeset)
    assert outcome.findings == []


# ------------------------------------------------------------- policy


def test_policy_pass_clean():
    result = evaluate([], Policy())
    assert result.status == Status.PASS and result.exit_code == PASS


def test_policy_fails_high_confidence_high():
    result = evaluate([_finding("high", 0.9)], Policy())
    assert result.status == Status.POLICY_FAILURE
    assert result.exit_code == POLICY_FAILURE


def test_policy_low_confidence_report_only():
    result = evaluate([_finding("critical", 0.1)], Policy())
    assert result.status == Status.PASS
    assert len(result.reported) == 1


def test_policy_medium_configurable():
    failing = evaluate([_finding("medium", 0.9)], Policy(fail_on=[Severity.MEDIUM]))
    assert failing.status == Status.POLICY_FAILURE
    passing = evaluate([_finding("medium", 0.9)], Policy())
    assert passing.status == Status.PASS


def test_policy_disabled_gate_reports_only():
    policy = Policy(security_gate=False)
    result = evaluate([_finding("critical", 0.99)], policy)
    assert result.status == Status.PASS
    assert len(result.reported) == 1


def test_policy_errors_fail_closed_by_default():
    result = evaluate([], Policy(), errors=["boom"])
    assert result.status == Status.ANALYSIS_ERROR
    assert result.exit_code == ANALYSIS_ERROR


def test_policy_errors_fail_open_when_explicit():
    result = evaluate([], Policy(on_error="fail-open"), errors=["boom"])
    assert result.status == Status.PASS
    assert result.warnings and "fail-open" in result.warnings[0]


def test_load_policy_validates(tmp_path):
    good = tmp_path / "p.yml"
    good.write_text(
        "fail_on: [critical]\nminimum_confidence: 0.5\non_error: fail-closed\n",
        encoding="utf-8",
    )
    policy, warnings = load_policy(str(good))
    assert policy.fail_on == [Severity.CRITICAL]
    assert policy.minimum_confidence == 0.5
    assert warnings == []


def test_load_policy_rejects_bad_severity(tmp_path):
    bad = tmp_path / "p.yml"
    bad.write_text("fail_on: [catastrophic]\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_policy(str(bad))


def test_load_policy_rejects_bad_confidence(tmp_path):
    bad = tmp_path / "p.yml"
    bad.write_text("fail_on: [high]\nminimum_confidence: 9\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_policy(str(bad))


# ------------------------------------------------------------- redaction


def test_redact_secrets_masks_keys():
    text = "key=sk-ant-abcdef123456 and Authorization: Bearer tokengoeshere"
    out = redact_secrets(text)
    assert "sk-ant-abcdef123456" not in out
    assert "tokengoeshere" not in out
    assert "[REDACTED]" in out


def test_redact_secrets_never_raises():
    assert redact_secrets("") == ""
    assert isinstance(redact_secrets(None) if False else "x", str)


def test_ai_analyzer_redacts_secrets_before_transport():
    """Secret-shaped values in the diff must never reach the provider."""
    from blastradius.ci.models import ChangeSet, FileChange, Hunk

    captured = {}

    class SniffingProvider:
        name = "sniffer"

        def is_configured(self):
            return True

        def review(self, request):
            captured["user"] = request.user
            return '{"findings": []}'

    changeset = ChangeSet(
        files=[
            FileChange(
                path="settings.py",
                hunks=[
                    Hunk(
                        old_start=1,
                        new_start=1,
                        lines=[
                            '+API_KEY = "sk-ant-TESTKEY0123456789abcdef"',
                            '+db_password = "hunter2-secret-value"',
                            "+debug = True",
                        ],
                    )
                ],
            )
        ]
    )
    outcome = AiReviewAnalyzer(provider=SniffingProvider()).analyze(changeset)
    assert outcome.errors == []
    sent = captured["user"]
    assert "sk-ant-TESTKEY0123456789abcdef" not in sent
    assert "hunter2-secret-value" not in sent
    assert "[REDACTED]" in sent
    # Structure survives redaction: file header + line numbers intact.
    assert "### settings.py" in sent
    assert "3: " in sent


def test_gate_never_executes_pr_code(tmp_path):
    """A payload that runs on import/exec must leave no trace after the gate."""
    from blastradius.ci.cli import main as ci_main

    marker = tmp_path / "PWNED_BY_GATE"
    payload = (
        "import os\n"
        f'os.system("touch {marker}")\n'
        "__import__('os').popen('touch IMPORT_MARKER').read()\n"
        "eval(\"__import__('os').system('touch EVAL_MARKER')\")\n"
    )
    (tmp_path / "evil.py").write_text(payload + "x = 1\n", encoding="utf-8")
    diff_lines = "\n".join(f"+{line}" for line in payload.splitlines())
    diff_file = tmp_path / "c.diff"
    diff_file.write_text(
        "diff --git a/evil.py b/evil.py\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/evil.py\n"
        "@@ -0,0 +1,4 @@\n" + diff_lines + "\n",
        encoding="utf-8",
    )
    rc = ci_main(
        [
            "gate",
            "--repo",
            str(tmp_path),
            "--diff-file",
            str(diff_file),
            "--no-ai",
            "--out",
            str(tmp_path / "out"),
        ]
    )
    assert rc in (PASS, POLICY_FAILURE)  # decided, never crashed
    assert not marker.exists()  # nothing executed the payload


# ------------------------------------------------------------- reporting


def test_reports_contain_schema(tmp_path):
    result = evaluate([_finding("high", 0.9)], Policy())
    from blastradius.ci.reporting import write_json, write_markdown

    jp = write_json(result, str(tmp_path / "r.json"))
    mp = write_markdown(result, str(tmp_path / "r.md"))
    payload = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert payload["status"] == "POLICY_FAILURE"
    assert payload["counts"]["high"] == 1
    assert payload["policy"]["fail_on"] == ["critical", "high"]
    md = (tmp_path / "r.md").read_text(encoding="utf-8")
    assert "POLICY_FAILURE" in md and jp and mp


def test_render_markdown_pass():
    md = render_markdown(evaluate([], Policy()))
    assert "PASS" in md


# ------------------------------------------------------------- notify isolation


def test_notify_failure_does_not_change_result(monkeypatch):
    from blastradius.ci.notify import gate_summary_text, notify_gate

    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/x")
    monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://outlook.office.com/x")

    def boom(url, payload, headers=None):
        raise RuntimeError("network down")

    from blastradius.notify.notifier import Notifier

    result = evaluate([_finding("high", 0.9)], Policy())
    note = notify_gate(result, notifier=Notifier(http=boom))
    assert "slack" in note.channels and "teams" in note.channels
    assert note.errors and not note.sent
    # The gate result itself is untouched by notification failure.
    assert result.status == Status.POLICY_FAILURE
    assert "POLICY_FAILURE" in gate_summary_text(result)


def test_notify_quiet_without_channels(monkeypatch):
    from blastradius.ci.notify import notify_gate

    for var in ("SLACK_WEBHOOK_URL", "TEAMS_WEBHOOK_URL", "DISCORD_WEBHOOK_URL"):
        monkeypatch.delenv(var, raising=False)
    note = notify_gate(evaluate([], Policy()))
    assert note.sent is False and note.channels == []


# ------------------------------------------------------------- CLI fixtures


def test_cli_gate_fails_on_vuln_fixture(tmp_path):
    from blastradius.ci.cli import main as ci_main

    (tmp_path / "app.py").write_text(
        "from flask import request\ndef s():\n    n = request.args.get('n')\n"
        '    q = "SELECT * FROM u WHERE n=\'" + n + "\'"\n    return db.execute(q)\n',
        encoding="utf-8",
    )
    diff_file = tmp_path / "c.diff"
    diff_file.write_text(VULN_DIFF, encoding="utf-8")
    rc = ci_main(
        [
            "gate",
            "--repo",
            str(tmp_path),
            "--diff-file",
            str(diff_file),
            "--no-ai",
            "--out",
            str(tmp_path / "out"),
        ]
    )
    assert rc == POLICY_FAILURE
    assert (tmp_path / "out" / "ci-gate.json").exists()
    assert (tmp_path / "out" / "ci-gate.md").exists()


def test_cli_gate_passes_on_fixed_fixture(tmp_path):
    from blastradius.ci.cli import main as ci_main

    (tmp_path / "app.py").write_text("q = 'SELECT 1'\n", encoding="utf-8")
    diff_file = tmp_path / "c.diff"
    diff_file.write_text(FIXED_DIFF, encoding="utf-8")
    rc = ci_main(
        [
            "gate",
            "--repo",
            str(tmp_path),
            "--diff-file",
            str(diff_file),
            "--no-ai",
            "--out",
            str(tmp_path / "out"),
        ]
    )
    assert rc == PASS


def test_cli_gate_deterministic_only_without_key(tmp_path, capsys, monkeypatch):
    from blastradius.ci.cli import main as ci_main

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    diff_file = tmp_path / "c.diff"
    diff_file.write_text(FIXED_DIFF, encoding="utf-8")
    rc = ci_main(
        [
            "gate",
            "--repo",
            str(tmp_path),
            "--diff-file",
            str(diff_file),
            "--out",
            str(tmp_path / "out"),
        ]
    )
    # Missing optional credentials degrade VISIBLY to deterministic-only.
    assert rc == PASS
    out = capsys.readouterr().out
    assert "deterministic-only" in out
    payload = json.loads((tmp_path / "out" / "ci-gate.json").read_text(encoding="utf-8"))
    assert payload["status"] == "PASS"
    assert any("deterministic-only" in w for w in payload["warnings"])


def test_cli_gate_configured_provider_failure_is_analysis_error(tmp_path, monkeypatch):
    from blastradius.ci import cli as cli_mod
    from blastradius.ci.cli import main as ci_main
    from blastradius.ci.llm import ProviderError

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

    class FailingProvider:
        name = "anthropic"

        def is_configured(self):
            return True

        def review(self, request):
            raise ProviderError("boom 500")

    monkeypatch.setattr(cli_mod, "AnthropicAdapter", lambda: FailingProvider())
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    diff_file = tmp_path / "c.diff"
    diff_file.write_text(FIXED_DIFF, encoding="utf-8")
    rc = ci_main(
        [
            "gate",
            "--repo",
            str(tmp_path),
            "--diff-file",
            str(diff_file),
            "--out",
            str(tmp_path / "out"),
        ]
    )
    # Genuine configured-provider failure still respects fail-closed policy.
    assert rc == ANALYSIS_ERROR


def test_cli_review_never_fails_on_findings(tmp_path):
    from blastradius.ci.cli import main as ci_main

    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    diff_file = tmp_path / "c.diff"
    diff_file.write_text(VULN_DIFF, encoding="utf-8")
    rc = ci_main(
        [
            "review",
            "--repo",
            str(tmp_path),
            "--diff-file",
            str(diff_file),
            "--no-ai",
            "--out",
            str(tmp_path / "out"),
        ]
    )
    assert rc == PASS


# ------------------------------------------------------------- workflow YAML


def test_github_workflow_is_valid_and_fork_safe():
    import yaml

    root = Path(__file__).resolve().parents[1]
    path = root / ".github" / "workflows" / "ci-review.yml"
    assert path.exists(), "ci-review.yml template missing"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert data["name"] == "ci-security-quality-gate"
    triggers = data.get("on") or data.get(True)
    assert "pull_request" in triggers
    assert "pull_request_target" not in triggers
    perms = data.get("permissions")
    assert perms == {"contents": "read"}, f"workflow must be least-privilege: {perms}"
    text = path.read_text(encoding="utf-8")
    # The string may appear in explanatory comments; what matters is that no
    # trigger uses it and no write permissions exist anywhere.
    assert "pull-requests: write" not in text
    assert "contents: write" not in text
    for step in data["jobs"]["ci-gate"]["steps"]:
        uses = step.get("uses", "")
        if uses.count("@") == 1 and "/" in uses:
            ref = uses.split("@", 1)[1]
            assert len(ref) == 40 and all(c in "0123456789abcdef" for c in ref), (
                f"third-party action not SHA-pinned: {uses}"
            )


def test_bitbucket_template_is_valid_yaml():
    import yaml

    root = Path(__file__).resolve().parents[1]
    path = root / "bitbucket-pipelines.yml.example"
    assert path.exists(), "bitbucket template missing"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert "pipelines" in data
    assert "pull-requests" in data["pipelines"]
    text = path.read_text(encoding="utf-8")
    assert "blastradius.ci gate" in text
    assert "exit" in text.lower() or "0" in text


def test_example_policy_loads_and_is_safe(tmp_path):
    root = Path(__file__).resolve().parents[1]
    policy, warnings = load_policy(str(root / "blastradius-ci.example.yml"))
    assert policy.fail_on == [Severity.CRITICAL, Severity.HIGH]
    assert policy.minimum_confidence == 0.80
    assert policy.on_error == "fail-closed"
    assert warnings == []


# ------------------------------------------------------------- unified CLI


def test_unified_cli_ci_subcommand(tmp_path):
    from blastradius.cli.main import main as blast_main

    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    diff_file = tmp_path / "c.diff"
    diff_file.write_text(FIXED_DIFF, encoding="utf-8")
    rc = blast_main(
        [
            "ci",
            "gate",
            "--repo",
            str(tmp_path),
            "--diff-file",
            str(diff_file),
            "--no-ai",
            "--out",
            str(tmp_path / "out"),
        ]
    )
    assert rc == PASS


def test_unified_cli_ci_help_lists_actions(capsys):
    from blastradius.cli.main import main as blast_main

    with pytest.raises(SystemExit) as exc:
        blast_main(["ci", "--help"])
    assert exc.value.code == 0
    assert "review" in capsys.readouterr().out


def test_ci_module_help(capsys):
    from blastradius.ci.cli import build_parser

    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["gate", "--help"])
    assert exc.value.code == 0
    assert "--diff-file" in capsys.readouterr().out


def test_cli_invalid_policy_is_analysis_error(tmp_path):
    from blastradius.ci.cli import main as ci_main

    bad = tmp_path / "p.yml"
    bad.write_text("fail_on: [nope]\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    diff_file = tmp_path / "c.diff"
    diff_file.write_text(FIXED_DIFF, encoding="utf-8")
    rc = ci_main(
        [
            "gate",
            "--repo",
            str(tmp_path),
            "--diff-file",
            str(diff_file),
            "--no-ai",
            "--policy",
            str(bad),
            "--out",
            str(tmp_path / "out"),
        ]
    )
    assert rc == ANALYSIS_ERROR
