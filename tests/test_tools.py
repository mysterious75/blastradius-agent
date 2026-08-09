"""Tests for the BlastRadius tool wrappers (self-contained scanners).

The wrappers run without cai-framework (plain callables) and without
prometheus — detection uses the built-in blastradius.scanners package.
"""

import json
from pathlib import Path

import pytest

from blastradius.tools import (
    prometheus_adversarial_validate,
    prometheus_sqli_scan,
    prometheus_ssrf_scan,
    prometheus_xss_scan,
)


@pytest.fixture
def vuln_repo(tmp_path):
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "name = request.args.get('name')\n"
        "query = \"SELECT * FROM users WHERE name = '\" + name + \"'\"\n",
        encoding="utf-8",
    )
    (tmp_path / "views.js").write_text(
        "const el = document.getElementById('out');\n"
        "el.innerHTML = userInput;\n",
        encoding="utf-8",
    )
    (tmp_path / "fetch.py").write_text(
        "import requests\n"
        "def load():\n"
        "    url = request.args.get('url')\n"
        "    return requests.get(url)\n",
        encoding="utf-8",
    )
    (tmp_path / "safe.py").write_text(
        "from flask import request\n"
        "name = request.args.get('name')\n"
        "cur.execute('SELECT * FROM users WHERE name = %s', (name,))\n",
        encoding="utf-8",
    )
    return tmp_path


def test_all_tools_are_callable():
    for tool in (
        prometheus_sqli_scan,
        prometheus_xss_scan,
        prometheus_ssrf_scan,
        prometheus_adversarial_validate,
    ):
        assert callable(tool)


def test_sqli_scan_finds_concat_injection(vuln_repo):
    result = prometheus_sqli_scan(str(vuln_repo))
    findings = json.loads(result)
    assert isinstance(findings, list)
    assert findings, "expected at least one SQLi finding"
    sqli = [f for f in findings if f["vuln_type"] == "SQL Injection"]
    assert sqli
    assert sqli[0]["payload"] and "SELECT" in sqli[0]["payload"]


def test_sqli_scan_ignores_parameterized(vuln_repo):
    result = prometheus_sqli_scan(str(vuln_repo))
    payloads = " ".join(f["payload"] for f in json.loads(result))
    assert "safe.py" not in payloads  # parameterized query not flagged


def test_xss_and_ssrf_scans(vuln_repo):
    xss = json.loads(prometheus_xss_scan(str(vuln_repo)))
    ssrf = json.loads(prometheus_ssrf_scan(str(vuln_repo)))
    assert any(f["vuln_type"] == "Cross-Site Scripting" for f in xss)
    assert any(f["vuln_type"] == "Server-Side Request Forgery" for f in ssrf)


def test_scan_empty_dir_returns_empty(tmp_path):
    assert json.loads(prometheus_sqli_scan(str(tmp_path))) == []


def test_scan_missing_path_returns_empty():
    assert json.loads(prometheus_sqli_scan(str(Path("/nonexistent/nowhere")))) == []


def test_invalid_params_json_is_rejected(vuln_repo):
    with pytest.raises(ValueError, match="not valid JSON"):
        prometheus_sqli_scan(str(vuln_repo), params_json="not-json")


def test_adversarial_validate_returns_verdict():
    finding = {
        "vuln_type": "SQL Injection",
        "title": "Error-based SQLi in parameter 'id'",
        "severity": "CRITICAL",
        "url": "http://localhost/page?id=1",
        "parameter": "id",
        "method": "GET",
        "payload": "' OR 1=1--",
        "evidence": "SQL error from MySQL detected in response for parameter 'id'.",
        "remediation": "Use parameterized queries",
        "cvss": 9.8,
        "cwe": "CWE-89",
        "verified": True,
        "confidence": "HIGH",
    }
    result = prometheus_adversarial_validate(json.dumps(finding))
    results = json.loads(result)
    assert len(results) == 1
    assert results[0]["verdict"] in {
        "confirmed",
        "likely_false_positive",
        "false_positive",
        "needs_manual_review",
    }
    assert results[0]["vuln_type"] == finding["vuln_type"]


def test_adversarial_validate_fallback_without_prometheus(monkeypatch):
    """When prometheus cannot be imported, a local heuristic verdict is used."""
    def boom():
        raise ImportError("no prometheus")

    monkeypatch.setattr("blastradius.prometheus_bootstrap.ensure_prometheus_importable", boom)
    result = prometheus_adversarial_validate(json.dumps({
        "vuln_type": "SQL Injection", "url": "file://x.py",
        "evidence": "SELECT * FROM users", "confidence": 0.9,
    }))
    results = json.loads(result)
    assert results[0]["verdict"] == "needs_manual_review"
    # _local_verdict must propagate dict fields (was getattr-on-dict bug)
    assert results[0]["vuln_type"] == "SQL Injection"
    assert results[0]["url"] == "file://x.py"
    assert results[0]["evidence_strength"] == "moderate"


def test_adversarial_validate_batch_and_bad_input():
    empty = prometheus_adversarial_validate("[]")
    assert json.loads(empty) == []
    with pytest.raises(ValueError, match="not valid JSON"):
        prometheus_adversarial_validate("not-json")
    with pytest.raises(ValueError, match="JSON object or a list"):
        prometheus_adversarial_validate('"just a string"')
