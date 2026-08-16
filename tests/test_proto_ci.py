"""Proto pollution + GitHub Actions CI injection scanners — detection tests and a
benchmark-corpus smoke test. No network, no Docker, no CAI."""

from pathlib import Path

from blastradius.hunter.scanner import CVEHunter
from blastradius.scanners import get_scanner
from blastradius.scanners.proto_pollution import ProtoPollutionScanner

VULN_PROTO = """\
const express = require('express');
const _ = require('lodash');
const app = express();

app.post('/merge', (req, res) => {
  const options = {};
  _.merge(options, req.body);
  res.json({ ok: true });
});
"""

VULN_PROTO_PROTO = """\
const payload = JSON.parse(req.body.payload);
if (payload["__proto__"]) {
  payload["__proto__"].admin = true;
}
"""

SAFE_PROTO = """\
const _ = require('lodash');
app.post('/merge', (req, res) => {
  const options = {};
  if (!Object.prototype.hasOwnProperty.call(req.body, '__proto__')) {
    _.merge(Object.freeze(options), structuredClone(req.body));
  }
  res.json({ ok: true });
});
"""

VULN_CI = """\
name: CI
on:
  pull_request_target:

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: node script.js ${{ github.event.pull_request.head.sha }}
"""

SAFE_CI = """\
name: CI
on:
  pull_request:

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
"""


def _write(tmp_path, name, content):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _types(hunter, tmp_path):
    return {f.vuln_type for f in hunter.scan_repo(str(tmp_path))}


# --- prototype pollution ------------------------------------------------------


def test_proto_pollution_merge_sink_detected():
    findings = ProtoPollutionScanner().detect(VULN_PROTO)
    assert [f.vuln_type for f in findings] == ["proto_pollution"]
    assert findings[0].confidence >= 0.8
    assert findings[0].cwe == "CWE-1321"


def test_proto_pollution_proto_key_detected():
    findings = ProtoPollutionScanner().detect(VULN_PROTO_PROTO)
    assert any(f.vuln_type == "proto_pollution" for f in findings)
    assert all(f.confidence >= 0.8 for f in findings)


def test_proto_pollution_safe_not_flagged():
    assert ProtoPollutionScanner().detect(SAFE_PROTO) == []


def test_proto_pollution_registered():
    scanner = get_scanner("proto_pollution")
    assert scanner is not None
    assert scanner.name == "proto_pollution"


def test_proto_pollution_hunter_detects_in_js(tmp_path):
    _write(tmp_path, "app.js", VULN_PROTO)
    findings = CVEHunter().scan_repo(str(tmp_path))
    assert "proto_pollution" in _types(CVEHunter(), tmp_path)
    proto = [f for f in findings if f.vuln_type == "proto_pollution"]
    assert len(proto) == 1
    assert proto[0].confidence >= 0.8


def test_proto_pollution_hunter_not_in_python(tmp_path):
    # proto sinks are JS-only in the hunter
    _write(
        tmp_path,
        "app.py",
        "payload = {}\npayload['__proto__']['polluted'] = True\n_.merge(options, req.body)\n",
    )
    assert "proto_pollution" not in _types(CVEHunter(), tmp_path)


# --- CI injection --------------------------------------------------------------


def test_ci_injection_detected(tmp_path):
    _write(tmp_path, ".github/workflows/ci.yml", VULN_CI)
    findings = CVEHunter().scan_repo(str(tmp_path))
    ci = [f for f in findings if f.vuln_type == "ci_injection"]
    assert len(ci) == 1
    assert ci[0].confidence == 0.85
    assert ci[0].line == 1
    assert ci[0].cwe == "CWE-94"


def test_ci_injection_safe_without_pull_request_target(tmp_path):
    _write(tmp_path, ".github/workflows/ci.yml", SAFE_CI)
    assert "ci_injection" not in _types(CVEHunter(), tmp_path)


def test_ci_injection_no_checkout_not_flagged(tmp_path):
    _write(
        tmp_path,
        ".github/workflows/ci.yml",
        VULN_CI.replace("      - uses: actions/checkout@v4\n", ""),
    )
    assert "ci_injection" not in _types(CVEHunter(), tmp_path)


def test_ci_injection_no_run_no_head_sha_not_flagged(tmp_path):
    # pull_request_target + checkout, but nothing executes PR code
    _write(
        tmp_path,
        ".github/workflows/ci.yml",
        VULN_CI.replace(
            "      - run: node script.js ${{ github.event.pull_request.head.sha }}\n", ""
        ),
    )
    assert "ci_injection" not in _types(CVEHunter(), tmp_path)


def test_ci_injection_yaml_not_under_github_not_flagged(tmp_path):
    # only .github workflow yaml files are checked
    _write(tmp_path, "config.yml", VULN_CI)
    assert "ci_injection" not in _types(CVEHunter(), tmp_path)


# --- benchmark corpus smoke ---------------------------------------------------


def test_benchmark_corpus_smoke():
    corpus = Path(__file__).resolve().parent.parent / "benchmarks" / "corpus"
    hunter = CVEHunter()

    proto = hunter.scan_repo(str(corpus / "flask-proto-pollution"))
    assert [f.vuln_type for f in proto] == ["proto_pollution"]
    assert Path(proto[0].file).name == "app.js"

    ci = hunter.scan_repo(str(corpus / "ci-supply-chain"))
    assert [f.vuln_type for f in ci] == ["ci_injection"]
    assert Path(ci[0].file).name == "ci.yml"
