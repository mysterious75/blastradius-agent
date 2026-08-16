"""Insecure deserialization — detection + sandbox PoC tests (offline, no mocks)."""

import shutil
import tempfile
from pathlib import Path

from blastradius.hunter.scanner import CVEHunter, reconstruct_target_code
from blastradius.sandbox.generator import generate_exploit
from blastradius.tools.sandbox_tool import run_exploit_sandbox

VULN_PICKLE = (
    "from flask import Flask, request\n"
    "import pickle\n"
    "app = Flask(__name__)\n"
    "@app.route('/data')\n"
    "def load():\n"
    "    data = request.args.get('data')\n"
    "    return pickle.loads(bytes.fromhex(data))\n"
)

SAFE_YAML = "import yaml\ndef load(data):\n    return yaml.safe_load(data)\n"

SAFE_RESTRICTED = (
    "import pickle\n"
    "class SafeUnpickler(pickle.Unpickler):\n"
    "    def find_class(self, module, name):\n"
    "        raise pickle.UnpicklingError('blocked')\n"
    "def load(data):\n"
    "    return SafeUnpickler(bytes(data)).load()\n"
)

PHP_UNSERIALIZE = "<?php\n$data = $_POST['data'];\n$obj = unserialize($data);\n"


def _scan(code: str, suffix: str = ".py"):
    tmp = Path(tempfile.mkdtemp(prefix="br-deser-"))
    try:
        (tmp / f"app{suffix}").write_text(code, encoding="utf-8")
        return CVEHunter().scan_repo(str(tmp))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_detects_pickle_loads():
    findings = _scan(VULN_PICKLE)
    assert any(f.vuln_type == "deserialization" for f in findings)
    finding = next(f for f in findings if f.vuln_type == "deserialization")
    assert finding.cwe == "CWE-502"
    assert finding.severity == "HIGH"


def test_detects_php_unserialize():
    findings = _scan(PHP_UNSERIALIZE, suffix=".php")
    assert any(f.vuln_type == "deserialization" for f in findings)


def test_skips_safe_loaders():
    assert _scan(SAFE_YAML) == []
    assert _scan(SAFE_RESTRICTED) == []


def test_sandbox_poc_confirms_pickle():
    target = reconstruct_target_code(
        next(f for f in _scan(VULN_PICKLE) if f.vuln_type == "deserialization")
    )
    result = run_exploit_sandbox("deserialization", target)
    assert result.startswith("CONFIRMED_EXPLOITABLE")
    assert "[VULNERABLE]" in result


def test_sandbox_poc_rejects_safe_loader():
    result = run_exploit_sandbox("deserialization", SAFE_YAML)
    assert result.startswith("NOT_EXPLOITABLE")


def test_generate_exploit_embeds_target():
    exploit = generate_exploit("deserialization", "def target(u):\n    return u\n")
    assert "TARGET_CODE = " in exploit
    assert "[VULNERABLE]" in exploit
