"""Intraprocedural taint traces — pure stdlib, offline, no mocks."""

import shutil
import tempfile
from pathlib import Path

from blastradius.hunter.scanner import CVEHunter
from blastradius.taint import trace_sink


def test_trace_source():
    lines = [
        "def f():",
        '    x = request.args.get("q")',
        "    os.system(x)",
    ]
    trace = trace_sink(lines, 2, "x")
    assert len(trace) == 2
    assert trace[0]["kind"] == "source"
    assert trace[0]["var"] == "x"
    assert trace[-1]["kind"] == "sink"
    assert trace[-1]["var"] == "x"
    assert trace[-1]["sanitized"] is False
    assert trace[0]["line"] == 2  # 1-based human line numbers
    assert trace[-1]["line"] == 3


def test_trace_chained():
    lines = [
        "def f():",
        '    x = request.args.get("q")',
        "    y = x",
        "    os.system(y)",
    ]
    trace = trace_sink(lines, 3, "y")
    assert len(trace) == 3
    assert [s["kind"] for s in trace] == ["source", "propagator", "sink"]
    assert trace[1]["var"] == "y"
    assert trace[1]["expr"] == "x"


def test_trace_no_origin():
    # a string-literal sink has no variable to trace
    lines = ["def f():", '    os.system("cls")']
    assert trace_sink(lines, 1, "") == []
    # a plain constant assignment is not a taint origin either
    lines2 = ["def f():", '    x = "cls"', "    os.system(x)"]
    assert trace_sink(lines2, 2, "x") == []


def test_sanitizer():
    lines = [
        "def f():",
        '    x = html.escape(request.args.get("q"))',
        "    return x",
    ]
    trace = trace_sink(lines, 2, "x")
    assert len(trace) == 2
    assert trace[-1]["sanitized"] is True
    # a plain source assignment stays unsanitized
    lines2 = [
        "def f():",
        '    x = request.args.get("q")',
        "    os.system(x)",
    ]
    assert trace_sink(lines2, 2, "x")[-1]["sanitized"] is False
    # var.replace() reassignment between origin and sink is also a sanitizer
    lines3 = [
        "def f():",
        '    x = request.args.get("q")',
        '    x = x.replace(";", "")',
        "    os.system(x)",
    ]
    trace3 = trace_sink(lines3, 3, "x")
    assert len(trace3) == 2
    assert trace3[-1]["sanitized"] is True


def test_finding_carries_code_flows():
    code = (
        "from flask import request\n"
        "import os\n"
        "def ping():\n"
        "    host = request.args.get('host')\n"
        "    os.system(host)\n"
    )
    tmp = Path(tempfile.mkdtemp(prefix="br-taint-"))
    try:
        (tmp / "app.py").write_text(code, encoding="utf-8")
        findings = CVEHunter().scan_repo(str(tmp))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    f = next((f for f in findings if f.vuln_type == "cmd_injection"), None)
    assert f is not None
    assert f.code_flows, "cmd_injection finding should carry a taint trace"
    assert f.code_flows[0]["kind"] == "source"
    assert f.code_flows[-1]["kind"] == "sink"
