"""CVE hunter tests — no network, no Docker, no CAI required."""

import subprocess
from pathlib import Path

import pytest

from blastradius.hunter.cli import main as cli_main
from blastradius.hunter.disclosure import DisclosureReport
from blastradius.hunter.scanner import CVEHunter, reconstruct_target_code
from blastradius.hunter.targets import DEFAULT_TARGETS
from blastradius.tools.sandbox_tool import run_exploit_sandbox

ALLOWED_VERDICTS = {
    "confirmed",
    "likely_false_positive",
    "false_positive",
    "needs_manual_review",
}

VULN_APP_PY = '''\
from flask import request

def search():
    name = request.args.get("name")
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return db.execute(query)
'''

SAFE_APP_PY = '''\
from flask import request

def search():
    name = request.args.get("name")
    query = "SELECT * FROM users WHERE name = %s"
    return db.execute(query, (name,))
'''

VULN_PAGE_PHP = '''\
<?php
$name = $_GET['name'];
echo "<h1>Hello " . $name . "</h1>";
?>
'''

VULN_JS = '''\
const params = new URLSearchParams(window.location.search);
const q = params.get("q");
document.getElementById("out").innerHTML = q;
'''

VULN_SSRF_PY = '''\
import requests
from flask import request

def fetch():
    url = request.args.get("url")
    return requests.get(url).text
'''


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "vulnerable_app.py").write_text(VULN_APP_PY)
    (tmp_path / "safe_app.py").write_text(SAFE_APP_PY)
    (tmp_path / "page.php").write_text(VULN_PAGE_PHP)
    (tmp_path / "x.js").write_text(VULN_JS)
    (tmp_path / "ssrf.py").write_text(VULN_SSRF_PY)
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "fake.py").write_text("query = 'SELECT 1' + x\n")
    return tmp_path


def _finding(hunter, repo, vuln_type):
    for f in hunter.scan_repo(str(repo)):
        if f.vuln_type == vuln_type:
            return f
    raise AssertionError(f"no {vuln_type} finding found")


# --- targets ---------------------------------------------------------------


def test_default_targets():
    assert DEFAULT_TARGETS == [
        "https://github.com/WebGoat/WebGoat",
        "https://github.com/digininja/DVWA",
        "https://github.com/juice-shop/juice-shop",
    ]


# --- clone_repo (git mocked) ------------------------------------------------


def test_clone_repo_mocks_git(tmp_path, monkeypatch):
    hunter = CVEHunter()

    def fake_clone(cmd, **kwargs):
        assert cmd[0] == "git"
        assert cmd[1:4] == ["clone", "--depth", "1"]
        assert cmd[-2].startswith("https://github.com/")
        dest = Path(cmd[-1])
        dest.mkdir(parents=True)
        (dest / "README.md").write_text("fake clone")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("blastradius.hunter.scanner.subprocess.run", fake_clone)
    repo_path = hunter.clone_repo("https://github.com/WebGoat/WebGoat")

    assert Path(repo_path).is_dir()
    assert (Path(repo_path) / "README.md").exists()


def test_clone_repo_rejects_non_github_url():
    with pytest.raises(ValueError, match="Not a GitHub repo URL"):
        CVEHunter().clone_repo("https://example.com/foo/bar")


def test_clone_repo_failure_cleans_up(tmp_path, monkeypatch):
    def failing_clone(cmd, **kwargs):
        raise subprocess.CalledProcessError(128, cmd, stderr="repository not found")

    monkeypatch.setattr("blastradius.hunter.scanner.subprocess.run", failing_clone)
    with pytest.raises(RuntimeError, match="git clone failed"):
        CVEHunter().clone_repo("https://github.com/WebGoat/WebGoat")


# --- scan_repo (local files) ------------------------------------------------


def test_scan_finds_all_three_vuln_types(repo):
    hunter = CVEHunter()
    findings = hunter.scan_repo(str(repo))
    assert {f.vuln_type for f in findings} == {"sqli", "xss", "ssrf"}
    for f in findings:
        assert f.confidence >= 0.7


def _types(hunter, path):
    return {f.vuln_type for f in hunter.scan_repo(str(path))}


def test_go_echo_lines_not_flagged_as_xss(tmp_path):
    (tmp_path / "run.go").write_text(
        'if IFS= read -r -t 5 leaked; then echo "STDIN_LEAK:[$leaked]"; fi\n'
        'echo \'executed=$(echo "yes")\' >> $GITLAB_ENV\n',
        encoding="utf-8",
    )
    assert "xss" not in _types(CVEHunter(), tmp_path)


def test_python_print_not_flagged_as_xss(tmp_path):
    (tmp_path / "app.py").write_text("print(user_input)\n", encoding="utf-8")
    assert "xss" not in _types(CVEHunter(), tmp_path)


def test_php_echo_still_flagged_as_xss(tmp_path):
    (tmp_path / "page.php").write_text(
        '<?php echo "<h1>Hello " . $_GET["name"] . "</h1>"; ?>\n', encoding="utf-8"
    )
    assert "xss" in _types(CVEHunter(), tmp_path)


def test_test_files_and_dirs_skipped(tmp_path):
    # *_test.go with a real sink, and a tests/ dir with a real sink — both skipped
    (tmp_path / "client_test.go").write_text(
        'el.innerHTML = req.body["q"]\n', encoding="utf-8"
    )
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "app.py").write_text(
        "name = request.args.get('name')\n"
        "query = \"SELECT * FROM users WHERE name = '\" + name + \"'\"\n",
        encoding="utf-8",
    )
    assert _types(CVEHunter(), tmp_path) == set()


# --- client-side / config fetches are not SSRF --------------------------------


def test_client_side_fetch_not_flagged_as_ssrf(tmp_path):
    (tmp_path / "x.js").write_text(
        "const { data } = await axios.get(generateUrl('/apps/files/' + id))\n"
        "const res = await window.fetch('/api/' + q)\n",
        encoding="utf-8",
    )
    assert "ssrf" not in _types(CVEHunter(), tmp_path)


def test_server_side_axios_url_still_flagged(tmp_path):
    (tmp_path / "proxy.js").write_text(
        "const url = req.query.url;\naxios.get(url)\n", encoding="utf-8"
    )
    assert "ssrf" in _types(CVEHunter(), tmp_path)


def test_webhook_response_url_not_flagged(tmp_path):
    (tmp_path / "provider.rb").write_text(
        "resp = http.request(Net::HTTP::Post.new(URI(response_url)))\n",
        encoding="utf-8",
    )
    assert "ssrf" not in _types(CVEHunter(), tmp_path)


# --- Ruby params[ is a source, not a sink ------------------------------------


def test_ruby_params_alone_not_flagged(tmp_path):
    (tmp_path / "c.rb").write_text(
        "def show\n  params[:name]\nend\n", encoding="utf-8"
    )
    assert "xss" not in _types(CVEHunter(), tmp_path)


def test_ruby_raw_params_still_flagged(tmp_path):
    (tmp_path / "d.rb").write_text(
        "def show\n  raw(params[:name])\nend\n", encoding="utf-8"
    )
    assert "xss" in _types(CVEHunter(), tmp_path)


def test_sqli_finding_has_file_line_and_payload(repo):
    hunter = CVEHunter()
    sqli = _finding(hunter, repo, "sqli")
    assert sqli.file.endswith("vulnerable_app.py")
    assert sqli.line == 5  # the query=... concatenation line
    assert "SELECT * FROM users" in sqli.payload
    assert "name" in sqli.payload
    assert sqli.severity == "CRITICAL"
    assert sqli.cwe == "CWE-89"


def test_safe_and_git_files_are_ignored(repo):
    hunter = CVEHunter()
    findings = hunter.scan_repo(str(repo))
    assert not any("safe_app.py" in f.file for f in findings)
    assert not any(".git" in f.file for f in findings)


def test_confidence_filter_keeps_only_strong_signals(repo):
    hunter = CVEHunter(min_confidence=0.95)
    findings = hunter.scan_repo(str(repo))
    for f in findings:
        assert f.confidence >= 0.95
    # sqli/xss with file-level source score 1.0/0.95; ssrf scores 0.9 -> dropped
    assert "ssrf" not in {f.vuln_type for f in findings}


def test_validate_returns_allowed_verdict(repo):
    hunter = CVEHunter()
    for finding in hunter.scan_repo(str(repo)):
        assert hunter.validate(finding) in ALLOWED_VERDICTS


def test_reconstruct_target_code_confirms_in_sandbox(repo):
    hunter = CVEHunter()
    sqli = _finding(hunter, repo, "sqli")
    result = run_exploit_sandbox("sqli", reconstruct_target_code(sqli))
    assert result.startswith("CONFIRMED_EXPLOITABLE")


# --- DisclosureReport -------------------------------------------------------


def test_report_generation_contains_required_sections(repo):
    hunter = CVEHunter()
    sqli = _finding(hunter, repo, "sqli")
    report = DisclosureReport().generate_report(
        sqli, repo_name="myrepo", sandbox_result="CONFIRMED_EXPLOITABLE\n[VULNERABLE]"
    )
    assert "# Vulnerability Disclosure: SQLI in myrepo" in report
    assert "## Vulnerability description" in report
    assert sqli.file in report and "line 5" in report
    assert "## Proof of Concept" in report
    assert "## Sandbox validation" in report
    assert "CONFIRMED_EXPLOITABLE" in report
    assert "## Suggested patch" in report
    assert "CVSS estimate" in report and "9.8" in report


def test_save_report_writes_markdown_file(repo, tmp_path):
    hunter = CVEHunter()
    sqli = _finding(hunter, repo, "sqli")
    reports_dir = tmp_path / "reports"
    path = DisclosureReport().save_report(
        sqli, repo_name="myrepo", reports_dir=str(reports_dir),
        sandbox_result="CONFIRMED_EXPLOITABLE\n[VULNERABLE]",
    )
    import re as _re

    assert _re.fullmatch(r"\d{4}-\d{2}-\d{2}_sqli_myrepo_vulnerable_app-5\.md", path.name)
    assert path.suffix == ".md"
    assert path.exists()
    content = path.read_text(encoding="utf-8")
    assert "# Vulnerability Disclosure: SQLI in myrepo" in content
    assert "## Suggested patch" in content


# --- CLI --------------------------------------------------------------------


def test_cli_local_target_saves_reports(repo, tmp_path, capsys):
    reports_dir = tmp_path / "reports"
    rc = cli_main(["--target", str(repo), "--reports-dir", str(reports_dir)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "candidate finding(s)" in out
    reports = list(reports_dir.glob("*.md"))
    assert reports, "expected at least one report for confirmed-exploitable findings"
    assert any("sqli" in r.name for r in reports)
