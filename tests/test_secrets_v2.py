"""v2 secret-engine tests — entropy gating, keyword pre-filter, stopwords,
inline allow, fingerprint stability, and the pre-commit hook. Offline."""

import subprocess
import sys
from pathlib import Path

from blastradius.scan_secrets_hook import main as hook_main
from blastradius.scanners.secrets import SecretScanner, fingerprint, shannon_entropy

LOW_ENTROPY = "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
HIGH_ENTROPY = "sk-8fK2jLm9QwErTyUiOpAsDfGhJkLzXcVbN"
ROOT = Path(__file__).resolve().parent.parent


def test_entropy_rejects_low_entropy():
    scanner = SecretScanner()
    # 36 repeated 'a' — below the 3.5 bits/char gate -> not flagged
    assert scanner.detect(f'key = "{LOW_ENTROPY}"\n') == []
    # mixed-case + digits token — high entropy -> flagged at 0.95
    hits = scanner.detect(f'key = "{HIGH_ENTROPY}"\n')
    assert len(hits) == 1
    assert hits[0].confidence == 0.95


def test_entropy_unit():
    assert shannon_entropy("aaaaaaaaaa") < 3.5
    assert shannon_entropy(HIGH_ENTROPY.lstrip("sk-")) >= 3.5
    assert shannon_entropy("") == 0.0


def test_keyword_pre_and_stopwords():
    scanner = SecretScanner()
    # placeholder-ish lines are skipped by the stopword allowlist
    assert scanner.detect('api_key = "sk-placeholder-abc"\n') == []
    assert scanner.detect('key = "sk-example-xyz"\n') == []
    assert scanner.detect('key = "sk-your-secret-here"\n') == []
    assert scanner.detect('key = "sk-XXXXXX-XXXXXX-XXXXXX"\n') == []
    # no credential keyword on the line -> keyword pre-filter short-circuits
    assert scanner.detect('g = "8fK2jLm9QwErTyUiOpAsDfGhJkLzXcVbN"\n') == []


def test_inline_allow():
    scanner = SecretScanner()
    line = f'key = "{HIGH_ENTROPY}"  # blastradius:allow\n'
    assert scanner.detect(line) == []


def test_fingerprint_stable():
    a = fingerprint("src/app.py", 12, "secret", "abc123")
    b = fingerprint("src/app.py", 12, "secret", "abc123")
    c = fingerprint("src/app.py", 12, "secret", "abc123")
    assert a == b == c
    assert a == "abc123:src/app.py:secret:12"
    # commit sha may be None (working-tree scan) — still deterministic
    d = fingerprint("src/app.py", 12, "secret", None)
    e = fingerprint("src/app.py", 12, "secret", None)
    assert d == e
    assert d != a


def test_hook_exits_nonzero(tmp_path):
    leak = tmp_path / "leak.py"
    leak.write_text(f'API_KEY = "{HIGH_ENTROPY}"\n', encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "blastradius.scan_secrets_hook", str(leak)],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    assert proc.returncode == 1
    assert "secret" in proc.stdout.lower()


def test_hook_exits_zero_for_clean_and_allow(tmp_path):
    clean = tmp_path / "clean.py"
    clean.write_text('API_KEY = os.environ["API_KEY"]\n', encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "blastradius.scan_secrets_hook", str(clean)],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    assert proc.returncode == 0
    # a real-looking secret suppressed by the inline allow marker
    allowed = tmp_path / "allowed.py"
    allowed.write_text(f'API_KEY = "{HIGH_ENTROPY}"  # blastradius:allow\n', encoding="utf-8")
    assert hook_main(["hook", str(allowed)]) == 0
