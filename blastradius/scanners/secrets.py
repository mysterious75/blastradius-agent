"""SecretScanner — detection-only API-key / credential exposure scanning.

Finds high-signal API keys and credentials committed to code (CWE-798:
Use of Hard-coded Credentials). Detection ONLY — never validates or uses a
found key; the responsible flow is report -> owner revokes.

The v2 engine is gitleaks-style:
  * a cheap keyword pre-filter (:data:`_KEYWORD_PRE`) runs before the full
    regex set, so plain code lines never hit the slower patterns;
  * placeholder-ish lines are skipped via a stopword allowlist
    (:data:`_STOPWORDS`);
  * generic free-form token patterns (sk-, ghp_, AKIA, xox, sk_live_) must
    clear a Shannon-entropy gate of >= 3.5 bits/char — a line of repeated
    characters is an example, not a credential. Highly structured token
    formats (``github_pat_*``, ``AIza*``) are exempt: their fixed prefix plus
    strict length is already precise;
  * any line containing ``blastradius:allow`` is skipped entirely (inline
    opt-out).
"""

import math
import re

from blastradius.scanners._util import make_finding, scan_lines

_PATTERNS = [
    r"\bAIza[0-9A-Za-z\-_]{35}\b",  # Google API key
    r"\bsk-[A-Za-z0-9]{20,}\b",  # OpenAI
    r"\bghp_[A-Za-z0-9]{36}\b",  # GitHub personal access token
    r"\bgithub_pat_[A-Za-z0-9_]{22,}\b",  # GitHub fine-grained PAT
    r"\bAKIA[0-9A-Z]{16}\b",  # AWS access key id
    r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b",  # Slack token
    r"\bsk_live_[A-Za-z0-9]{20,}\b",  # Stripe live key
]
# Fixed-prefix, strict-length token formats whose format alone is precise
# (github_pat_*, AIza*) — exempt from the entropy gate. Every other pattern is
# generic and must clear the entropy threshold before being reported.
_STRUCTURED_PATTERNS = frozenset(
    {
        r"\bAIza[0-9A-Za-z\-_]{35}\b",
        r"\bgithub_pat_[A-Za-z0-9_]{22,}\b",
    }
)
# Cheap keyword pre-filter: a line must mention a credential-ish keyword (or a
# token prefix) before the slower full regex set is consulted.
_KEYWORD_PRE = re.compile(
    r"key|token|secret|password|passwd|api|sk-|AKIA|ghp_|github_pat_|sk_live_|"
    r"xox[baprs]-|AIza|BEGIN|credential|auth",
    re.I,
)
# Placeholder-ish false-positive terms. Lines containing any of these are
# examples/docs/tests, not leaked credentials. Short single words are matched
# with word boundaries so a coincidental fragment inside a real token (e.g.
# "...QwErTy..." in a high-entropy sk- key) never suppresses a finding;
# hyphenated/undercase placeholder idioms keep raw substring matching.
_STOPWORDS = re.compile(
    r"\b(?:example|changeme|sample|demo|placeholder|redacted|dummy|fake|"
    r"replaceme|todo|lorem|ipsum|qwerty|foo|bar|baz|generated|synthetic|mock|"
    r"test|test-key|test_key|testkey|abc123|1234|123456|0000|000000|"
    r"example-key|sample-key|dummy-key|fake-key|fake_key)\b|"
    r"your-|your_|your-secret|your-key|my-secret|my-key|change-me|change_me|"
    r"changethis|place-holder|test-token|test_token|replace-me|replace_me|"
    r"to-do|not-a-real|notareal|put-your|enter-your|insert-your|"
    r"<[a-z_]+>|xxxx+|\[REDACTED\]",
    re.I,
)


def shannon_entropy(s: str) -> float:
    """Shannon entropy of a string, in bits per character (stdlib only).

    High entropy means the token's characters are drawn from a varied
    alphabet; all-repeated or sequential tokens (``aaaaaaaa...``) score ~0 and
    are treated as placeholders.
    """
    if not s:
        return 0.0
    n = len(s)
    counts: dict = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def fingerprint(path, line, rule, payload):
    """Deterministic identifier for a secret occurrence.

    ``payload`` is the commit sha when scanning git history (may be None for
    working-tree scans, in which case the path anchors the fingerprint).
    Returns ``{commit_sha_or_file}:{path}:{rule}:{line}`` — stable across
    runs, so it is safe to store in ignore files. Not wired to ignore files
    yet (documented for later use).
    """
    anchor = payload if payload is not None else str(path)
    return f"{anchor}:{path}:{rule}:{line}"


class SecretScanner:
    """Pattern-based hard-coded credential detection (gitleaks-style v2)."""

    name = "secret"

    def detect(self, code: str, path=None):
        def check(line, idx):
            if "blastradius:allow" in line:
                return None
            if not _KEYWORD_PRE.search(line):
                return None
            if _STOPWORDS.search(line):
                return None
            for pattern in _PATTERNS:
                m = re.search(pattern, line)
                if m is None:
                    continue
                if pattern not in _STRUCTURED_PATTERNS:
                    # generic free-form token — require real entropy
                    if shannon_entropy(m.group(0)) < 3.5:
                        continue
                return make_finding(
                    path,
                    idx,
                    "secret",
                    line.strip(),
                    0.95,
                    "HIGH",
                    "CWE-798",
                    "Hard-coded API key or credential exposed in source.",
                    "Rotate the credential and remove it from the repository; load "
                    "secrets from environment variables or a secret manager.",
                )
            return None

        return scan_lines(code, path, check)
