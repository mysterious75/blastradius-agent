"""Release supply-chain tests — release workflow config, ci.yml publish-job
stability, and scripts/verify_release.py behavior. Offline, no Docker."""

import subprocess
import sys
import zipfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_release_workflow_valid_yaml():
    path = ROOT / ".github" / "workflows" / "release.yml"
    assert path.exists(), "release.yml missing"

    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert data["name"] == "Release"
    triggers = data.get("on") or data.get(True)  # pyyaml YAML 1.1: `on` -> True
    assert triggers["push"]["tags"] == ["v*"]

    text = path.read_text(encoding="utf-8")
    assert "attest-build-provenance" in text
    assert "id-token: write" in text
    assert "PYPI_API_TOKEN" not in text


def test_ci_publish_unchanged():
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    # The legacy publish job must stay untouched so tests/test_release.py stays
    # green — the OIDC trusted-publishing path lives in release.yml instead.
    assert "publish:" in text
    assert "pypa/gh-action-pypi-publish@release/v1" in text
    assert "PYPI_API_TOKEN" in text


def _make_wheel(path: Path, metadata: str) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("demo-1.0.0.dist-info/METADATA", metadata)
        zf.writestr("demo/__init__.py", "")


def test_verify_release_wheel(tmp_path):
    ok = tmp_path / "demo-1.0.0-py3-none-any.whl"
    _make_wheel(ok, "Name: demo\nVersion: 1.0.0\nLicense-Expression: MIT\n")
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "verify_release.py"), str(ok)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    classifier = tmp_path / "demo_classifier-1.0.0-py3-none-any.whl"
    _make_wheel(
        classifier,
        "Name: demo\nVersion: 1.0.0\nClassifier: License :: OSI Approved :: MIT License\n",
    )
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "verify_release.py"), str(classifier)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    bad = tmp_path / "demo_bad-1.0.0-py3-none-any.whl"
    _make_wheel(bad, "Name: demo\nVersion: 1.0.0\n")
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "verify_release.py"), str(bad)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "license" in (result.stdout + result.stderr).lower()
