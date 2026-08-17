"""Verify a released distribution's supply-chain artifacts (PEP 740 / SLSA).

Usage:
    python scripts/verify_release.py [--bundle FILE] [--sbom FILE] DIST...

Checks, in order:
  (a) every wheel's METADATA (or sdist's PKG-INFO) carries a license
      indicator — an SPDX ``License-Expression``, a ``License:`` field, or a
      ``License :: OSI Approved`` classifier;
  (b) a Sigstore bundle supplied via ``--bundle`` verifies against its
      artifact (keyless: identity + OIDC issuer read from the bundle cert);
  (c) an SBOM supplied via ``--sbom`` is parsed and its component count is
      printed.

Fail-closed: any failing check exits 1.
"""

import argparse
import json
import re
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

LICENSE_CLASSIFIER = re.compile(r"^Classifier:\s*License\s*::", re.MULTILINE)
LICENSE_EXPRESSION = re.compile(r"^License-Expression:\s*\S+", re.MULTILINE)
LICENSE_FIELD = re.compile(r"^License:\s*\S+", re.MULTILINE)


def metadata_texts(artifact: Path) -> list[str]:
    """Return the metadata texts embedded in a wheel or sdist."""
    texts: list[str] = []
    if artifact.name.endswith(".whl"):
        with zipfile.ZipFile(artifact) as zf:
            for name in zf.namelist():
                if name.endswith(".dist-info/METADATA"):
                    texts.append(zf.read(name).decode("utf-8", errors="replace"))
    elif artifact.name.endswith((".tar.gz", ".tgz")):
        with tarfile.open(artifact, "r:*") as tf:
            for member in tf.getmembers():
                if member.name.endswith("PKG-INFO") and member.isfile():
                    raw = tf.extractfile(member)
                    if raw is not None:
                        texts.append(raw.read().decode("utf-8", errors="replace"))
    else:
        raise ValueError(f"unsupported artifact {artifact.name} (expected .whl or .tar.gz)")
    if not texts:
        raise ValueError(f"no METADATA/PKG-INFO found in {artifact.name}")
    return texts


def has_license_indicator(text: str) -> bool:
    return bool(
        LICENSE_EXPRESSION.search(text)
        or LICENSE_CLASSIFIER.search(text)
        or LICENSE_FIELD.search(text)
    )


def verify_bundle(bundle: Path) -> None:
    """Verify a Sigstore bundle against its artifact via the sigstore CLI."""
    if not bundle.exists():
        raise ValueError(f"bundle not found: {bundle}")
    if not bundle.name.endswith(".sigstore"):
        raise ValueError(f"bundle must be a <artifact>.sigstore file: {bundle.name}")
    artifact = bundle.with_suffix("")
    if not artifact.exists():
        raise ValueError(f"cannot find signed artifact {artifact} for bundle {bundle.name}")

    # Read identity + OIDC issuer from the bundle's embedded certificate.
    identity, issuer = bundle_identity(bundle)
    if not identity or not issuer:
        raise ValueError(
            f"could not read identity/issuer from bundle {bundle.name} "
            f"(got identity={identity!r}, issuer={issuer!r})"
        )

    cmd = [
        sys.executable,
        "-m",
        "sigstore",
        "verify",
        "identity",
        "--cert-identity",
        identity,
        "--cert-oidc-issuer",
        issuer,
        "--bundle",
        str(bundle),
        str(artifact),
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"sigstore verify could not run: {exc}") from exc
    if result.returncode != 0:
        raise ValueError(
            f"sigstore verification failed for {bundle.name}: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )


def bundle_identity(bundle: Path) -> tuple[str | None, str | None]:
    """Extract (identity, issuer) from the bundle cert via `sigstore get-identity`."""
    cmd = [sys.executable, "-m", "sigstore", "get-identity", "--bundle", str(bundle)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"sigstore get-identity could not run: {exc}") from exc
    if result.returncode != 0:
        raise ValueError(
            f"sigstore get-identity failed: {result.stderr.strip() or result.stdout.strip()}"
        )
    identity: str | None = None
    issuer: str | None = None
    for line in result.stdout.splitlines():
        match = re.match(r"^(identity|issuer)\s*[:=]?\s*(\S.+)$", line.strip(), re.I)
        if not match:
            continue
        key, value = match.group(1).lower(), match.group(2).strip()
        if key == "identity" and identity is None:
            identity = value
        elif key == "issuer" and issuer is None:
            issuer = value
    return identity, issuer


def sbom_component_count(sbom: Path) -> int:
    """Print and return the component count of a CycloneDX SBOM."""
    if not sbom.exists():
        raise ValueError(f"SBOM not found: {sbom}")
    data = json.loads(sbom.read_text(encoding="utf-8"))
    count = len(data.get("components", []))
    if data.get("metadata", {}).get("component"):
        count += 1  # root component
    print(f"SBOM components: {count}")
    return count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "artifacts", nargs="+", metavar="DIST", help="built distribution(s) to check"
    )
    parser.add_argument(
        "--bundle",
        metavar="FILE",
        help="Sigstore bundle (<artifact>.sigstore) to verify",
    )
    parser.add_argument(
        "--sbom",
        metavar="FILE",
        help="CycloneDX SBOM (e.g. sbom.cdx.json) to summarize",
    )
    args = parser.parse_args(argv)

    failures: list[str] = []
    for artifact_arg in args.artifacts:
        artifact = Path(artifact_arg)
        try:
            for text in metadata_texts(artifact):
                if not has_license_indicator(text):
                    raise ValueError(f"{artifact.name} has no license metadata")
            print(f"OK  {artifact.name}: license metadata present")
        except (OSError, ValueError, zipfile.BadZipFile) as exc:
            failures.append(str(exc))

    if args.bundle:
        try:
            verify_bundle(Path(args.bundle))
            print(f"OK  sigstore bundle {Path(args.bundle).name} verified")
        except (OSError, ValueError) as exc:
            failures.append(str(exc))

    if args.sbom:
        try:
            sbom_component_count(Path(args.sbom))
        except (OSError, ValueError) as exc:
            failures.append(str(exc))

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
