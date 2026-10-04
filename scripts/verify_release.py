"""Verify a released distribution's supply-chain artifacts (PEP 740 / SLSA).

Usage:
    python scripts/verify_release.py [--bundle FILE] [--sbom FILE] DIST...

Checks, in order:
  (a) every wheel's METADATA (or sdist's PKG-INFO) carries a license
      indicator — an SPDX ``License-Expression``, a ``License:`` field, or a
      ``License :: OSI Approved`` classifier;
  (b) a Sigstore bundle supplied via ``--bundle`` verifies against its
      artifact (keyless: identity + OIDC issuer read from the bundle cert);
  (c) an SBOM supplied via ``--sbom`` is a structurally valid CycloneDX
      document with root-component identity, valid component/purl entries,
      and no duplicates. ``--require-sbom-components`` additionally fails
      metadata-only documents.

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

#: CycloneDX JSON versions accepted by local verification. The repository
#: emits 1.5; newer release-tool SBOMs may use later 1.x documents.
ALLOWED_CYCLONEDX_SPEC_VERSIONS = {"1.5", "1.6", "1.7"}
ALLOWED_COMPONENT_TYPES = {
    "application",
    "framework",
    "library",
    "container",
    "platform",
    "operating-system",
    "device",
    "device-driver",
    "firmware",
    "file",
}


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


def validate_cyclonedx_sbom(sbom: Path, require_components: bool = False) -> dict:
    """Validate a CycloneDX SBOM document without network access.

    Checks the required ``bomFormat``/``specVersion`` envelope, root metadata
    component identity, component shape/purls, and duplicate components.
    Returns ``{"components": n, "root": bool}``. Fail-closed: malformed or
    incomplete documents raise ``ValueError``.
    """
    if not sbom.exists():
        raise ValueError(f"SBOM not found: {sbom}")
    try:
        data = json.loads(sbom.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ValueError(f"SBOM is not valid JSON: {sbom}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"SBOM must be a JSON object: {sbom}")
    if data.get("bomFormat") != "CycloneDX":
        raise ValueError(f"SBOM bomFormat must be 'CycloneDX': {sbom}")
    spec_version = str(data.get("specVersion", ""))
    if spec_version not in ALLOWED_CYCLONEDX_SPEC_VERSIONS:
        raise ValueError(
            f"unsupported CycloneDX specVersion {spec_version!r}: {sbom} "
            f"(expected one of {sorted(ALLOWED_CYCLONEDX_SPEC_VERSIONS)})"
        )

    metadata = data.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError(f"SBOM metadata must be an object: {sbom}")
    root = metadata.get("component")
    if not isinstance(root, dict):
        raise ValueError(f"SBOM metadata.component must be an object: {sbom}")
    for field in ("type", "name", "version"):
        if not root.get(field):
            raise ValueError(f"SBOM root component is missing {field}: {sbom}")

    components = data.get("components", [])
    if components is None:
        components = []
    if not isinstance(components, list):
        raise ValueError(f"SBOM components must be a list: {sbom}")
    seen = set()
    for index, component in enumerate(components):
        if not isinstance(component, dict):
            raise ValueError(f"SBOM component {index} must be an object: {sbom}")
        for field in ("type", "name", "version", "purl"):
            if not component.get(field):
                raise ValueError(f"SBOM component {index} is missing {field}: {sbom}")
        if component["type"] not in ALLOWED_COMPONENT_TYPES:
            raise ValueError(
                f"SBOM component {index} has unsupported type {component['type']!r}: {sbom}"
            )
        if not str(component["purl"]).startswith("pkg:"):
            raise ValueError(f"SBOM component {index} has an invalid purl: {sbom}")
        key = (str(component["name"]), str(component["version"]), str(component["purl"]))
        if key in seen:
            raise ValueError(f"duplicate SBOM component {key[0]}@{key[1]}: {sbom}")
        seen.add(key)

    count = len(components) + 1  # include the root application component
    if require_components and not components:
        raise ValueError(f"SBOM has no dependency components: {sbom}")
    print(f"SBOM components: {count}")
    return {"components": count, "root": True}


def sbom_component_count(sbom: Path) -> int:
    """Print and return the component count of a CycloneDX SBOM."""
    return validate_cyclonedx_sbom(sbom)["components"]


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
        help="CycloneDX SBOM (e.g. sbom.cdx.json) to validate and summarize",
    )
    parser.add_argument(
        "--require-sbom-components",
        action="store_true",
        help="fail when the SBOM has metadata only and no dependency components",
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
            validate_cyclonedx_sbom(
                Path(args.sbom), require_components=args.require_sbom_components
            )
        except (OSError, ValueError) as exc:
            failures.append(str(exc))

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
