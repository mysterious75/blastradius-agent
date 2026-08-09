"""BlastRadiusGraph — dependency blast-radius mapping (Neo4j + in-memory).

Package -> Repo graph. Uses Neo4j (bolt://localhost:7687) when the driver is
available and reachable, otherwise an in-memory dict backend — the fallback
keeps everything functional and testable without a database.

Dependency parsing supports requirements.txt, package.json, go.mod, and
Pipfile, returning (name, version) pairs.
"""

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "")


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------


class MemoryBackend:
    """In-memory package -> repo graph (dict-based)."""

    def __init__(self):
        self.packages: Dict[str, Dict] = {}
        self.repos: Dict[str, str] = {}
        self.links: Dict[str, Set[str]] = {}

    def add_package(self, name: str, version: str, vulnerable: bool = False):
        pkg = self.packages.setdefault(name, {"version": version, "vulnerable": False})
        pkg["version"] = version
        pkg["vulnerable"] = pkg["vulnerable"] or bool(vulnerable)

    def add_repo(self, name: str, url: str):
        self.repos[name] = url

    def link_package_to_repo(self, package: str, repo: str):
        self.add_package(package, self.packages.get(package, {}).get("version", ""))
        self.add_repo(repo, self.repos.get(repo, ""))
        self.links.setdefault(package, set()).add(repo)

    def query_blast_radius(self, package: str) -> List[str]:
        return sorted(self.links.get(package, set()))


class Neo4jBackend:
    """Neo4j-backed graph (Package)-[:USED_IN]->(Repo)."""

    def __init__(self, uri: Optional[str] = None, user: Optional[str] = None, password: Optional[str] = None):
        from neo4j import GraphDatabase

        self.driver = GraphDatabase.driver(
            uri or NEO4J_URI,
            auth=(user or NEO4J_USER, password or NEO4J_PASSWORD),
        )
        # Fail fast if the database is unreachable
        self.driver.verify_connectivity()

    def add_package(self, name: str, version: str, vulnerable: bool = False):
        with self.driver.session() as session:
            session.run(
                "MERGE (p:Package {name: $name}) "
                "SET p.version = $version, p.vulnerable = $vulnerable",
                name=name, version=version, vulnerable=bool(vulnerable),
            )

    def add_repo(self, name: str, url: str):
        with self.driver.session() as session:
            session.run(
                "MERGE (r:Repo {name: $name}) SET r.url = $url",
                name=name, url=url,
            )

    def link_package_to_repo(self, package: str, repo: str):
        with self.driver.session() as session:
            session.run(
                "MERGE (p:Package {name: $package}) "
                "MERGE (r:Repo {name: $repo}) "
                "MERGE (p)-[:USED_IN]->(r)",
                package=package, repo=repo,
            )

    def query_blast_radius(self, package: str) -> List[str]:
        with self.driver.session() as session:
            result = session.run(
                "MATCH (p:Package {name: $name})-[:USED_IN]->(r:Repo) RETURN r.name",
                name=package,
            )
            return sorted(record["r.name"] for record in result)

    def close(self):
        self.driver.close()


# ---------------------------------------------------------------------------
# Graph facade
# ---------------------------------------------------------------------------


class BlastRadiusGraph:
    """Package -> repo blast-radius graph with automatic backend selection."""

    def __init__(self, backend: Optional[str] = None):
        """``backend``: "memory" | "neo4j" | None (auto: neo4j, fallback memory)."""
        if backend == "memory":
            self.backend = MemoryBackend()
        elif backend == "neo4j":
            self.backend = Neo4jBackend()
        else:
            try:
                self.backend = Neo4jBackend()
            except Exception:
                self.backend = MemoryBackend()

    def add_package(self, name: str, version: str, vulnerable: bool = False):
        self.backend.add_package(name, version, vulnerable)

    def add_repo(self, name: str, url: str):
        self.backend.add_repo(name, url)

    def link_package_to_repo(self, package: str, repo: str):
        self.backend.link_package_to_repo(package, repo)

    def query_blast_radius(self, package_name: str) -> List[str]:
        """List of repo names affected by ``package_name``."""
        return self.backend.query_blast_radius(package_name)


# ---------------------------------------------------------------------------
# Dependency parsing
# ---------------------------------------------------------------------------

_REQ_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+?)\s*(?:==|>=|<=|~=|>|<|!=|===)\s*([^\s;]+)")
_GOMOD_REQ_RE = re.compile(r"^([A-Za-z0-9_.\-/]+)\s+(v?\d[\w.\-+]*)$")


def _clean_version(version: str) -> str:
    return version.lstrip("=<>~!^ ").strip()


def _parse_requirements(path: Path) -> List[Tuple[str, str]]:
    deps = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "\\")):
            continue
        m = _REQ_RE.match(line)
        if m:
            deps.append((m.group(1).split("[")[0], _clean_version(m.group(2))))
        else:
            name = line.split("[")[0].strip()
            if name:
                deps.append((name, ""))
    return deps


def _parse_package_json(path: Path) -> List[Tuple[str, str]]:
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    deps = []
    for section in ("dependencies", "devDependencies"):
        for name, version in (data.get(section) or {}).items():
            deps.append((name, _clean_version(version)))
    return deps


def _parse_go_mod(path: Path) -> List[Tuple[str, str]]:
    deps = []
    in_require = False
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if s.startswith("require") and "(" not in s:
            m = _GOMOD_REQ_RE.match(s[len("require"):].strip())
            if m:
                deps.append((m.group(1).split("/")[-1], _clean_version(m.group(2).lstrip("v"))))
            continue
        if s == "require (":
            in_require = True
            continue
        if in_require and s == ")":
            in_require = False
            continue
        if in_require:
            m = _GOMOD_REQ_RE.match(s)
            if m:
                deps.append((m.group(1).split("/")[-1], _clean_version(m.group(2).lstrip("v"))))
    return deps


def _parse_pipfile(path: Path) -> List[Tuple[str, str]]:
    deps = []
    section = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            section = s.strip("[]").lower()
            continue
        if section != "packages" or not s or s.startswith("#") or "=" not in s:
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*=\s*[\"']([^\"']*)[\"']", s)
        if m:
            deps.append((m.group(1), _clean_version(m.group(2))))
    return deps


def parse_dependencies(repo_path: str) -> List[Tuple[str, str]]:
    """Parse dependency manifests in ``repo_path`` into (name, version) pairs.

    Reads requirements.txt, package.json, go.mod, and Pipfile; results are
    deduplicated (first occurrence wins).
    """
    root = Path(repo_path)
    deps: List[Tuple[str, str]] = []
    for filename, parser in (
        ("requirements.txt", _parse_requirements),
        ("package.json", _parse_package_json),
        ("go.mod", _parse_go_mod),
        ("Pipfile", _parse_pipfile),
    ):
        path = root / filename
        if path.is_file():
            deps.extend(parser(path))
    return list(dict.fromkeys(deps))
