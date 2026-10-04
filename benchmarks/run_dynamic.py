"""Dynamic (live-target) benchmark for BlastRadius web checks.

Spins up each corpus target (stdlib HTTP servers on 127.0.0.1 ephemeral
ports), runs the matching live check, and scores hits against the target's
ground-truth manifest — the same precision / recall / F1 contract as
``benchmarks/run.py``, but for runtime behavior instead of source patterns.

Fully offline and deterministic: every server and every OOB listener is
localhost; no external network, no LLM, no Docker.

Usage:
    python benchmarks/run_dynamic.py
    python benchmarks/run_dynamic.py --min-f1 0.5   # CI gate: exit 1 below F1
"""

import argparse
import http.server
import importlib.util
import json
import sys
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
_REPO_ROOT = ROOT.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _load_server(target_dir: Path):
    server_py = target_dir / "server.py"
    if not server_py.is_file():
        # Targets that boot their own fixtures in the runner (e.g. the
        # multi-service live-netservices target) need no generic HTTP server.
        import http.server as _http

        class _Dummy(_http.BaseHTTPRequestHandler):
            def do_GET(self):  # pragma: no cover - never actually served
                self.send_response(404)
                self.end_headers()

            def log_message(self, *args):
                pass

        return _Dummy
    spec = importlib.util.spec_from_file_location(f"bench_{target_dir.name}", str(server_py))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Handler


def _serve(handler_cls):
    server = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _matches(finding, expected: dict) -> bool:
    """A finding hits when check type matches and the URL path ends with the suffix."""
    check = getattr(finding, "check", "")
    url = getattr(finding, "url", "").split("?")[0]
    return check == expected["check"] and url.endswith(expected.get("url_suffix", ""))


def run_idor_target(base: str, manifest: dict, target_dir=None):
    from blastradius.web.authz import AuthzDiffChecker
    from blastradius.web.browser import BrowserSession

    attacker = BrowserSession(default_headers={"X-Identity": "A"})
    victim = BrowserSession(default_headers={"X-Identity": "B"})
    checker = AuthzDiffChecker(
        attacker=attacker, victim=victim, victim_markers=manifest.get("victim_markers", [])
    )
    urls = [base + p for p in manifest.get("probe_urls", [])]
    return checker.check(urls)


def run_jwt_target(base: str, manifest: dict, target_dir=None):
    import base64

    from blastradius.web.browser import BrowserSession
    from blastradius.web.jwt import JwtChecker

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    session = BrowserSession()
    findings = []
    # A signed decoy token (payload never matters for the alg:none probe).
    header = b64(b'{"alg":"HS256","typ":"JWT"}')
    payload = b64(b'{"sub":"1","exp":9999999999}')
    decoy = f"{header}.{payload}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    for path in manifest.get("probe_paths", []):
        url = base + path

        def send(token, _url=url):
            body = urllib.parse.urlencode({"token": token}).encode()
            try:
                page = session._request(
                    "POST",
                    _url,
                    data=body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            except Exception:  # noqa: BLE001 - probe must never crash the scan
                return None
            return page

        findings.extend(JwtChecker(send=send, url=url).check(decoy))
        # Only the forged-none probe is meaningful here; hygiene findings
        # (no-exp etc.) are out of scope for this target.
    return [f for f in findings if f.check == "jwt-none"]


def run_ssrf_target(base: str, manifest: dict, target_dir=None):
    from blastradius.web.oob import OobListener
    from blastradius.web.ssrf import SsrfChecker

    with OobListener() as oob:
        checker = SsrfChecker(listener=oob, callback_base=oob.callback_base)
        param = manifest.get("probe_param", "url")
        urls = [f"{base}/fetch?{param}=https://example.com", f"{base}/static"]
        return checker.check(urls)


def run_sqli_target(base: str, manifest: dict, target_dir=None):
    from blastradius.web.sqli import SqliChecker

    urls = [base + p for p in manifest.get("probe_urls", [])]
    return SqliChecker().check(urls)


def run_massassign_target(base: str, manifest: dict, target_dir=None):
    from blastradius.web.massassign import MassassignChecker

    checker = MassassignChecker(
        verify_url=base + manifest.get("verify_url", "/api/me"), fields=manifest.get("fields")
    )
    findings = []
    findings.extend(
        checker.check(
            base + manifest.get("profile_url", "/api/profile"), dict(manifest.get("base_body", {}))
        )
    )
    findings.extend(
        checker.check(
            base + manifest.get("strict_url", "/api/strict"), dict(manifest.get("base_body", {}))
        )
    )
    return findings


def run_cachepoison_target(base: str, manifest: dict, target_dir=None):
    from blastradius.web.cachepoison import CachePoisonChecker

    urls = [base + p for p in manifest.get("probe_urls", [])]
    return CachePoisonChecker().check(urls)


def run_netservices_target(base: str, manifest: dict, target_dir: Path):
    """Boot the fake FTP/SMTP/Telnet/SSH services and run the net scanner."""
    from blastradius.net.scanner import NetworkServiceScanner

    spec = importlib.util.spec_from_file_location(
        "bench_live_netservices_services", str(target_dir / "services.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    servers = module.make_servers()
    try:
        ports = ",".join(str(s.server_address[1]) for _, s in servers)
        scanner = NetworkServiceScanner(connect_timeout=2, read_timeout=2, workers=8)
        return scanner.scan("127.0.0.1", ports=ports)
    finally:
        for _, server in servers:
            server.shutdown()
            server.server_close()


_RUNNERS = {
    "live-idor": run_idor_target,
    "live-jwt": run_jwt_target,
    "live-ssrf": run_ssrf_target,
    "live-sqli": run_sqli_target,
    "live-massassign": run_massassign_target,
    "live-cachepoison": run_cachepoison_target,
    "live-netservices": run_netservices_target,
}


def run_target(target_dir: Path):
    manifest = json.loads((target_dir / "manifest.json").read_text(encoding="utf-8"))
    server = _serve(_load_server(target_dir))
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        runner = _RUNNERS.get(target_dir.name)
        if runner is None:
            return {
                "target": target_dir.name,
                "expected": 0,
                "reported": 0,
                "hits": 0,
                "skipped": True,
            }
        findings = runner(base, manifest, target_dir)
        expected = manifest.get("expected", [])
        hits = sum(1 for exp in expected if any(_matches(f, exp) for f in findings))
        return {
            "target": target_dir.name,
            "expected": len(expected),
            "reported": len(findings),
            "hits": hits,
        }
    finally:
        server.shutdown()
        server.server_close()


def _render_markdown(summary: dict) -> str:
    lines = ["# BlastRadius Dynamic Benchmark", ""]
    lines.append("| Target | Expected | Reported | Hits | Precision | Recall | F1 |")
    lines.append("|---|---|---|---|---|---|---|")
    for r in summary["targets"]:
        p = r["hits"] / r["reported"] if r["reported"] else 0.0
        rec = r["hits"] / r["expected"] if r["expected"] else 0.0
        f1 = 2 * p * rec / (p + rec) if p + rec else 0.0
        lines.append(
            f"| {r['target']} | {r['expected']} | {r['reported']} | {r['hits']} | "
            f"{p:.3f} | {rec:.3f} | {f1:.3f} |"
        )
    tot = summary["totals"]
    lines.append(
        f"| **Total** | **{tot['expected']}** | **{tot['reported']}** | **{tot['hits']}** | "
        f"**{tot['precision']:.3f}** | **{tot['recall']:.3f}** | **{tot['f1']:.3f}** |"
    )
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", default=str(ROOT / "dynamic"))
    ap.add_argument("--out", default=str(ROOT / "results"))
    ap.add_argument("--min-f1", type=float, default=0.0)
    args = ap.parse_args(argv)

    corpus = Path(args.corpus)
    targets = sorted(p for p in corpus.iterdir() if (p / "manifest.json").is_file())
    if not targets:
        print(f"[bench] no targets (manifest.json) found under {corpus}", file=sys.stderr)
        return 2

    started = time.time()
    rows = [run_target(t) for t in targets]
    elapsed = time.time() - started

    total = {k: sum(r.get(k, 0) for r in rows) for k in ("expected", "reported", "hits")}
    precision = total["hits"] / total["reported"] if total["reported"] else 0.0
    recall = total["hits"] / total["expected"] if total["expected"] else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    summary = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "corpus": str(corpus),
        "elapsed_seconds": round(elapsed, 2),
        "totals": {
            **total,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
        },
        "targets": rows,
    }
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime())
    (out_dir / f"dynamic-benchmark-{stamp}.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    (out_dir / "DYNAMIC_BENCHMARK.md").write_text(_render_markdown(summary), encoding="utf-8")
    print(_render_markdown(summary))
    if f1 < args.min_f1:
        print(f"[bench] FAIL: overall F1 {f1:.3f} < --min-f1 {args.min_f1}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
