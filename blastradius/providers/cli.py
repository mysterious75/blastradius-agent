"""Provider CLI — list, test, and set LLM providers.

Usage:
    python -m blastradius.providers list
    python -m blastradius.providers test
    python -m blastradius.providers set --provider deepseek --model deepseek-chat
"""

import argparse
import os
import time
from pathlib import Path

from blastradius.cli.display import RichDisplay
from blastradius.providers.client import LLMClient, provider_key_set
from blastradius.providers.registry import PROVIDER_REGISTRY


def _env_path() -> Path:
    return Path(os.getenv("BLASTRADIUS_ENV_FILE", ".env"))


def _load_env(path: Path) -> dict:
    env = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            env[key.strip()] = value.strip()
    return env


def cmd_list(_args) -> int:
    display = RichDisplay()
    rows = []
    for name, cfg in PROVIDER_REGISTRY.items():
        models = ", ".join(cfg["models"][:6])
        if len(cfg["models"]) > 6:
            models += "…"
        if cfg.get("api_key"):
            key, status = "local", "local"
        elif provider_key_set(name):
            key, status = "yes", "ready"
        else:
            key, status = "no", "no key"
        rows.append([name, models, key, status])
    display.print_table(["Provider", "Models", "Key", "Status"], rows, title="LLM Providers")
    return 0


def cmd_test(_args) -> int:
    display = RichDisplay()
    ok = 0
    rows = []
    for name in PROVIDER_REGISTRY:
        model = PROVIDER_REGISTRY[name]["models"][0]
        if not provider_key_set(name):
            rows.append({"provider": name, "model": "—", "ok": False,
                         "status": "No API key", "latency": "—"})
            continue
        start = time.monotonic()
        try:
            LLMClient(provider=name, model=model, verbose=False).chat(["say hi"], "Reply with OK.")
            rows.append({"provider": name, "model": model, "ok": True,
                         "status": "Connected",
                         "latency": f"{(time.monotonic() - start) * 1000:.0f}ms"})
            ok += 1
        except Exception as exc:
            rows.append({"provider": name, "model": model, "ok": False,
                         "status": f"Failed: {exc}", "latency": "—"})
    display.print_provider_table(rows)
    print(f"{ok} provider(s) reachable")
    return 0


def cmd_cost(_args) -> int:
    from blastradius.providers.cost_tracker import CostTracker, cost_tracker

    tracker = cost_tracker
    session = tracker.get_session_cost()
    if not tracker.usage:
        # fresh process: reconstruct usage from the SQLite providers_log
        try:
            from blastradius.db.database import SQLiteDB

            db = SQLiteDB()
            with db._connect() as conn:
                rows = conn.execute(
                    "SELECT provider, model, tokens_used FROM providers_log"
                ).fetchall()
            tracker = CostTracker()
            for row in rows:
                provider = str(row["provider"])
                if provider.startswith("notify:"):
                    continue
                tracker.track_usage(provider, row["model"], int(row["tokens_used"]), 0)
            session = tracker.get_session_cost()
        except Exception:
            pass

    monthly = tracker.get_monthly_estimate()
    display = RichDisplay()
    display.print_stats_panel({
        "total_scans": len(session["breakdown"]),
        "confirmed_cves": round(session["total_usd"], 6),
        "patches_generated": 0,
        "success_rate": 0.0,
    })
    print(f"Session cost: ${session['total_usd']}")
    for key, value in session["breakdown"].items():
        print(f"  {key}: ${value}")
    print(f"Monthly estimate ({monthly['sessions_per_month']} sessions): ${monthly['monthly_usd']}")
    return 0


def cmd_set(args) -> int:
    if args.provider not in PROVIDER_REGISTRY:
        print(f"❌ unknown provider {args.provider!r}; choose from: {', '.join(PROVIDER_REGISTRY)}")
        return 1
    model = args.model or PROVIDER_REGISTRY[args.provider]["models"][0]
    env_path = _env_path()
    env = _load_env(env_path)
    env["BLASTRADIUS_PROVIDER"] = args.provider
    env["BLASTRADIUS_MODEL"] = model
    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text(
        "\n".join(f"{k}={v}" for k, v in env.items()) + "\n", encoding="utf-8"
    )
    print(f"[+] wrote {env_path}: BLASTRADIUS_PROVIDER={args.provider} BLASTRADIUS_MODEL={model}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="blastradius-providers")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list all providers and key status")

    sub.add_parser("test", help="test every configured provider with 'say hi'")

    set_p = sub.add_parser("set", help="write provider + model to .env")
    set_p.add_argument("--provider", required=True)
    set_p.add_argument("--model", default=None)

    sub.add_parser("cost", help="print LLM cost report")

    args = parser.parse_args(argv)
    if args.command != "set":
        RichDisplay().print_banner()
    return {"list": cmd_list, "test": cmd_test, "set": cmd_set, "cost": cmd_cost}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
