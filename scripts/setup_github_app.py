"""Interactive GitHub App setup wizard.

Prompts for the GitHub App + LLM credentials, writes them to ``.env``,
optionally tests the webhook endpoint connectivity, and prints next steps.

Usage:
    python -m scripts.setup_github_app
"""

import os
import urllib.request
from pathlib import Path

REQUIRED_KEYS = [
    ("GITHUB_APP_ID", "GitHub App ID"),
    ("GITHUB_PRIVATE_KEY", "GitHub App private key (path to .pem file, or the raw key)"),
    ("GITHUB_WEBHOOK_SECRET", "Webhook secret (used for X-Hub-Signature-256)"),
    ("OPENCODE_API_KEY", "OpenCode API key (LLM for patch generation)"),
]

WEBHOOK_HEALTH_URL = "http://localhost:8000/health"


def _ask(label: str, current: str) -> str:
    suffix = "[set]" if current else ""
    value = input(f"{label} {suffix}: ").strip() if suffix else input(f"{label}: ").strip()
    return value or current


def _resolve_private_key(value: str) -> str:
    path = Path(value)
    if path.is_file():
        return path.read_text(encoding="utf-8").strip()
    return value


def load_env(path: Path) -> dict:
    """Read an existing .env into a dict (ignores malformed lines)."""
    env = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            env[key.strip()] = value.strip()
    return env


def write_env(path: Path, env: dict) -> None:
    lines = [f"{key}={value}" for key, value in env.items()]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_webhook_connectivity() -> None:
    """Ping the local webhook /health endpoint if it is running."""
    try:
        with urllib.request.urlopen(WEBHOOK_HEALTH_URL, timeout=3) as resp:
            print(f"[+] Webhook reachable: {WEBHOOK_HEALTH_URL} -> {resp.status}")
    except Exception:
        print(
            f"[!] Webhook not reachable at {WEBHOOK_HEALTH_URL} "
            "(expected if the server is not running yet — start it with "
            "`blastradius-server` or `make server`)."
        )


def print_next_steps() -> None:
    print()
    print("Next steps:")
    print("  1. Start the webhook:  blastradius-server   (or: make server)")
    print("  2. Register the webhook URL in your GitHub App settings:")
    print("       https://github.com/settings/apps/<your-app>/webhooks")
    print("       URL:     https://<your-host>/webhook")
    print("       Content type: application/json")
    print("  3. Grant the app read access to pull requests and issues.")
    print("  4. Open a PR in a repo where the app is installed — BlastRadius")
    print("     will scan it and comment with findings and patches.")
    print()
    print("Security: keep .env out of version control (.gitignore already covers it).")


def main() -> int:
    env_path = Path.cwd() / ".env"
    env = load_env(env_path)

    print("BlastRadius — GitHub App setup wizard")
    print(f"Writing configuration to {env_path}")
    print("(press Enter to keep the current value)\n")

    for key, label in REQUIRED_KEYS:
        value = _ask(label, env.get(key, os.getenv(key, "")))
        if key == "GITHUB_PRIVATE_KEY" and value:
            value = _resolve_private_key(value)
        env[key] = value

    write_env(env_path, env)
    print(f"[+] wrote {env_path}")

    test_webhook_connectivity()
    print_next_steps()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
