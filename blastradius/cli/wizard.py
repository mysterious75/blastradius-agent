"""SetupWizard — interactive setup (questionary, with plain input() fallback).

Run with:  python -m blastradius.cli.wizard

Flow: pick providers → enter API keys → pick notification channels →
schedule auto-hunt → max targets → write .env → optional test scan.
"""

import getpass
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from blastradius.cli.display import RichDisplay
from blastradius.providers.registry import PROVIDER_REGISTRY

CHANNEL_PROMPTS = {
    "slack": [("SLACK_WEBHOOK_URL", "Slack webhook URL")],
    "discord": [("DISCORD_WEBHOOK_URL", "Discord webhook URL")],
    "telegram": [
        ("TELEGRAM_BOT_TOKEN", "Telegram bot token"),
        ("TELEGRAM_CHAT_ID", "Telegram chat id"),
    ],
    "email": [
        ("SMTP_HOST", "SMTP host"),
        ("SMTP_PORT", "SMTP port (default 587)"),
        ("SMTP_USER", "SMTP user"),
        ("SMTP_PASS", "SMTP password"),
        ("NOTIFY_EMAIL", "Notification recipient email"),
    ],
    "github": [("BLASTRADIUS_ISSUES_REPO", "Repo to file issues in (owner/name)")],
}


# ---------------------------------------------------------------------------
# Prompt helpers (questionary first, input() fallback)
# ---------------------------------------------------------------------------

def _text(message: str, default: str = "") -> str:
    try:
        import questionary

        return questionary.text(message, default=default).ask() or default
    except ImportError:
        prompt = f"{message} [{default}]" if default else f"{message}: "
        value = input(prompt).strip()
        return value or default


def _password(message: str) -> str:
    try:
        import questionary

        return questionary.password(message).ask() or ""
    except ImportError:
        return getpass.getpass(message + ": ")


def _select(message: str, choices: List[str], default: Optional[str] = None) -> str:
    try:
        import questionary

        return questionary.select(message, choices=choices, default=default or choices[0]).ask()
    except ImportError:
        print(message)
        for i, choice in enumerate(choices, 1):
            print(f"  {i}. {choice}")
        default_idx = choices.index(default) + 1 if default in choices else 1
        raw = input(f"Enter number [{default_idx}]: ").strip()
        if not raw:
            return default or choices[0]
        if raw.isdigit() and 0 < int(raw) <= len(choices):
            return choices[int(raw) - 1]
        return default or choices[0]


def _checkbox(message: str, choices: List[str]) -> List[str]:
    try:
        import questionary

        return questionary.checkbox(message, choices=choices).ask() or []
    except ImportError:
        print(message)
        print("  (comma-separated numbers; empty = none)")
        for i, choice in enumerate(choices, 1):
            print(f"  {i}. {choice}")
        raw = input("> ").strip()
        if not raw:
            return []
        picked = []
        for part in raw.split(","):
            part = part.strip()
            if part.isdigit() and 0 < int(part) <= len(choices):
                picked.append(choices[int(part) - 1])
        return picked


def _confirm(message: str, default: bool = True) -> bool:
    try:
        import questionary

        return questionary.confirm(message, default=default).ask()
    except ImportError:
        suffix = "[Y/n]" if default else "[y/N]"
        raw = input(f"{message} {suffix}: ").strip().lower()
        if not raw:
            return default
        return raw in ("y", "yes")


def _int(message: str, default: int) -> int:
    try:
        import questionary

        value = questionary.text(message, default=str(default)).ask()
        return int(value or default)
    except ImportError:
        raw = input(f"{message} [{default}]: ").strip()
        return int(raw) if raw.isdigit() else default


# ---------------------------------------------------------------------------
# .env helpers
# ---------------------------------------------------------------------------

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


def _write_env(path: Path, env: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(f"{k}={v}" for k, v in env.items()) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Wizard
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    display = RichDisplay()
    display.print_banner()
    print("[*] Welcome to BlastRadius Setup\n")

    env_path = _env_path()
    env = _load_env(env_path)

    provider_names = list(PROVIDER_REGISTRY)
    selected = _checkbox("Select providers to configure:", provider_names)
    for name in selected:
        key_env = PROVIDER_REGISTRY[name]["key_env"]
        if not key_env:
            print(f"[*] {name} is a local provider (no API key needed).")
            continue
        env[key_env] = _password(f"Enter API key for {name}")

    channels = _checkbox("Select notification channels:", list(CHANNEL_PROMPTS))
    for channel in channels:
        for key, label in CHANNEL_PROMPTS[channel]:
            env[key] = _text(label, default=env.get(key, ""))

    schedule = _select("Schedule auto-hunt?", ["daily", "weekly", "disabled"], default="disabled")
    max_targets = _int("Max targets per hunt:", default=10)
    env["HUNT_SCHEDULE"] = schedule
    env["HUNT_MAX_TARGETS"] = str(max_targets)

    _write_env(env_path, env)
    print(f"[+] wrote {env_path}")

    display.print_stats_panel({
        "total_scans": len(selected),
        "confirmed_cves": len(channels),
        "patches_generated": 0,
        "success_rate": 0.0,
    })

    if _confirm("Run a test scan now? (WebGoat)", default=False):
        subprocess.run(
            [sys.executable, "-m", "blastradius.hunter", "--target",
             "https://github.com/WebGoat/WebGoat"],
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
