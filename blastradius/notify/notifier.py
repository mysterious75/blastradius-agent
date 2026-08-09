"""Notifier — multi-channel alerts for confirmed findings.

Channels (all optional via env, each gracefully skipped when unconfigured):
    slack    SLACK_WEBHOOK_URL
    discord  DISCORD_WEBHOOK_URL
    telegram TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID
    email    SMTP_HOST/PORT/USER/PASS + NOTIFY_EMAIL
    github   GITHUB_TOKEN + BLASTRADIUS_ISSUES_REPO

All configured channels fire simultaneously (one thread each); each successful
delivery is logged to the providers_log table.
"""

import json
import os
import smtplib
import threading
from email.mime.text import MIMEText
from pathlib import Path
from typing import Callable, Dict, List, Optional
from urllib import request as urllib_request


def _default_http(url: str, payload: dict, headers: Dict = None) -> int:
    data = json.dumps(payload).encode("utf-8")
    req = urllib_request.Request(
        url, data=data,
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    with urllib_request.urlopen(req, timeout=15) as resp:
        return resp.status


class Notifier:
    """Send finding alerts to every configured channel."""

    CHANNELS = ("slack", "discord", "telegram", "email", "github")

    def __init__(self, http: Optional[Callable] = None, db=None):
        self.http = http or _default_http
        self.db = db  # SQLiteDB (optional) — successful deliveries are logged
        self._errors: List[str] = []

    # ------------------------------------------------------------------
    # Config
    # ------------------------------------------------------------------

    def configured_channels(self) -> List[str]:
        out = []
        if os.getenv("SLACK_WEBHOOK_URL"):
            out.append("slack")
        if os.getenv("DISCORD_WEBHOOK_URL"):
            out.append("discord")
        if os.getenv("TELEGRAM_BOT_TOKEN") and os.getenv("TELEGRAM_CHAT_ID"):
            out.append("telegram")
        if os.getenv("SMTP_HOST") and os.getenv("NOTIFY_EMAIL"):
            out.append("email")
        if os.getenv("GITHUB_TOKEN") and os.getenv("BLASTRADIUS_ISSUES_REPO"):
            out.append("github")
        return out

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def notify_finding(self, finding, patch_result=None, report_path: str = "") -> List[str]:
        """Send the finding to ALL configured channels simultaneously.

        Returns a list of per-channel errors (empty = all delivered).
        """
        self._errors = []
        channels = self.configured_channels()
        threads = []
        for channel in channels:
            thread = threading.Thread(
                target=self._dispatch, args=(channel, finding, patch_result, report_path),
                daemon=True,
            )
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join(timeout=30)
        return list(self._errors)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _dispatch(self, channel: str, finding, patch_result, report_path: str) -> None:
        try:
            handler = getattr(self, f"_send_{channel}")
            handler(finding, patch_result, report_path)
            self._log_delivery(channel)
        except Exception as exc:  # a failing channel never breaks the caller
            self._errors.append(f"{channel}: {exc}")

    def _log_delivery(self, channel: str) -> None:
        if self.db is None:
            try:
                from blastradius.db.database import SQLiteDB

                self.db = SQLiteDB()
            except Exception:
                return
        try:
            self.db.log_provider_usage(f"notify:{channel}", "-", 0, 0.0)
        except Exception:
            pass

    @staticmethod
    def _summary(finding, report_path: str) -> str:
        repo = getattr(finding, "repo", "") or "unknown"
        file = Path(finding.file).name if finding.file else "?"
        location = f"{repo}/{file}:{finding.line}" if repo != "unknown" else f"{file}:{finding.line}"
        line = (
            f"🔴 BlastRadius: [{finding.vuln_type.upper()}] confirmed in {location}"
            f"\nSeverity: {finding.severity} | CWE: {finding.cwe}"
        )
        if report_path:
            line += f"\nReport: {report_path}"
        return line

    # ------------------------------------------------------------------
    # Channels
    # ------------------------------------------------------------------

    def _send_slack(self, finding, patch_result, report_path) -> None:
        self.http(os.getenv("SLACK_WEBHOOK_URL"), {"text": self._summary(finding, report_path)})

    def _send_discord(self, finding, patch_result, report_path) -> None:
        if patch_result is not None:
            color = 0xFF4444 if not patch_result.needs_human else 0xD29922
        else:
            color = 0xFF4444
        self.http(os.getenv("DISCORD_WEBHOOK_URL"), {
            "embeds": [{
                "title": f"BlastRadius: {finding.vuln_type.upper()} confirmed",
                "description": self._summary(finding, report_path),
                "color": color,
            }],
        })

    def _send_telegram(self, finding, patch_result, report_path) -> None:
        token = os.getenv("TELEGRAM_BOT_TOKEN")
        chat_id = os.getenv("TELEGRAM_CHAT_ID")
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        self.http(url, {"chat_id": chat_id, "text": self._summary(finding, report_path)})

    def _send_email(self, finding, patch_result, report_path) -> None:
        host = os.getenv("SMTP_HOST")
        port = int(os.getenv("SMTP_PORT", "587"))
        user = os.getenv("SMTP_USER", "")
        password = os.getenv("SMTP_PASS", "")
        to_addr = os.getenv("NOTIFY_EMAIL")
        subject = f"BlastRadius Alert: {finding.vuln_type.upper()} in {getattr(finding, 'repo', '') or 'target'}"
        msg = MIMEText(self._summary(finding, report_path))
        msg["Subject"] = subject
        msg["From"] = user or "blastradius@local"
        msg["To"] = to_addr
        with smtplib.SMTP(host, port, timeout=15) as server:
            if user and password:
                server.starttls()
                server.login(user, password)
            server.sendmail(msg["From"], [to_addr], msg.as_string())

    def _send_github(self, finding, patch_result, report_path) -> None:
        token = os.getenv("GITHUB_TOKEN")
        repo = os.getenv("BLASTRADIUS_ISSUES_REPO")
        url = f"https://api.github.com/repos/{repo}/issues"
        body = self._summary(finding, report_path)
        labels = ["security-finding"]
        if patch_result is not None and patch_result.needs_human:
            labels.append("needs-review")
        self.http(url, {"title": f"Security Finding: {finding.vuln_type.upper()} in {finding.file}",
                        "body": body, "labels": labels},
                  {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})
