"""Data-egress (exfiltration) guardrail for agent actions.

A scanner is a *reader* of secrets; the highest-severity agent failure mode is
turning that reader into a *writer* of attacker-visible data. This module is
the hard block for every publish-shaped primitive an agent could reach:

- creating a public repository or flipping a private repo to public,
- creating or updating a Gist (Gists are publicly reachable even when
  "secret", and are indexed by search engines),
- publishing a release, an npm/PyPI package, or a container image,
- uploading file content to a paste / file-drop service,
- any ``git push`` whose remote is not the operator's in-scope workspace.

Design rules:

- **Fail closed.** An unrecognised action is denied, and an audit failure
  denies the action instead of silently allowing it.
- **Publish primitives are never implicit.** ``repo-create``, ``gist-create``,
  ``gist-update`` and ``package-publish`` are denied even inside scope, because
  a scan has no legitimate need to publish; they require an explicit human
  override.
- **Scope-aware.** Non-publishing writes are allowed only when the destination
  is explicitly marked in-scope by the operator.
- **Audited.** Every decision is written to the tamper-evident
  :class:`~blastradius.security.audit_log.AuditLogger` before it is returned.

Everything here is offline and deterministic: no network, no LLM, no shell.
"""

import re
from typing import NamedTuple, Optional

from .audit_log import AuditLogger


class Verdict(NamedTuple):
    """One guardrail decision."""

    allowed: bool
    rule: str
    reason: str

    def __bool__(self) -> bool:
        return self.allowed


# Actions that can move data off the machine, and their default disposition.
SCAN_WRITE_ACTIONS = frozenset(
    {
        "repo-push",
        "repo-visibility-change",
        "release-publish",
        "file-upload",
    }
)

PUBLISH_PRIMITIVES = frozenset({"repo-create", "gist-create", "gist-update", "package-publish"})

KNOWN_ACTIONS = PUBLISH_PRIMITIVES | SCAN_WRITE_ACTIONS

# Hosts that are publicly readable by design; any write here is exfiltration.
PUBLIC_EGRESS_HOSTS = frozenset(
    {
        "0x0.st",
        "bashupload.com",
        "file.io",
        "gist.github.com",
        "github.com",
        "gitlab.com",
        "hastebin.com",
        "hexdump.com",
        "ngrok.io",
        "npmjs.com",
        "paste.ee",
        "pastebin.com",
        "pypi.org",
        "raw.githubusercontent.com",
        "requestbin.com",
        "transfer.sh",
        "webhook.site",
    }
)

_HOST_RE = re.compile(r"://(?:[^@/\s]+@)?([A-Za-z0-9._-]+)(?::\d+)?(?:/|\b)")

_UPLOAD_FLAGS = (
    "-T",
    "--upload-file",
    "-F",
    "--form",
    "-d",
    "--data",
    "--data-binary",
    "--data-raw",
)

_PUBLISH_PATTERNS = (
    (re.compile(r"\bgit\s+push\b"), "git-push"),
    (re.compile(r"\bgit\s+remote\s+add\b.*\bhttps?://"), "git-remote-add"),
    (re.compile(r"\bgh\s+repo\s+create\b"), "gh-repo-create"),
    (re.compile(r"\bgh\s+gist\s+(?:create|edit)\b"), "gh-gist-create"),
    (re.compile(r"\bgh\s+release\s+(?:create|upload)\b"), "gh-release-create"),
    (re.compile(r"\b(?:npm|yarn\s+npm|pnpm)\s+publish\b"), "package-publish"),
    (re.compile(r"\b(?:twine|python\s+-m\s+twine)\s+upload\b"), "package-publish"),
    (re.compile(r"\b(?:docker|oras|nerdctl)\s+push\b"), "registry-push"),
    (re.compile(r"\brclone\s+(?:copy|sync)\b"), "rclone-copy"),
    (re.compile(r"\b(?:curl|wget)\b"), "http-transfer"),
)


def _host_of(destination: str) -> str:
    match = _HOST_RE.search(destination or "")
    return match.group(1).lower() if match else ""


def classify(
    action: str,
    destination: str = "",
    to_visibility: str = "",
    in_scope: bool = False,
    override: bool = False,
) -> Verdict:
    """Decide whether ``action`` may run.

    Args:
        action: One of :data:`KNOWN_ACTIONS`; anything else is denied.
        destination: Remote/URL the data would be written to.
        to_visibility: Target visibility for visibility changes (``public``,
            ``private``, ``unlisted``).
        in_scope: Operator has explicitly scoped this destination.
        override: Human explicitly authorised a publish primitive.

    Returns:
        A :class:`Verdict`; ``allowed`` is ``False`` for every denial.
    """
    if not action or action not in KNOWN_ACTIONS:
        return Verdict(
            False, "unknown-action", f"unrecognised egress action {action!r}; denied by default"
        )

    if action in PUBLISH_PRIMITIVES and not override:
        return Verdict(
            False,
            "publish-primitive",
            f"{action} publishes data off-box and needs an explicit human override",
        )

    if override:
        if not in_scope:
            return Verdict(
                False, "override-without-scope", "override given but destination is not in scope"
            )
        return Verdict(True, "human-override", f"{action} explicitly overridden by operator")

    if (to_visibility or "").strip().lower() == "public":
        return Verdict(
            False,
            "public-visibility",
            f"visibility change to public via {action} would expose target data",
        )

    if _host_of(destination) in PUBLIC_EGRESS_HOSTS:
        return Verdict(
            False, "public-egress-host", f"destination {destination!r} is publicly readable"
        )

    if not in_scope:
        return Verdict(False, "unscoped-egress", f"{action} to {destination!r} is not in scope")

    return Verdict(True, "in-scope", f"{action} stays inside the operator-scoped destination")


def scan_command(command: str) -> Verdict:
    """Screen a shell command for publish-shaped behaviour.

    Denies any command that could write scan output to a public destination.
    Detects the transport (``git push``, ``gh gist create``, ``npm publish``,
    ``curl -T``) rather than trusting the caller's stated intent.
    """
    text = (command or "").strip()
    if not text:
        return Verdict(False, "empty-command", "no command supplied")

    for pattern, rule in _PUBLISH_PATTERNS:
        match = pattern.search(text)
        if not match:
            continue
        if rule == "http-transfer":
            hosts = {h.lower() for h in _HOST_RE.findall(text)}
            uploading = any(flag in text for flag in _UPLOAD_FLAGS)
            if not uploading and not hosts & PUBLIC_EGRESS_HOSTS:
                return Verdict(True, "plain-fetch", "HTTP GET without upload flag or public host")
            return Verdict(
                False,
                "http-transfer",
                f"HTTP upload to {sorted(hosts) or ['unknown']} can exfiltrate scan output",
            )
        return Verdict(False, rule, f"command matches blocked egress pattern {pattern.pattern!r}")

    return Verdict(True, "no-egress", "no publish-shaped pattern found")


class ExfilGuard:
    """Auditing wrapper around :func:`classify` and :func:`scan_command`.

    A decision is recorded before it is returned, and an audit failure denies
    the action (fail-closed) instead of passing it through.
    """

    def __init__(self, audit: Optional[AuditLogger] = None):
        self.audit = audit if audit is not None else AuditLogger()

    def _decide(self, event: str, verdict: Verdict, **data) -> Verdict:
        try:
            self.audit.log(
                event, allowed=verdict.allowed, rule=verdict.rule, reason=verdict.reason, **data
            )
        except Exception as exc:  # noqa: BLE001 - any audit failure must deny
            return Verdict(
                False, "audit-failure", f"audit log unavailable ({exc}); denied by default"
            )
        return verdict

    def check(
        self,
        action: str,
        destination: str = "",
        to_visibility: str = "",
        in_scope: bool = False,
        override: bool = False,
    ) -> Verdict:
        """Audited :func:`classify`."""
        verdict = classify(
            action,
            destination=destination,
            to_visibility=to_visibility,
            in_scope=in_scope,
            override=override,
        )
        return self._decide(
            "exfil-guard",
            verdict,
            action=action,
            destination=destination,
            to_visibility=to_visibility,
            in_scope=in_scope,
            override=override,
        )

    def check_command(self, command: str) -> Verdict:
        """Audited :func:`scan_command`."""
        return self._decide("exfil-command", scan_command(command), command=command)
