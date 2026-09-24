"""Cross-chain verification & security configuration auditor.

**Defensive.** Finds *under-redundant* security configuration before a
deployment goes live — the class of misconfiguration that turns one
compromised signer into a nine-figure drain.

Every rule traces to a real, publicly documented failure mode. The anchor case
is KelpDAO / LayerZero (18 Apr 2026): an OFTAdapter configured with
``requiredDVNCount = 1, optionalDVNCount = 0`` meant a single compromised
signer set could authorize an arbitrary cross-chain message. No contract bug
was involved — the contracts all behaved exactly as designed. A one-line
config check would have flagged it before $292M moved.

Nothing here generates attack traffic or payloads: it reads a configuration
and reports where redundancy / thresholds / controls are missing. See the
repo ``DISCLAIMER.md`` — authorized use only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Finding:
    """One configuration weakness."""

    rule_id: str
    severity: str
    title: str
    detail: str
    remediation: str
    target: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def row(self) -> List[str]:
        return [self.severity, self.rule_id, self.target, self.title]


@dataclass
class AuditReport:
    """Collection of findings for one configuration snapshot."""

    target: str
    findings: List[Finding] = field(default_factory=list)

    @property
    def worst_severity(self) -> str:
        if not self.findings:
            return "INFO"
        return min((f.severity for f in self.findings), key=lambda s: _RANK[s])

    @property
    def passed(self) -> bool:
        return self.worst_severity not in ("CRITICAL", "HIGH")

    def counts(self) -> Dict[str, int]:
        out = dict.fromkeys(SEVERITIES, 0)
        for f in self.findings:
            out[f.severity] += 1
        return out

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: (_RANK[f.severity], f.rule_id, f.target))

    def rows(self) -> List[List[str]]:
        return [f.row() for f in self.sorted_findings()]

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)


def _num(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


class ConfigAuditor:
    """Rule-based auditor for cross-chain and protocol security config.

    Usage::

        auditor = ConfigAuditor()
        report = auditor.audit(snapshot_dict)
        if not report.passed:
            ...
    """

    #: A verifier stack should require at least this many independent attestors.
    min_independent_attestors = 2
    #: Block confirmations below this are treated as reorg-exposed (per chain
    #: override available through ``chain_confirmations``).
    min_confirmations = 15
    #: Optional per-chain confirmation floors, e.g. ``{"Ethereum": 15}``.
    chain_confirmations: Dict[str, int] = {}

    def __init__(
        self,
        min_independent_attestors: int = 2,
        min_confirmations: int = 15,
        chain_confirmations: Optional[Dict[str, int]] = None,
    ) -> None:
        self.min_independent_attestors = min_independent_attestors
        self.min_confirmations = min_confirmations
        self.chain_confirmations = dict(chain_confirmations or {})

    # -- public ------------------------------------------------------------
    def audit(self, config: Dict[str, Any]) -> AuditReport:
        report = AuditReport(target=str(config.get("target", "unnamed-config")))
        self._audit_pathways(config, report)
        self._audit_oracles(config, report)
        self._audit_multisigs(config, report)
        self._audit_admin(config, report)
        self._audit_roles(config, report)
        self._audit_backstops(config, report)
        self._audit_cross_pathway_correlation(config, report)
        return report

    # -- rules: cross-chain verifier stacks --------------------------------
    def _audit_pathways(self, config: Dict[str, Any], report: AuditReport) -> None:
        for path in config.get("pathways", []) or []:
            pid = str(path.get("id", "pathway"))
            required = int(_num(path.get("required_dvn_count"), 0))
            optional = int(_num(path.get("optional_dvn_count"), 0))
            threshold = int(_num(path.get("optional_dvn_threshold"), 0))
            req_list = [str(x) for x in (path.get("required_dvns") or [])]
            opt_list = [str(x) for x in (path.get("optional_dvns") or [])]

            # --- R1: total independent attestors below the floor -----------
            effective_optional = min(threshold, optional) if optional else 0
            attestors = required + effective_optional
            if attestors < self.min_independent_attestors:
                report.add(
                    Finding(
                        rule_id="DVN-INSUFFICIENT-REDUNDANCY",
                        severity="CRITICAL",
                        title=f"{attestors} attestor(s) — below the {self.min_independent_attestors} floor",
                        detail=(
                            f"required_dvn_count={required}, optional_dvn_count={optional}, "
                            f"optional_dvn_threshold={threshold}. A single compromised signer "
                            "set can authorize any cross-chain message on this pathway. This is "
                            "the exact structural failure behind the KelpDAO drain (18 Apr 2026): "
                            "a 1-of-1 DVN stack let one forged packet release $292M."
                        ),
                        remediation=(
                            "Require at least two independent DVNs from different operators "
                            "(e.g. LayerZero default + a second provider), or configure optional "
                            "DVNs with threshold >= 1 so no single signer can attest alone."
                        ),
                        target=f"pathway:{pid}",
                        evidence={
                            "required_dvn_count": required,
                            "optional_dvn_count": optional,
                            "optional_dvn_threshold": threshold,
                        },
                    )
                )

            # --- R2: optional threshold cannot be satisfied ----------------
            if optional and threshold > optional:
                report.add(
                    Finding(
                        rule_id="DVN-THRESHOLD-UNREACHABLE",
                        severity="CRITICAL",
                        title=f"optional_dvn_threshold {threshold} > optional_dvn_count {optional}",
                        detail=(
                            "The configured threshold can never be met, so message verification "
                            "either fails closed permanently or silently degrades to whatever the "
                            "required set alone permits."
                        ),
                        remediation=f"Set optional_dvn_threshold <= {optional}, or add more optional DVNs.",
                        target=f"pathway:{pid}",
                        evidence={"optional_dvn_threshold": threshold, "optional_dvn_count": optional},
                    )
                )

            # --- R3: duplicate operator is not redundancy ------------------
            dupes = sorted({d for d in req_list + opt_list if (req_list + opt_list).count(d) > 1})
            if dupes:
                report.add(
                    Finding(
                        rule_id="DVN-DUPLICATE-OPERATOR",
                        severity="HIGH",
                        title=f"{len(dupes)} repeated DVN address(es) counted as separate attestors",
                        detail=(
                            "The same signer appears more than once (or in both the required and "
                            "optional sets). Nominally redundant, actually a single point of failure."
                        ),
                        remediation="De-duplicate DVN lists; use distinct independent operators.",
                        target=f"pathway:{pid}",
                        evidence={"duplicates": dupes},
                    )
                )

            # --- R5: reorg-exposed confirmation depth ----------------------
            chain = str(path.get("chain", "") or "")
            floor = self.chain_confirmations.get(chain, self.min_confirmations)
            confs = int(_num(path.get("confirmations"), 0))
            if confs < floor:
                report.add(
                    Finding(
                        rule_id="LOW-CONFIRMATIONS",
                        severity="MEDIUM",
                        title=f"confirmations={confs} below floor {floor}",
                        detail=(
                            "Shallow confirmation depth exposes the attestation to chain reorgs; "
                            "a reorged source message can be replayed against the destination."
                        ),
                        remediation=f"Raise confirmations to >= {floor}"
                        + (f" (chain override for {chain})" if chain else "") + ".",
                        target=f"pathway:{pid}",
                        evidence={"confirmations": confs, "floor": floor, "chain": chain},
                    )
                )

            # --- R: no receive library / endpoint pinned --------------------
            if not path.get("receive_library"):
                report.add(
                    Finding(
                        rule_id="DVN-LIBRARY-UNPINNED",
                        severity="LOW",
                        title="receive_library not pinned",
                        detail=(
                            "Without an explicitly pinned receive library the verification path "
                            "can change underneath the deployment (library migration), moving the "
                            "trust boundary without a review."
                        ),
                        remediation="Pin receive_library explicitly and monitor for library migration events.",
                        target=f"pathway:{pid}",
                    )
                )

    def _audit_cross_pathway_correlation(self, config: Dict[str, Any], report: AuditReport) -> None:
        """R4: one operator securing many pathways = correlated failure."""
        owners: Dict[str, List[str]] = {}
        for path in config.get("pathways", []) or []:
            pid = str(path.get("id", "pathway"))
            for addr in (path.get("required_dvns") or []) + (path.get("optional_dvns") or []):
                owners.setdefault(str(addr), []).append(pid)

        for addr, paths in sorted(owners.items()):
            unique_paths = sorted(set(paths))
            if len(unique_paths) > 1:
                report.add(
                    Finding(
                        rule_id="DVN-CORRELATED-PATHWAYS",
                        severity="HIGH",
                        title=f"one DVN secures {len(unique_paths)} pathways",
                        detail=(
                            "A single verifier operator backs multiple pathways, so one operational "
                            "compromise unlocks all of them at once. Cross-chain redundancy that shares "
                            "an operator is not redundancy."
                        ),
                        remediation="Spread pathways across independent DVN operators.",
                        target=f"dvn:{addr}",
                        evidence={"pathways": unique_paths},
                    )
                )

    # -- rules: pricing ----------------------------------------------------
    def _audit_oracles(self, config: Dict[str, Any], report: AuditReport) -> None:
        for oracle in config.get("oracles", []) or []:
            market = str(oracle.get("market", "oracle"))
            feeds = [str(x) for x in (oracle.get("feeds") or [])]
            if len(set(feeds)) < 2:
                report.add(
                    Finding(
                        rule_id="ORACLE-SINGLE-FEED",
                        severity="HIGH",
                        title=f"{len(set(feeds))} price feed(s) — single point of failure",
                        detail=(
                            "The market prices collateral from a single feed. A stale, frozen or "
                            "manipulated feed reprices collateral directly, which is what turns a "
                            "pricing outage into unliquidatable positions."
                        ),
                        remediation=(
                            "Add an independent secondary feed (different vendor / different "
                            "aggregation path) and define staleness + deviation circuit breakers."
                        ),
                        target=f"market:{market}",
                        evidence={"feeds": feeds},
                    )
                )
            if not oracle.get("max_staleness_seconds"):
                report.add(
                    Finding(
                        rule_id="ORACLE-NO-STALENESS-LIMIT",
                        severity="MEDIUM",
                        title="no max_staleness_seconds configured",
                        detail="Without a staleness bound a frozen feed keeps being accepted as current.",
                        remediation="Set max_staleness_seconds and pause on breach.",
                        target=f"market:{market}",
                    )
                )
            if oracle.get("max_deviation_bps") in (None, 0):
                report.add(
                    Finding(
                        rule_id="ORACLE-NO-DEVIATION-LIMIT",
                        severity="MEDIUM",
                        title="no max_deviation_bps configured",
                        detail="No cross-feed deviation breaker, so one bad print reprices the book unchallenged.",
                        remediation="Set max_deviation_bps and halt new borrowing when breached.",
                        target=f"market:{market}",
                    )
                )

    # -- rules: keys, multisigs, timelocks ---------------------------------
    def _audit_multisigs(self, config: Dict[str, Any], report: AuditReport) -> None:
        for ms in config.get("multisigs", []) or []:
            name = str(ms.get("id", "multisig"))
            threshold = int(_num(ms.get("threshold"), 0))
            signers = int(_num(ms.get("signers"), 0))
            if threshold < 2:
                report.add(
                    Finding(
                        rule_id="MULTISIG-THRESHOLD-ONE",
                        severity="HIGH",
                        title=f"threshold {threshold}-of-{signers or '?'} — one key is enough",
                        detail=(
                            "A 1-of-N multisig is a single key in practice: one compromised signer "
                            "can pause, upgrade or move funds unilaterally."
                        ),
                        remediation="Raise the threshold to at least 2 (preferably a majority).",
                        target=f"multisig:{name}",
                        evidence={"threshold": threshold, "signers": signers},
                    )
                )
            if signers and threshold > signers:
                report.add(
                    Finding(
                        rule_id="MULTISIG-THRESHOLD-UNREACHABLE",
                        severity="CRITICAL",
                        title=f"threshold {threshold} > signers {signers}",
                        detail="This multisig can never execute; every emergency action is dead on arrival.",
                        remediation=f"Set threshold <= {signers}.",
                        target=f"multisig:{name}",
                        evidence={"threshold": threshold, "signers": signers},
                    )
                )
            if signers and signers < 3:
                report.add(
                    Finding(
                        rule_id="MULTISIG-SMALL-SIGNER-SET",
                        severity="MEDIUM",
                        title=f"only {signers} signer(s)",
                        detail="A very small signer set leaves no room for key rotation without downtime.",
                        remediation="Grow the signer set to at least 3-5 with a documented rotation policy.",
                        target=f"multisig:{name}",
                        evidence={"signers": signers},
                    )
                )

    def _audit_admin(self, config: Dict[str, Any], report: AuditReport) -> None:
        admin = config.get("admin") or {}
        if not admin:
            return
        label = str(admin.get("address", "admin"))
        kind = str(admin.get("type", "unknown")).lower()

        if kind in ("eoa", "unknown"):
            report.add(
                Finding(
                    rule_id="ADMIN-NOT-A-MULTISIG",
                    severity="HIGH",
                    title=f"admin is {kind}",
                    detail=(
                        "Upgrade / withdraw authority sits behind a single externally owned account. "
                        "One device compromise is a full protocol compromise."
                    ),
                    remediation="Move admin authority to a threshold multisig behind a timelock.",
                    target=f"admin:{label}",
                    evidence={"type": kind},
                )
            )

        timelock = int(_num(admin.get("timelock_seconds"), 0))
        if timelock <= 0:
            report.add(
                Finding(
                    rule_id="ADMIN-NO-TIMELOCK",
                    severity="MEDIUM",
                    title="no timelock on admin actions",
                    detail=(
                        "Upgrades and parameter changes can land in one block. Users get no exit "
                        "window and monitoring has nothing to warn about."
                    ),
                    remediation="Add a timelock (>= 24h) on upgrades and parameter changes.",
                    target=f"admin:{label}",
                    evidence={"timelock_seconds": timelock},
                )
            )

    def _audit_roles(self, config: Dict[str, Any], report: AuditReport) -> None:
        roles = config.get("roles") or {}
        if not roles:
            return
        if not roles.get("pauser"):
            report.add(
                Finding(
                    rule_id="NO-EMERGENCY-PAUSER",
                    severity="MEDIUM",
                    title="no emergency pauser role",
                    detail=(
                        "There is no fast brake. In the KelpDAO incident a second forged packet "
                        "(40,000 rsETH, ~$100M) was stopped purely because an emergency multisig "
                        "paused transfers 46 minutes in. Without that role the whole reserve drains."
                    ),
                    remediation="Define a narrowly scoped pauser role with a documented runbook and rotation.",
                    target="roles",
                )
            )
        if not roles.get("guardian") and not roles.get("sentinel"):
            report.add(
                Finding(
                    rule_id="NO-LIVE-SENTINEL",
                    severity="LOW",
                    title="no monitoring/guardian role wired to incident response",
                    detail="Detection without an owner to act on it buys nothing during a live drain.",
                    remediation="Wire alerts to a staffed on-call with authority to pause.",
                    target="roles",
                )
            )

    def _audit_backstops(self, config: Dict[str, Any], report: AuditReport) -> None:
        for market in config.get("markets", []) or []:
            name = str(market.get("name") or market.get("id") or "market")
            buffer_usd = _num(market.get("backstop_buffer_usd"), 0.0)
            debt_usd = _num(market.get("debt_against_token_usd"), 0.0)
            if debt_usd > 0 and buffer_usd <= 0:
                report.add(
                    Finding(
                        rule_id="NO-BACKSTOP-BUFFER",
                        severity="HIGH",
                        title="borrowing enabled with zero backstop buffer",
                        detail=(
                            f"${debt_usd:,.0f} of debt is taken against this listing but the market "
                            "has no safety-module / umbrella buffer. Any collateral collapse lands "
                            "directly on the pool's own reserves as unliquidatable bad debt."
                        ),
                        remediation="Fund a safety module / backstop sized to cover a realistic collateral collapse.",
                        target=f"market:{name}",
                        evidence={"debt_against_token_usd": debt_usd, "backstop_buffer_usd": buffer_usd},
                    )
                )
            elif debt_usd > 0 and buffer_usd < 0.25 * debt_usd:
                report.add(
                    Finding(
                        rule_id="THIN-BACKSTOP-BUFFER",
                        severity="MEDIUM",
                        title=f"backstop covers {buffer_usd / debt_usd:.0%} of outstanding debt",
                        detail="Buffer absorbs only a fraction of a full collateral collapse.",
                        remediation="Grow the backstop toward full coverage of debt against this listing.",
                        target=f"market:{name}",
                        evidence={"debt_against_token_usd": debt_usd, "backstop_buffer_usd": buffer_usd},
                    )
                )
