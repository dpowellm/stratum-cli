"""Composition engine — compositional severity escalation.

7 within-reliability compositions (STRAT-COMP) and
6 cross-dataset compositions (STRAT-XCOMP) per spec Section 10.

Compositions fire when two constituent findings co-occur on the same
repository AND share at least one affected node (overlapping subgraphs).
"""
from __future__ import annotations

from stratum.models import Confidence, Finding, RiskCategory, Severity


# ---------------------------------------------------------------------------
# Composition tables (spec Section 10)
# ---------------------------------------------------------------------------

# Within-reliability compositions
COMP_TABLE: list[dict] = [
    {
        "id": "STRAT-COMP-001",
        "title": "Unsupervised Chain With Silent Error Propagation",
        "finding_a": "STRAT-DC-001",
        "finding_b": "STRAT-SI-001",
        "severity": Severity.CRITICAL,
        "description": (
            "Unsupervised decision chain WITH silent error propagation through "
            "the same chain. The chain can make bad decisions AND no one sees the errors."
        ),
        "remediation": (
            "Add human checkpoints in the chain AND replace default-on-error "
            "with explicit error propagation."
        ),
    },
    {
        "id": "STRAT-COMP-002",
        "title": "Misaligned Objectives Competing for Shared Resources",
        "finding_a": "STRAT-OC-001",
        "finding_b": "STRAT-OC-002",
        "severity": Severity.CRITICAL,
        "description": (
            "Agents with misaligned objectives competing for shared resources. "
            "Conflicting goals amplified by resource contention."
        ),
        "remediation": (
            "Align agent objectives or add arbitration. Implement shared rate "
            "limiting with priority ordering."
        ),
    },
    {
        "id": "STRAT-COMP-003",
        "title": "Unsupervised Chain With Implicit Authority Escalation",
        "finding_a": "STRAT-DC-001",
        "finding_b": "STRAT-EA-001",
        "severity": Severity.CRITICAL,
        "description": (
            "Unsupervised chain where agents exercise authority they weren't "
            "directly granted. Escalation without oversight."
        ),
        "remediation": (
            "Add human gates AND scope delegation with explicit tools= parameter."
        ),
    },
    {
        "id": "STRAT-COMP-004",
        "title": "Silent Errors Across Unvalidated Data Boundaries",
        "finding_a": "STRAT-SI-001",
        "finding_b": "STRAT-SI-004",
        "severity": Severity.CRITICAL,
        "description": (
            "Errors propagate silently across unvalidated data boundaries. "
            "No schema contracts AND no error visibility."
        ),
        "remediation": (
            "Add schema validation on data flows AND explicit error propagation."
        ),
    },
    {
        "id": "STRAT-COMP-005",
        "title": "Unbounded Delegation in Recursive Loop",
        "finding_a": "STRAT-EA-003",
        "finding_b": "STRAT-DC-006",
        "severity": Severity.CRITICAL,
        "description": (
            "Unbounded delegation in a recursive loop. Unconstrained agents "
            "delegating recursively without depth bounds."
        ),
        "remediation": (
            "Scope delegation AND set max_iterations on recursive delegation cycles."
        ),
    },
    {
        "id": "STRAT-COMP-006",
        "title": "Unbounded Autonomous Execution of Irreversible Actions",
        "finding_a": "STRAT-AB-001",
        "finding_b": "STRAT-DC-002",
        "severity": Severity.CRITICAL,
        "description": (
            "Unbounded autonomous execution of irreversible actions. No rate "
            "limiting AND no approval gate on destructive capabilities."
        ),
        "remediation": (
            "Add rate limiting AND human approval gates before irreversible actions."
        ),
    },
    {
        "id": "STRAT-COMP-007",
        "title": "Single Point of Failure That Swallows Errors",
        "finding_a": "STRAT-DC-005",
        "finding_b": "STRAT-SI-006",
        "severity": Severity.CRITICAL,
        "description": (
            "Single point of failure that also swallows errors. Bottleneck agent "
            "silently drops errors at trust boundary."
        ),
        "remediation": (
            "Add redundancy for the bottleneck AND replace fail_silent with "
            "explicit error propagation."
        ),
    },
]

# Mapping from spec STRATUM-NNN IDs to potential finding IDs in the scanner.
SEC_ID_ALIASES: dict[str, list[str]] = {
    "STRATUM-001": ["STRATUM-001", "STRATUM-SEC-001"],
    "STRATUM-002": ["STRATUM-002", "STRATUM-SEC-002", "ENV-001", "ENV-002"],
    "STRATUM-003": ["STRATUM-003", "STRATUM-SEC-003"],
    "STRATUM-004": ["STRATUM-004", "STRATUM-SEC-004", "STRATUM-CR05"],
    "STRATUM-005": ["STRATUM-005", "STRATUM-SEC-005", "EVAL-001"],
}

# Cross-dataset compositions (security x reliability) — spec Section 10
XCOMP_TABLE: list[dict] = [
    {
        "id": "STRAT-XCOMP-001",
        "title": "Unguarded Data Path Through Unsupervised Chain",
        "security_finding": "STRATUM-001",
        "reliability_finding": "STRAT-DC-001",
        "severity": Severity.CRITICAL,
        "description": (
            "The chain can exfiltrate data AND no human sees it. "
            "Unguarded data path through an unsupervised decision chain."
        ),
        "remediation": (
            "Add guardrails on the data path AND human checkpoints in the chain."
        ),
    },
    {
        "id": "STRAT-XCOMP-002",
        "title": "Invalid Inputs With Silent Error Propagation",
        "security_finding": "STRATUM-003",
        "reliability_finding": "STRAT-SI-001",
        "severity": Severity.CRITICAL,
        "description": (
            "Invalid inputs enter AND errors from bad data propagate silently. "
            "Missing input validation combined with error laundering."
        ),
        "remediation": (
            "Add input validation at system boundaries. Replace default-on-error "
            "with explicit error propagation."
        ),
    },
    {
        "id": "STRAT-XCOMP-003",
        "title": "Credentials Accessible via Unauthorized Delegation",
        "security_finding": "STRATUM-005",
        "reliability_finding": "STRAT-EA-001",
        "severity": Severity.CRITICAL,
        "description": (
            "Credential accessible via delegation chain that wasn't directly "
            "authorized. Implicit authority reaches sensitive credentials."
        ),
        "remediation": (
            "Rotate credentials. Scope delegation to prevent transitive access."
        ),
    },
    {
        "id": "STRAT-XCOMP-004",
        "title": "Hardcoded Credentials With No Audit Trail",
        "security_finding": "STRATUM-002",
        "reliability_finding": "STRAT-AB-003",
        "severity": Severity.CRITICAL,
        "description": (
            "Hardcoded credentials used by agent with no audit logging. "
            "Credential usage is invisible."
        ),
        "remediation": (
            "Move credentials to secure vault AND add audit logging."
        ),
    },
    {
        "id": "STRAT-XCOMP-005",
        "title": "Over-Permissioned Tool via Unsupervised Delegation",
        "security_finding": "STRATUM-004",
        "reliability_finding": "STRAT-DC-001",
        "severity": Severity.CRITICAL,
        "description": (
            "Over-permissioned tool reachable through unsupervised delegation. "
            "Excessive capability accessible without human oversight."
        ),
        "remediation": (
            "Reduce tool permissions AND add human checkpoints in the chain."
        ),
    },
    {
        "id": "STRAT-XCOMP-006",
        "title": "Unguarded Data Path With No Schema Validation",
        "security_finding": "STRATUM-001",
        "reliability_finding": "STRAT-SI-004",
        "severity": Severity.HIGH,
        "description": (
            "Unguarded data path with no schema validation at boundaries. "
            "Data flows unvalidated and uncontrolled."
        ),
        "remediation": (
            "Add guardrails on data paths AND schema validation at boundaries."
        ),
    },
]


# ---------------------------------------------------------------------------
# Composition engine
# ---------------------------------------------------------------------------

def _extract_affected_nodes(finding: Finding) -> set[str]:
    """Extract node identifiers from a finding's path and evidence."""
    nodes: set[str] = set()
    if finding.path:
        for part in finding.path.split(" \u2192 "):
            part = part.strip()
            if part:
                nodes.add(part)
    return nodes


def _findings_share_subgraph(finding_a: Finding, finding_b: Finding) -> bool:
    """Check if two findings share at least one affected node."""
    nodes_a = _extract_affected_nodes(finding_a)
    nodes_b = _extract_affected_nodes(finding_b)
    if not nodes_a or not nodes_b:
        return True  # Co-occurrence is sufficient if nodes can't be extracted
    return bool(nodes_a & nodes_b)


def _find_findings_by_id(
    findings: list[Finding],
    finding_id: str,
    aliases: dict[str, list[str]] | None = None,
) -> list[Finding]:
    """Find all findings matching an ID (with optional alias resolution)."""
    ids_to_check = {finding_id}
    if aliases and finding_id in aliases:
        ids_to_check.update(aliases[finding_id])
    return [f for f in findings if f.id in ids_to_check]


def _make_composite(
    comp_id: str,
    title: str,
    severity: Severity,
    description: str,
    remediation: str,
    constituent_a: Finding,
    constituent_b: Finding,
) -> Finding:
    """Create a composite finding from two constituent findings."""
    evidence = []
    evidence.append(f"Constituent A: {constituent_a.id} ({constituent_a.title})")
    evidence.append(f"Constituent B: {constituent_b.id} ({constituent_b.title})")
    evidence.extend(constituent_a.evidence[:2])
    evidence.extend(constituent_b.evidence[:2])

    path_parts = []
    if constituent_a.path:
        path_parts.append(constituent_a.path)
    if constituent_b.path:
        path_parts.append(constituent_b.path)
    path = " | ".join(path_parts)

    return Finding(
        id=comp_id,
        severity=severity,
        confidence=Confidence.CONFIRMED,
        category=RiskCategory.COMPOUNDING,
        title=title,
        path=path,
        description=description,
        evidence=evidence[:5],
        scenario=description,
        remediation=remediation,
        effort="high",
        finding_class="reliability",
    )


def compose_within_reliability(
    reliability_findings: list[Finding],
) -> list[Finding]:
    """Run within-reliability compositions (STRAT-COMP)."""
    composites: list[Finding] = []
    fired: set[str] = set()

    for comp in COMP_TABLE:
        matches_a = _find_findings_by_id(reliability_findings, comp["finding_a"])
        matches_b = _find_findings_by_id(reliability_findings, comp["finding_b"])

        if not matches_a or not matches_b:
            continue

        for fa in matches_a:
            for fb in matches_b:
                if _findings_share_subgraph(fa, fb):
                    if comp["id"] not in fired:
                        fired.add(comp["id"])
                        composites.append(_make_composite(
                            comp["id"],
                            comp["title"],
                            comp["severity"],
                            comp["description"],
                            comp["remediation"],
                            fa,
                            fb,
                        ))
                    break
            if comp["id"] in fired:
                break

    return composites


def compose_cross_dataset(
    security_findings: list[Finding],
    reliability_findings: list[Finding],
) -> list[Finding]:
    """Run cross-dataset compositions (STRAT-XCOMP)."""
    composites: list[Finding] = []
    fired: set[str] = set()

    for xcomp in XCOMP_TABLE:
        sec_matches = _find_findings_by_id(
            security_findings,
            xcomp["security_finding"],
            aliases=SEC_ID_ALIASES,
        )
        rel_matches = _find_findings_by_id(
            reliability_findings,
            xcomp["reliability_finding"],
        )

        if not sec_matches or not rel_matches:
            continue

        for fs in sec_matches:
            for fr in rel_matches:
                if _findings_share_subgraph(fs, fr):
                    if xcomp["id"] not in fired:
                        fired.add(xcomp["id"])
                        composites.append(_make_composite(
                            xcomp["id"],
                            xcomp["title"],
                            xcomp["severity"],
                            xcomp["description"],
                            xcomp["remediation"],
                            fs,
                            fr,
                        ))
                    break
            if xcomp["id"] in fired:
                break

    return composites


def run_compositions(
    security_findings: list[Finding],
    reliability_findings: list[Finding],
) -> list[Finding]:
    """Run all compositions: within-reliability + cross-dataset."""
    composites: list[Finding] = []
    composites.extend(compose_within_reliability(reliability_findings))
    composites.extend(compose_cross_dataset(security_findings, reliability_findings))
    return composites
