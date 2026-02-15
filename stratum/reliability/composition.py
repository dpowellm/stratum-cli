"""Composition engine — compositional severity escalation.

Phase 6: 7 within-reliability compositions (STRAT-COMP) and
6 cross-dataset compositions (STRAT-XCOMP).

Compositions fire when two constituent findings co-occur on the same
repository AND share at least one affected node (overlapping subgraphs).
Composite findings are first-class findings with their own severity,
affected subgraph, and evidence.
"""
from __future__ import annotations

from stratum.models import Confidence, Finding, RiskCategory, Severity


# ---------------------------------------------------------------------------
# Composition tables
# ---------------------------------------------------------------------------

# Within-reliability compositions
COMP_TABLE: list[dict] = [
    {
        "id": "STRAT-COMP-001",
        "title": "Unsupervised Chain With Authority Escalation",
        "finding_a": "STRAT-DC-001",
        "finding_b": "STRAT-EA-001",
        "severity": Severity.CRITICAL,
        "description": (
            "Unsupervised decision chain also has transitive authority escalation — "
            "agents in the chain can trigger capabilities never directly assigned to them, "
            "with no human oversight anywhere."
        ),
        "remediation": (
            "Add human gates (human_input=True or interrupt_before) AND scope "
            "delegation with explicit tools= parameter on each Task."
        ),
    },
    {
        "id": "STRAT-COMP-002",
        "title": "Error Laundering in Unsupervised Chain",
        "finding_a": "STRAT-SI-001",
        "finding_b": "STRAT-DC-001",
        "severity": Severity.CRITICAL,
        "description": (
            "Silently laundered errors propagate through an unsupervised decision chain — "
            "default values treated as valid inputs by downstream agents with no human "
            "to catch the corruption."
        ),
        "remediation": (
            "Replace default-on-error with explicit error types. Add human checkpoints "
            "at agent boundaries where error handling changes."
        ),
    },
    {
        "id": "STRAT-COMP-003",
        "title": "Unmonitored Volume in Regulated Domain",
        "finding_a": "STRAT-AB-001",
        "finding_b": "STRAT-AB-003",
        "severity": Severity.CRITICAL,
        "description": (
            "No aggregate volume monitoring combined with regulatory blindness — "
            "regulated operations can scale unchecked without alerting."
        ),
        "remediation": (
            "Implement volume monitoring with regulatory-aware thresholds. "
            "Add compliance-specific alerting rules."
        ),
    },
    {
        "id": "STRAT-COMP-004",
        "title": "Conflicting Agents With Uncoordinated Writes",
        "finding_a": "STRAT-OC-001",
        "finding_b": "STRAT-OC-002",
        "severity": Severity.CRITICAL,
        "description": (
            "Agents with conflicting objectives write to the same shared state "
            "without coordination — their competing writes corrupt shared data."
        ),
        "remediation": (
            "Align agent objectives or add concurrency control (locking, versioning) "
            "on shared data stores."
        ),
    },
    {
        "id": "STRAT-COMP-005",
        "title": "Stale Context in Regulated Domain",
        "finding_a": "STRAT-SI-002",
        "finding_b": "STRAT-AB-003",
        "severity": Severity.CRITICAL,
        "description": (
            "Stale knowledge base context combined with regulatory blindness — "
            "decisions based on outdated data in a domain requiring current information."
        ),
        "remediation": (
            "Add freshness validation (TTL, timestamp checks) on knowledge bases "
            "and implement regulatory threshold monitoring."
        ),
    },
    {
        "id": "STRAT-COMP-006",
        "title": "Irreversible Actions via Authority Escalation",
        "finding_a": "STRAT-DC-002",
        "finding_b": "STRAT-EA-001",
        "severity": Severity.CRITICAL,
        "description": (
            "Irreversible capabilities are triggerable through delegation chains "
            "by agents never intended to have them — authority escalation reaches "
            "irreversible actions with no checkpoint."
        ),
        "remediation": (
            "Add human approval gates before irreversible actions AND scope "
            "delegation to prevent transitive access to irreversible tools."
        ),
    },
    {
        "id": "STRAT-COMP-007",
        "title": "Signal Filtering in Unobservable Chain",
        "finding_a": "STRAT-SI-005",
        "finding_b": "STRAT-DC-003",
        "severity": Severity.CRITICAL,
        "description": (
            "Signal filtering drops information in an agent chain that already "
            "exceeds observability — filtered data is permanently lost with no "
            "way to audit."
        ),
        "remediation": (
            "Add per-agent observability before filtering steps. "
            "Log pre-filter and post-filter signals for audit."
        ),
    },
]

# Mapping from taxonomy STRATUM-SEC-* IDs to potential legacy finding IDs.
# The composition engine matches on any of these IDs.
SEC_ID_ALIASES: dict[str, list[str]] = {
    "STRATUM-SEC-001": ["STRATUM-SEC-001", "STRATUM-001"],
    "STRATUM-SEC-002": ["STRATUM-SEC-002", "STRATUM-002"],
    "STRATUM-SEC-003": ["STRATUM-SEC-003", "ENV-001", "ENV-002"],
    "STRATUM-SEC-004": ["STRATUM-SEC-004", "STRATUM-CR05"],
    "STRATUM-SEC-005": ["STRATUM-SEC-005", "EVAL-001"],
}

# Cross-dataset compositions (security x reliability)
XCOMP_TABLE: list[dict] = [
    {
        "id": "STRAT-XCOMP-001",
        "title": "Unguarded Data Path Through Unsupervised Chain",
        "security_finding": "STRATUM-SEC-001",
        "reliability_finding": "STRAT-DC-001",
        "severity": Severity.CRITICAL,
        "description": (
            "Unguarded data flows through an unsupervised decision chain to an "
            "external service — no validation AND no human oversight on the path."
        ),
        "remediation": (
            "Add input validation/guardrails on the data path AND human checkpoints "
            "in the decision chain."
        ),
    },
    {
        "id": "STRAT-XCOMP-002",
        "title": "Unvalidated Input Laundered Through Error Handling",
        "security_finding": "STRATUM-SEC-002",
        "reliability_finding": "STRAT-SI-001",
        "severity": Severity.CRITICAL,
        "description": (
            "Invalid external input is silently laundered through default-on-error "
            "handling into downstream agent decisions — input never validated, "
            "error never surfaced."
        ),
        "remediation": (
            "Add input validation at system boundaries. Replace default-on-error "
            "with explicit error propagation."
        ),
    },
    {
        "id": "STRAT-XCOMP-003",
        "title": "Credentials Exposed via Authority Escalation",
        "security_finding": "STRATUM-SEC-003",
        "reliability_finding": "STRAT-EA-001",
        "severity": Severity.CRITICAL,
        "description": (
            "Exposed credentials are accessible through delegation chain by agents "
            "never intended to have them — the escalation path reaches the credentials."
        ),
        "remediation": (
            "Rotate exposed credentials immediately. Scope delegation to prevent "
            "transitive access to credential-bearing agents."
        ),
    },
    {
        "id": "STRAT-XCOMP-004",
        "title": "Over-Permissioned Agent With Irreversible Capabilities",
        "security_finding": "STRATUM-SEC-004",
        "reliability_finding": "STRAT-DC-002",
        "severity": Severity.CRITICAL,
        "description": (
            "Over-provisioned agent has irreversible capabilities with no human gate — "
            "maximum blast radius with no checkpoint."
        ),
        "remediation": (
            "Reduce agent permissions to minimum required. Add human approval gate "
            "before irreversible actions."
        ),
    },
    {
        "id": "STRAT-XCOMP-005",
        "title": "Unguarded Data Path With No Volume Monitoring",
        "security_finding": "STRATUM-SEC-001",
        "reliability_finding": "STRAT-AB-001",
        "severity": Severity.CRITICAL,
        "description": (
            "Unguarded outbound data path with no volume monitoring — potential for "
            "mass data exposure at scale with no detection."
        ),
        "remediation": (
            "Add guardrails on outbound data paths AND implement aggregate volume "
            "monitoring with alerting."
        ),
    },
    {
        "id": "STRAT-XCOMP-006",
        "title": "Unvalidated Input With Confidence Amplification",
        "security_finding": "STRATUM-SEC-002",
        "reliability_finding": "STRAT-SI-003",
        "severity": Severity.HIGH,
        "description": (
            "Unvalidated input enters an agent chain that amplifies confidence at "
            "each hop — garbage in, high-confidence garbage out."
        ),
        "remediation": (
            "Validate input at system boundaries. Propagate uncertainty metadata "
            "through agent chains."
        ),
    },
]


# ---------------------------------------------------------------------------
# Composition engine
# ---------------------------------------------------------------------------

def _extract_affected_nodes(finding: Finding) -> set[str]:
    """Extract node identifiers from a finding's path and evidence."""
    nodes: set[str] = set()
    # Path field may contain "label1 → label2 → label3"
    if finding.path:
        for part in finding.path.split(" → "):
            part = part.strip()
            if part:
                nodes.add(part)
    # Evidence may contain "file:line" references — not node IDs, skip
    return nodes


def _findings_share_subgraph(finding_a: Finding, finding_b: Finding) -> bool:
    """Check if two findings share at least one affected node.

    Since findings store labels in path (not raw IDs), we compare labels.
    For safety, if either finding has no extractable nodes, we still fire
    (same-repo co-occurrence is sufficient for composition).
    """
    nodes_a = _extract_affected_nodes(finding_a)
    nodes_b = _extract_affected_nodes(finding_b)

    # If we can't extract nodes from either, treat co-occurrence as overlap
    if not nodes_a or not nodes_b:
        return True

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

    # Merge paths
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
    """Run within-reliability compositions (STRAT-COMP).

    For each pair in the COMP_TABLE that co-occurs with overlapping subgraphs,
    generate a composite finding with escalated severity.
    """
    composites: list[Finding] = []
    fired: set[str] = set()

    for comp in COMP_TABLE:
        matches_a = _find_findings_by_id(reliability_findings, comp["finding_a"])
        matches_b = _find_findings_by_id(reliability_findings, comp["finding_b"])

        if not matches_a or not matches_b:
            continue

        # Check for overlapping subgraphs
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
    """Run cross-dataset compositions (STRAT-XCOMP).

    Requires both security and reliability findings from the same graph.
    Fires when a security finding and a reliability finding share at least
    one affected node.
    """
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
    """Run all compositions: within-reliability + cross-dataset.

    Returns list of composite findings (STRAT-COMP + STRAT-XCOMP).
    """
    composites: list[Finding] = []
    composites.extend(compose_within_reliability(reliability_findings))
    composites.extend(compose_cross_dataset(security_findings, reliability_findings))
    return composites
