"""Structural anomaly detection for reliability analysis.

Phase 8: Framework-relative z-scores, topological anomalies, and
novel motif detection. Anomalies are surfaced as low-confidence
advisory findings — they don't have fixed IDs but flag unusual
structural patterns that may warrant review.
"""
from __future__ import annotations

import math
from collections import defaultdict

from stratum.graph.models import EdgeType, NodeType, RiskGraph
from stratum.models import Confidence, Finding, RiskCategory, Severity


# ---------------------------------------------------------------------------
# Reference statistics (from taxonomy 5A hypothetical baselines)
# ---------------------------------------------------------------------------

# Framework-relative reference distributions (mean, stddev).
# These are bootstrapped from the taxonomy's hypothetical benchmarks
# and will be updated as mass-scan data becomes available.
REFERENCE_STATS: dict[str, tuple[float, float]] = {
    "agent_count": (3.7, 2.5),
    "tool_per_agent_ratio": (5.2, 3.0),
    "max_chain_depth": (3.0, 1.5),
    "delegation_edges_per_agent": (1.2, 0.8),
    "external_service_ratio": (0.34, 0.2),
    "guardrail_coverage": (0.18, 0.15),
    "observability_coverage": (0.29, 0.2),
}


def _z_score(value: float, mean: float, std: float) -> float:
    """Compute z-score. Returns 0 if std is 0."""
    if std == 0:
        return 0.0
    return (value - mean) / std


# ---------------------------------------------------------------------------
# Anomaly types
# ---------------------------------------------------------------------------

def detect_structural_anomalies(graph: RiskGraph) -> list[Finding]:
    """Run all anomaly detection passes.

    Returns advisory findings for unusual structural patterns.
    """
    findings: list[Finding] = []
    findings.extend(_z_score_anomalies(graph))
    findings.extend(_topological_anomalies(graph))
    findings.extend(_motif_anomalies(graph))
    return findings


def _z_score_anomalies(graph: RiskGraph) -> list[Finding]:
    """Detect metrics that deviate significantly from framework baselines."""
    agents = {nid for nid, n in graph.nodes.items() if n.node_type == NodeType.AGENT}
    if not agents:
        return []

    capabilities = {nid for nid, n in graph.nodes.items() if n.node_type == NodeType.CAPABILITY}
    externals = {nid for nid, n in graph.nodes.items()
                 if n.node_type == NodeType.EXTERNAL_SERVICE}
    guardrails = {nid for nid, n in graph.nodes.items() if n.node_type == NodeType.GUARDRAIL}

    # Compute observed values
    observed: dict[str, float] = {
        "agent_count": len(agents),
        "tool_per_agent_ratio": len(capabilities) / max(len(agents), 1),
        "external_service_ratio": len(externals) / max(len(agents), 1),
        "guardrail_coverage": len(guardrails) / max(len(agents), 1),
    }

    # Chain depth
    from stratum.reliability.traversals import find_paths
    chain_edges = {EdgeType.DELEGATES_TO.value, EdgeType.FEEDS_INTO.value}
    paths = find_paths(graph, chain_edges, source_filter="agent", min_length=2, max_length=10)
    if paths:
        observed["max_chain_depth"] = max(len(p) for p in paths)
    else:
        observed["max_chain_depth"] = 0

    # Delegation edges per agent
    delegation_count = sum(
        1 for e in graph.edges
        if e.edge_type in (EdgeType.DELEGATES_TO, EdgeType.FEEDS_INTO)
    )
    observed["delegation_edges_per_agent"] = delegation_count / max(len(agents), 1)

    # Observability coverage
    observed_agents = {
        e.source for e in graph.edges
        if e.edge_type == EdgeType.OBSERVED_BY and e.source in agents
    }
    observed["observability_coverage"] = len(observed_agents) / max(len(agents), 1)

    findings: list[Finding] = []
    z_threshold = 2.0  # Flag at 2 standard deviations

    for metric_id, value in observed.items():
        if metric_id not in REFERENCE_STATS:
            continue
        mean, std = REFERENCE_STATS[metric_id]
        z = _z_score(value, mean, std)

        if abs(z) < z_threshold:
            continue

        direction = "above" if z > 0 else "below"
        severity = Severity.MEDIUM if abs(z) > 3.0 else Severity.LOW

        findings.append(Finding(
            id="STRAT-ANOMALY-ZSCORE",
            severity=severity,
            confidence=Confidence.HEURISTIC,
            category=RiskCategory.OPERATIONAL,
            title=f"Structural Anomaly: {metric_id}",
            path="",
            description=(
                f"{metric_id} = {value:.2f} is {abs(z):.1f} standard deviations "
                f"{direction} the reference baseline (mean={mean:.2f}, std={std:.2f}). "
                f"This may indicate an unusual architecture pattern."
            ),
            evidence=[f"z-score: {z:.2f}", f"observed: {value:.2f}", f"baseline: {mean:.2f}"],
            remediation="Review the architecture for this metric. High deviation is not "
                        "necessarily bad but warrants inspection.",
            effort="low",
            finding_class="reliability",
        ))

    return findings


def _topological_anomalies(graph: RiskGraph) -> list[Finding]:
    """Detect topological anomalies: isolated agents, disconnected subgraphs,
    star topologies, extreme fan-out."""
    findings: list[Finding] = []
    agents = {nid for nid, n in graph.nodes.items() if n.node_type == NodeType.AGENT}

    if len(agents) < 2:
        return []

    # Build undirected adjacency for agents
    adj: dict[str, set[str]] = defaultdict(set)
    for edge in graph.edges:
        if edge.source in agents and edge.target in agents:
            adj[edge.source].add(edge.target)
            adj[edge.target].add(edge.source)

    # Detect isolated agents (no connections to other agents)
    connected = set()
    for nid in agents:
        if adj.get(nid):
            connected.add(nid)
    isolated = agents - connected

    if isolated and len(isolated) < len(agents):
        labels = [graph.nodes[nid].label for nid in isolated if nid in graph.nodes]
        findings.append(Finding(
            id="STRAT-ANOMALY-ISOLATED",
            severity=Severity.LOW,
            confidence=Confidence.HEURISTIC,
            category=RiskCategory.OPERATIONAL,
            title="Isolated Agent(s) in Multi-Agent System",
            path=", ".join(labels[:3]),
            description=(
                f"{len(isolated)} agent(s) have no delegation or data flow connections "
                f"to other agents: {', '.join(labels[:3])}. "
                f"These may be unused or misconfigured."
            ),
            evidence=[f"Isolated: {', '.join(labels[:3])}"],
            remediation="Verify isolated agents are intentionally standalone. "
                        "Connect them to the workflow if needed.",
            effort="low",
            finding_class="reliability",
        ))

    # Detect star topology (one agent connected to all others)
    for nid in agents:
        neighbors = adj.get(nid, set())
        if len(neighbors) >= len(agents) - 1 and len(agents) >= 4:
            node = graph.nodes.get(nid)
            if node:
                findings.append(Finding(
                    id="STRAT-ANOMALY-STAR",
                    severity=Severity.LOW,
                    confidence=Confidence.HEURISTIC,
                    category=RiskCategory.OPERATIONAL,
                    title="Star Topology Detected",
                    path=node.label,
                    description=(
                        f"{node.label} is connected to all {len(neighbors)} other agents. "
                        f"This creates a single point of failure."
                    ),
                    evidence=[f"Hub agent: {node.label}", f"Connections: {len(neighbors)}"],
                    remediation="Consider distributing connections across multiple agents "
                                "to reduce single-point-of-failure risk.",
                    effort="med",
                    finding_class="reliability",
                ))

    # Detect extreme fan-out (agent delegates to >= 5 others)
    out_degree: dict[str, int] = defaultdict(int)
    for edge in graph.edges:
        if edge.edge_type in (EdgeType.DELEGATES_TO, EdgeType.FEEDS_INTO):
            if edge.source in agents:
                out_degree[edge.source] += 1

    for nid, degree in out_degree.items():
        if degree >= 5:
            node = graph.nodes.get(nid)
            if node:
                findings.append(Finding(
                    id="STRAT-ANOMALY-FANOUT",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HEURISTIC,
                    category=RiskCategory.OPERATIONAL,
                    title="Extreme Fan-Out Delegation",
                    path=node.label,
                    description=(
                        f"{node.label} delegates to {degree} downstream agents. "
                        f"This exceeds typical multi-agent patterns and may indicate "
                        f"coordination challenges."
                    ),
                    evidence=[f"Fan-out degree: {degree}"],
                    remediation="Consider hierarchical delegation with intermediate "
                                "coordinator agents.",
                    effort="med",
                    finding_class="reliability",
                ))

    return findings[:5]  # Cap anomaly findings


def _motif_anomalies(graph: RiskGraph) -> list[Finding]:
    """Detect novel graph motifs: diamond patterns, long linear chains,
    bidirectional delegation."""
    findings: list[Finding] = []
    agents = {nid for nid, n in graph.nodes.items() if n.node_type == NodeType.AGENT}

    if len(agents) < 3:
        return []

    # Build directed adjacency for agents
    adj: dict[str, set[str]] = defaultdict(set)
    for edge in graph.edges:
        if edge.edge_type in (EdgeType.DELEGATES_TO, EdgeType.FEEDS_INTO):
            if edge.source in agents and edge.target in agents:
                adj[edge.source].add(edge.target)

    # Detect bidirectional delegation (A delegates to B AND B delegates to A)
    bidirectional_pairs: list[tuple[str, str]] = []
    seen = set()
    for src, targets in adj.items():
        for tgt in targets:
            if src in adj.get(tgt, set()):
                pair = (min(src, tgt), max(src, tgt))
                if pair not in seen:
                    seen.add(pair)
                    bidirectional_pairs.append(pair)

    for a, b in bidirectional_pairs[:2]:
        node_a = graph.nodes.get(a)
        node_b = graph.nodes.get(b)
        if node_a and node_b:
            findings.append(Finding(
                id="STRAT-ANOMALY-BIDIRECTIONAL",
                severity=Severity.MEDIUM,
                confidence=Confidence.HEURISTIC,
                category=RiskCategory.OPERATIONAL,
                title="Bidirectional Delegation Between Agents",
                path=f"{node_a.label} \u2194 {node_b.label}",
                description=(
                    f"{node_a.label} and {node_b.label} delegate to each other. "
                    f"This creates a tight coupling and potential infinite loop."
                ),
                evidence=[
                    f"{node_a.label} \u2192 {node_b.label}",
                    f"{node_b.label} \u2192 {node_a.label}",
                ],
                remediation="Break bidirectional delegation. Designate one agent as "
                            "the coordinator and the other as the worker.",
                effort="med",
                finding_class="reliability",
            ))

    # Detect diamond pattern (A->B, A->C, B->D, C->D)
    for source in agents:
        targets = adj.get(source, set())
        if len(targets) < 2:
            continue
        # Check if any two targets share a common downstream
        targets_list = list(targets)
        for i, t1 in enumerate(targets_list):
            downstream_1 = adj.get(t1, set())
            for t2 in targets_list[i + 1:]:
                downstream_2 = adj.get(t2, set())
                common = downstream_1 & downstream_2
                if common:
                    merge_node = next(iter(common))
                    src_label = graph.nodes[source].label if source in graph.nodes else source
                    merge_label = graph.nodes[merge_node].label if merge_node in graph.nodes else merge_node
                    findings.append(Finding(
                        id="STRAT-ANOMALY-DIAMOND",
                        severity=Severity.LOW,
                        confidence=Confidence.HEURISTIC,
                        category=RiskCategory.OPERATIONAL,
                        title="Diamond Delegation Pattern",
                        path=f"{src_label} \u2192 ... \u2192 {merge_label}",
                        description=(
                            f"Diamond pattern: {src_label} fans out then merges at "
                            f"{merge_label}. This requires careful result reconciliation."
                        ),
                        evidence=[
                            f"Fan-out from: {src_label}",
                            f"Merge at: {merge_label}",
                        ],
                        remediation="Ensure the merge node properly reconciles "
                                    "potentially conflicting outputs.",
                        effort="low",
                        finding_class="reliability",
                    ))
                    break
            if len(findings) >= 3:
                break

    return findings[:5]
