"""Structural metrics computation for reliability analysis.

Phase 7: Computes 15 global metrics and 5 per-node metrics from the
enriched graph, using the definitions in stratum_core.metrics.

Risk Score Computation (from taxonomy):
  Each CRITICAL finding contributes 25 points, HIGH contributes 10,
  MEDIUM contributes 3, LOW contributes 1. Score is capped at 100.
  Security and reliability scores use the same formula.
"""
from __future__ import annotations

from collections import defaultdict

from stratum.graph.models import EdgeType, NodeType, RiskGraph
from stratum.models import Finding, Severity
from stratum.reliability.traversals import (
    find_paths, detect_cycles, compute_centrality,
    compute_transitive_capabilities,
)


# ---------------------------------------------------------------------------
# Score formula
# ---------------------------------------------------------------------------

SEVERITY_POINTS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 10,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
}


def compute_risk_score(findings: list[Finding]) -> float:
    """Compute 0-100 risk score from findings using linear severity weights.

    Each CRITICAL=25, HIGH=10, MEDIUM=3, LOW=1. Capped at 100.
    """
    raw = sum(
        SEVERITY_POINTS.get(f.severity, 0)
        for f in findings
    )
    return min(raw, 100.0)


# ---------------------------------------------------------------------------
# Gap classification
# ---------------------------------------------------------------------------

def classify_gap(
    security_findings: list[Finding],
    reliability_findings: list[Finding],
) -> tuple[str, float]:
    """Classify the gap between security and reliability dimensions.

    Returns:
        (gap_classification, gap_severity) where gap_severity is the
        absolute difference between security and reliability scores.
    """
    def max_sev(findings: list[Finding]) -> str:
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        if not findings:
            return "LOW"
        return max(findings, key=lambda f: order.get(f.severity.value, 0)).severity.value

    sec_max = max_sev(security_findings)
    rel_max = max_sev(reliability_findings)

    sec_severe = sec_max in ("CRITICAL", "HIGH")
    rel_severe = rel_max in ("CRITICAL", "HIGH")

    sec_score = compute_risk_score(security_findings)
    rel_score = compute_risk_score(reliability_findings)
    gap = abs(sec_score - rel_score)

    if not sec_severe and rel_severe:
        classification = "security_clean_reliability_poor"
    elif not rel_severe and sec_severe:
        classification = "reliability_clean_security_poor"
    elif not sec_severe and not rel_severe:
        classification = "both_clean"
    elif sec_severe and rel_severe:
        classification = "both_poor"
    else:
        classification = "mixed"

    return classification, gap


# ---------------------------------------------------------------------------
# Global metrics
# ---------------------------------------------------------------------------

def compute_global_metrics(
    graph: RiskGraph,
    reliability_findings: list[Finding],
) -> dict[str, float | int]:
    """Compute all 15 global structural metrics.

    Returns dict of metric_id -> value.
    """
    metrics: dict[str, float | int] = {}

    agents = {
        nid: node for nid, node in graph.nodes.items()
        if node.node_type == NodeType.AGENT
    }
    agent_ids = set(agents.keys())

    # --- Chain depth ---
    chain_edges = {EdgeType.DELEGATES_TO.value, EdgeType.FEEDS_INTO.value}
    paths = find_paths(graph, chain_edges, source_filter="agent", min_length=2, max_length=10)
    agent_paths = [
        p for p in paths
        if all(graph.nodes.get(nid) and graph.nodes[nid].node_type == NodeType.AGENT for nid in p)
    ]

    if agent_paths:
        lengths = [len(p) for p in agent_paths]
        metrics["max_chain_depth"] = max(lengths)
        metrics["mean_chain_depth"] = round(sum(lengths) / len(lengths), 2)
    else:
        metrics["max_chain_depth"] = 0
        metrics["mean_chain_depth"] = 0.0

    # --- Human gate coverage ---
    chains_with_gate = 0
    for path in agent_paths:
        has_gate = False
        for nid in path:
            for edge in graph.edges:
                if edge.source == nid and edge.edge_type == EdgeType.GATED_BY:
                    guard = graph.nodes.get(edge.target)
                    if guard and guard.guardrail_kind in ("hitl", "human_in_the_loop"):
                        has_gate = True
                        break
            if has_gate:
                break
        if has_gate:
            chains_with_gate += 1

    metrics["human_gate_coverage"] = round(
        chains_with_gate / max(len(agent_paths), 1), 3
    )

    # --- Irreversible action gate rate ---
    irreversible_caps = [
        nid for nid, node in graph.nodes.items()
        if node.node_type == NodeType.CAPABILITY and node.reversibility == "irreversible"
    ]
    gated_irreversible = 0
    for cap_id in irreversible_caps:
        # Find agent owning this capability
        for edge in graph.edges:
            if edge.edge_type == EdgeType.TOOL_OF and edge.source == cap_id:
                agent_id = edge.target
                for gate_edge in graph.edges:
                    if gate_edge.source == agent_id and gate_edge.edge_type == EdgeType.GATED_BY:
                        guard = graph.nodes.get(gate_edge.target)
                        if guard and guard.guardrail_kind in ("hitl", "human_in_the_loop"):
                            gated_irreversible += 1
                            break
                break

    metrics["irreversible_gate_rate"] = round(
        gated_irreversible / max(len(irreversible_caps), 1), 3
    )

    # --- Schema contract coverage ---
    feeds_into_edges = [
        e for e in graph.edges
        if e.edge_type == EdgeType.FEEDS_INTO
        and graph.nodes.get(e.source) and graph.nodes[e.source].node_type == NodeType.AGENT
        and graph.nodes.get(e.target) and graph.nodes[e.target].node_type == NodeType.AGENT
    ]
    validated = sum(1 for e in feeds_into_edges if e.schema_validated)
    metrics["schema_contract_coverage"] = round(
        validated / max(len(feeds_into_edges), 1), 3
    )

    # --- Error laundering rate ---
    agents_with_downstream = set()
    laundering_agents = set()
    for edge in graph.edges:
        if edge.edge_type == EdgeType.FEEDS_INTO:
            src = graph.nodes.get(edge.source)
            tgt = graph.nodes.get(edge.target)
            if src and tgt and src.node_type == NodeType.AGENT and tgt.node_type == NodeType.AGENT:
                agents_with_downstream.add(edge.source)
                if src.error_handling_pattern in ("default_on_error", "fail_silent"):
                    laundering_agents.add(edge.source)

    metrics["error_laundering_rate"] = round(
        len(laundering_agents) / max(len(agents_with_downstream), 1), 3
    )

    # --- Delegation scope rate ---
    delegation_edges = [e for e in graph.edges if e.edge_type == EdgeType.DELEGATES_TO]
    scoped = sum(1 for e in delegation_edges if e.scoped)
    metrics["delegation_scope_rate"] = round(
        scoped / max(len(delegation_edges), 1), 3
    )

    # --- Observability coverage ---
    observed_agents = set()
    for edge in graph.edges:
        if edge.edge_type == EdgeType.OBSERVED_BY and edge.source in agent_ids:
            observed_agents.add(edge.source)
    metrics["observability_coverage"] = round(
        len(observed_agents) / max(len(agent_ids), 1), 3
    )

    # --- Cycle count ---
    cycles = detect_cycles(graph, node_type_filter="agent")
    metrics["cycle_count"] = len(cycles)

    # --- Timeout coverage ---
    chains_with_timeout = 0
    for path in agent_paths:
        has_timeout = any(
            graph.nodes.get(nid) and graph.nodes[nid].timeout_config
            for nid in path
        )
        if has_timeout:
            chains_with_timeout += 1
    metrics["timeout_coverage"] = round(
        chains_with_timeout / max(len(agent_paths), 1), 3
    )

    # --- Transitive escalation ---
    tc = compute_transitive_capabilities(graph)
    escalation_count = 0
    max_amplification = 1.0
    for agent_id, (direct, effective) in tc.items():
        escalated = effective - direct
        if escalated:
            escalation_count += 1
        if direct:
            ratio = len(effective) / len(direct)
            max_amplification = max(max_amplification, ratio)

    metrics["transitive_escalation_count"] = escalation_count
    metrics["authority_amplification_factor"] = round(max_amplification, 2)

    # --- Simple counts ---
    metrics["agent_count"] = len(agent_ids)
    metrics["reliability_finding_count"] = len(reliability_findings)
    metrics["reliability_score"] = compute_risk_score(reliability_findings)

    return metrics


# ---------------------------------------------------------------------------
# Per-node metrics
# ---------------------------------------------------------------------------

def compute_per_node_metrics(graph: RiskGraph) -> dict[str, dict[str, float | int]]:
    """Compute per-node metrics for all agent nodes.

    Returns dict of agent_id -> {metric_id: value}.
    """
    result: dict[str, dict[str, float | int]] = {}

    agents = {
        nid: node for nid, node in graph.nodes.items()
        if node.node_type == NodeType.AGENT
    }

    if not agents:
        return result

    # Betweenness centrality
    centrality = compute_centrality(graph)

    # In-degree / out-degree
    in_degree: dict[str, int] = defaultdict(int)
    out_degree: dict[str, int] = defaultdict(int)
    for edge in graph.edges:
        if edge.target in agents:
            in_degree[edge.target] += 1
        if edge.source in agents:
            out_degree[edge.source] += 1

    # Capability counts
    tc = compute_transitive_capabilities(graph)

    for agent_id in agents:
        node_metrics: dict[str, float | int] = {}
        node_metrics["betweenness_centrality"] = round(
            centrality.get(agent_id, 0.0), 4
        )
        node_metrics["in_degree"] = in_degree.get(agent_id, 0)
        node_metrics["out_degree"] = out_degree.get(agent_id, 0)

        if agent_id in tc:
            direct, effective = tc[agent_id]
            node_metrics["direct_capability_count"] = len(direct)
            node_metrics["effective_capability_count"] = len(effective)
        else:
            node_metrics["direct_capability_count"] = 0
            node_metrics["effective_capability_count"] = 0

        result[agent_id] = node_metrics

    return result


# ---------------------------------------------------------------------------
# Repo profile
# ---------------------------------------------------------------------------

def build_repo_profile(
    graph: RiskGraph,
    security_findings: list[Finding],
    reliability_findings: list[Finding],
    composite_findings: list[Finding],
    framework: str = "unknown",
) -> dict:
    """Build the repo_profile structure for JSON output.

    Follows the taxonomy-defined repo_profile schema.
    """
    def count_by_severity(findings: list[Finding]) -> dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            if sev in counts:
                counts[sev] += 1
        return counts

    sec_score = compute_risk_score(security_findings)
    rel_score = compute_risk_score(reliability_findings)
    gap_class, gap_sev = classify_gap(security_findings, reliability_findings)

    # Structural counts
    agent_count = sum(1 for n in graph.nodes.values() if n.node_type == NodeType.AGENT)
    tool_count = sum(1 for n in graph.nodes.values() if n.node_type == NodeType.CAPABILITY)
    ds_count = sum(1 for n in graph.nodes.values() if n.node_type == NodeType.DATA_STORE)
    ext_count = sum(1 for n in graph.nodes.values() if n.node_type == NodeType.EXTERNAL_SERVICE)
    mcp_count = sum(1 for n in graph.nodes.values() if n.node_type == NodeType.MCP_SERVER)

    # Chain depth
    chain_edges = {EdgeType.DELEGATES_TO.value, EdgeType.FEEDS_INTO.value}
    paths = find_paths(graph, chain_edges, source_filter="agent", min_length=2, max_length=10)
    max_depth = max((len(p) for p in paths), default=0)

    # Graph density
    n_nodes = len(graph.nodes)
    n_edges = len(graph.edges)
    density = n_edges / max(n_nodes * (n_nodes - 1), 1) if n_nodes > 1 else 0.0

    return {
        "framework": framework,
        "agent_count": agent_count,
        "tool_count": tool_count,
        "data_store_count": ds_count,
        "external_service_count": ext_count,
        "mcp_server_count": mcp_count,
        "max_chain_depth": max_depth,
        "graph_density": round(density, 4),
        "security_findings": count_by_severity(security_findings),
        "security_risk_score": sec_score,
        "security_finding_ids": sorted({f.id for f in security_findings}),
        "reliability_findings": count_by_severity(reliability_findings),
        "reliability_risk_score": rel_score,
        "reliability_finding_ids": sorted({f.id for f in reliability_findings}),
        "composite_findings": count_by_severity(composite_findings),
        "composite_finding_ids": sorted({f.id for f in composite_findings}),
        "gap_classification": gap_class,
        "gap_severity": round(gap_sev, 2),
    }
