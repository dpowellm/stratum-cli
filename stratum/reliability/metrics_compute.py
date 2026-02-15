"""Structural metrics computation for reliability analysis.

Computes ~35 global metrics, 10 per-node metrics from the enriched graph,
plus risk scoring and gap classification per spec Section 7 and Section 13.

Risk Score Computation:
  CRITICAL*25 + HIGH*15 + MEDIUM*8 + LOW*3
  + COMP bonus (10 each) + XCOMP bonus (15 each)
  + structural anomaly bonus (3 each)
  Capped at 100.

Gap Classification (threshold=30):
  both_clean | security_clean_reliability_poor | security_poor_reliability_clean | both_poor
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
# Score formula (spec Section 13)
# ---------------------------------------------------------------------------

SEVERITY_POINTS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
}


def compute_risk_score(
    findings: list[Finding],
    compositions: list[Finding] | None = None,
    anomaly_count: int = 0,
) -> float:
    """Compute 0-100 risk score from findings using spec formula.

    reliability_risk_score = sum of:
      CRITICAL * 25 + HIGH * 15 + MEDIUM * 8 + LOW * 3
      + each COMP adds 10, each XCOMP adds 15
      + each topological anomaly adds 3
    Capped at 100.
    """
    raw = sum(
        SEVERITY_POINTS.get(f.severity, 0)
        for f in findings
    )

    if compositions:
        for comp in compositions:
            comp_id = comp.id if hasattr(comp, 'id') else ""
            if "XCOMP" in comp_id:
                raw += 15
            elif "COMP" in comp_id:
                raw += 10

    raw += anomaly_count * 3

    return min(raw, 100.0)


# ---------------------------------------------------------------------------
# Gap classification (spec Section 13)
# ---------------------------------------------------------------------------

def classify_gap(
    security_score: float,
    reliability_score: float,
) -> str:
    """Classify the gap between security and reliability dimensions.

    Uses threshold-based logic per spec:
    - sec_threshold = 30 (poor if above)
    - rel_threshold = 30 (poor if above)
    """
    sec_threshold = 30
    rel_threshold = 30

    if security_score <= sec_threshold and reliability_score <= rel_threshold:
        return "both_clean"
    elif security_score <= sec_threshold and reliability_score > rel_threshold:
        return "security_clean_reliability_poor"  # THE BLIND SPOT
    elif security_score > sec_threshold and reliability_score <= rel_threshold:
        return "security_poor_reliability_clean"
    else:
        return "both_poor"


# ---------------------------------------------------------------------------
# Global metrics (spec Section 7 — ~35 fields)
# ---------------------------------------------------------------------------

def compute_global_metrics(
    graph: RiskGraph,
    reliability_findings: list[Finding] | None = None,
) -> dict[str, float | int]:
    """Compute all ~35 global structural metrics per spec Section 7.

    Returns dict of metric_name -> value.
    """
    if reliability_findings is None:
        reliability_findings = []

    metrics: dict[str, float | int] = {}

    agents = {
        nid: node for nid, node in graph.nodes.items()
        if node.node_type == NodeType.AGENT
    }
    agent_ids = set(agents.keys())
    capabilities = {
        nid: node for nid, node in graph.nodes.items()
        if node.node_type == NodeType.CAPABILITY
    }
    data_stores = {
        nid: node for nid, node in graph.nodes.items()
        if node.node_type == NodeType.DATA_STORE
    }
    guardrails = {
        nid: node for nid, node in graph.nodes.items()
        if node.node_type == NodeType.GUARDRAIL
    }
    obs_sinks = {
        nid: node for nid, node in graph.nodes.items()
        if node.node_type == NodeType.OBSERVABILITY_SINK
    }

    # ── Scale ──
    metrics["total_agents"] = len(agents)
    metrics["total_capabilities"] = len(capabilities)
    metrics["total_data_stores"] = len(data_stores)
    metrics["total_edges"] = len(graph.edges)
    metrics["total_guardrails"] = len(guardrails)
    metrics["total_observability_sinks"] = len(obs_sinks)

    # ── Topology ──
    # Delegation depth
    delegation_edges = {EdgeType.DELEGATES_TO.value}
    deleg_paths = find_paths(graph, delegation_edges, source_filter="agent",
                             min_length=2, max_length=10)
    agent_deleg_paths = [
        p for p in deleg_paths
        if all(graph.nodes.get(n) and graph.nodes[n].node_type == NodeType.AGENT for n in p)
    ]
    metrics["max_delegation_depth"] = max((len(p) for p in agent_deleg_paths), default=0)

    # Data flow depth
    flow_edges = {EdgeType.FEEDS_INTO.value}
    flow_paths = find_paths(graph, flow_edges, source_filter="agent",
                            min_length=2, max_length=10)
    agent_flow_paths = [
        p for p in flow_paths
        if all(graph.nodes.get(n) and graph.nodes[n].node_type == NodeType.AGENT for n in p)
    ]
    metrics["max_data_flow_depth"] = max((len(p) for p in agent_flow_paths), default=0)

    # Graph density
    n_nodes = len(graph.nodes)
    n_edges = len(graph.edges)
    metrics["graph_density"] = round(
        n_edges / max(n_nodes * (n_nodes - 1), 1), 4
    ) if n_nodes > 1 else 0.0

    # Strongly connected components (simplified: count cycles)
    cycles = detect_cycles(graph, node_type_filter="agent")
    # SCC count approximated by number of unique cycle sets
    scc_nodes: list[set[str]] = []
    for cycle in cycles:
        cycle_set = frozenset(cycle[:-1])
        merged = False
        for i, existing in enumerate(scc_nodes):
            if cycle_set & existing:
                scc_nodes[i] = existing | cycle_set
                merged = True
                break
        if not merged:
            scc_nodes.append(set(cycle_set))
    metrics["strongly_connected_components"] = len(scc_nodes)

    # Avg path length to critical capabilities
    irreversible_caps = [
        nid for nid, node in capabilities.items()
        if node.reversibility == "irreversible"
    ]
    if irreversible_caps and agents:
        # Use delegation + feeds_into paths
        all_edges = {EdgeType.DELEGATES_TO.value, EdgeType.FEEDS_INTO.value,
                     EdgeType.TOOL_OF.value}
        all_paths = find_paths(graph, all_edges, min_length=2, max_length=10)
        path_lengths = []
        for p in all_paths:
            if p[0] in agent_ids and p[-1] in irreversible_caps:
                path_lengths.append(len(p))
        metrics["avg_path_length_to_critical"] = round(
            sum(path_lengths) / max(len(path_lengths), 1), 2
        )
    else:
        metrics["avg_path_length_to_critical"] = 0.0

    # ── Control coverage ──
    # Agents/capabilities with at least 1 guardrail edge
    guarded_nodes: set[str] = set()
    for edge in graph.edges:
        if edge.edge_type in (EdgeType.GATED_BY, EdgeType.FILTERED_BY,
                              EdgeType.APPROVAL_REQUIRED):
            guarded_nodes.add(edge.source)

    guardable = set(agent_ids) | set(capabilities.keys())
    metrics["control_coverage_pct"] = round(
        len(guarded_nodes & guardable) / max(len(guardable), 1), 3
    )

    # Observability coverage
    observed_agents: set[str] = set()
    for edge in graph.edges:
        if edge.edge_type == EdgeType.OBSERVED_BY and edge.source in agent_ids:
            observed_agents.add(edge.source)
    metrics["observability_coverage_pct"] = round(
        len(observed_agents) / max(len(agent_ids), 1), 3
    )

    # Human checkpoint ratio
    human_agents = sum(1 for a in agents.values() if a.human_input_enabled)
    metrics["human_checkpoint_ratio"] = round(
        human_agents / max(len(agents), 1), 3
    )

    # Approval gate ratio
    gated_irreversible = 0
    for cap_id in irreversible_caps:
        for edge in graph.edges:
            if edge.edge_type == EdgeType.TOOL_OF and edge.source == cap_id:
                agent_id = edge.target
                for gate_edge in graph.edges:
                    if gate_edge.source == agent_id and gate_edge.edge_type in (
                        EdgeType.GATED_BY, EdgeType.APPROVAL_REQUIRED
                    ):
                        guard = graph.nodes.get(gate_edge.target)
                        if guard and guard.node_type == NodeType.GUARDRAIL:
                            gated_irreversible += 1
                            break
                break
    metrics["approval_gate_ratio"] = round(
        gated_irreversible / max(len(irreversible_caps), 1), 3
    )

    # ── Risk surface ──
    trust_crossings = sum(1 for e in graph.edges if e.trust_crossing)
    unguarded_crossings = sum(
        1 for e in graph.edges
        if e.trust_crossing and not e.has_control
    )
    metrics["trust_boundary_crossings"] = trust_crossings
    metrics["unguarded_trust_crossings"] = unguarded_crossings

    shared_state_conflicts = sum(
        1 for e in graph.edges
        if e.edge_type == EdgeType.SHARED_STATE_CONFLICT
    )
    metrics["shared_state_conflicts"] = shared_state_conflicts

    metrics["irreversible_capabilities"] = len(irreversible_caps)

    unguarded_irreversible = 0
    for cap_id in irreversible_caps:
        is_guarded = False
        for edge in graph.edges:
            if edge.edge_type == EdgeType.TOOL_OF and edge.source == cap_id:
                agent_id = edge.target
                for gate_edge in graph.edges:
                    if gate_edge.source == agent_id and gate_edge.edge_type in (
                        EdgeType.GATED_BY, EdgeType.APPROVAL_REQUIRED
                    ):
                        is_guarded = True
                        break
                break
        if not is_guarded:
            unguarded_irreversible += 1
    metrics["unguarded_irreversible"] = unguarded_irreversible

    # ── Error handling ──
    fail_silent_agents = [
        a for a in agents.values()
        if a.error_handling_pattern in ("fail_silent",)
    ]
    default_on_error_agents = [
        a for a in agents.values()
        if a.error_handling_pattern in ("default_on_error",)
    ]
    metrics["fail_silent_agents_pct"] = round(
        len(fail_silent_agents) / max(len(agents), 1), 3
    )
    metrics["default_on_error_pct"] = round(
        len(default_on_error_agents) / max(len(agents), 1), 3
    )

    # Fail silent on critical path
    fail_silent_on_critical = 0
    for agent in fail_silent_agents:
        # Check if agent is on a path to irreversible capabilities
        tools = [
            e.source for e in graph.edges
            if e.edge_type == EdgeType.TOOL_OF and e.target == agent.id
        ]
        has_critical = any(
            graph.nodes.get(tid) and graph.nodes[tid].reversibility == "irreversible"
            for tid in tools
        )
        if has_critical:
            fail_silent_on_critical += 1
    metrics["fail_silent_on_critical_path"] = fail_silent_on_critical

    error_prop_paths = sum(
        1 for e in graph.edges
        if e.edge_type == EdgeType.ERROR_PROPAGATION_PATH
    )
    # Also count error_boundary edges as proxy
    if error_prop_paths == 0:
        error_prop_paths = sum(
            1 for e in graph.edges
            if e.edge_type == EdgeType.ERROR_BOUNDARY
        )
    metrics["error_propagation_paths"] = error_prop_paths

    # ── Concentration ──
    centrality = compute_centrality(graph)
    metrics["max_betweenness_centrality"] = round(
        max(centrality.values(), default=0.0), 4
    )

    # Single points of failure (removing node disconnects critical capabilities)
    spof_count = 0
    for agent_id, score in centrality.items():
        if score > 0.5:  # High centrality = potential SPOF
            spof_count += 1
    metrics["single_points_of_failure"] = spof_count

    # Tool to agent ratio
    metrics["tool_to_agent_ratio"] = round(
        len(capabilities) / max(len(agents), 1), 2
    )

    # Max tools per agent
    agent_tool_counts: dict[str, int] = defaultdict(int)
    for edge in graph.edges:
        if edge.edge_type == EdgeType.TOOL_OF and edge.target in agent_ids:
            agent_tool_counts[edge.target] += 1
    metrics["max_tools_per_agent"] = max(agent_tool_counts.values(), default=0)

    # ── Feedback / loops ──
    all_cycles = detect_cycles(graph, node_type_filter=None)
    metrics["feedback_loops_detected"] = len(all_cycles)

    # Undampened feedback loops
    undampened = 0
    for cycle in all_cycles:
        cycle_nodes = cycle[:-1]
        has_dampener = any(
            graph.nodes.get(nid) and graph.nodes[nid].max_iterations is not None
            for nid in cycle_nodes
            if graph.nodes.get(nid) and graph.nodes[nid].node_type == NodeType.AGENT
        )
        if not has_dampener:
            has_dampener = any(
                e.edge_type == EdgeType.DAMPENED_BY
                for e in graph.edges
                if e.source in cycle_nodes
            )
        if not has_dampener:
            undampened += 1
    metrics["undampened_feedback_loops"] = undampened

    # ── Data integrity ──
    feeds_into_edges = [
        e for e in graph.edges
        if e.edge_type == EdgeType.FEEDS_INTO
        and graph.nodes.get(e.source) and graph.nodes[e.source].node_type == NodeType.AGENT
        and graph.nodes.get(e.target) and graph.nodes[e.target].node_type == NodeType.AGENT
    ]
    unvalidated = sum(1 for e in feeds_into_edges if not e.schema_validated)
    metrics["unvalidated_data_flows"] = unvalidated

    validated = sum(1 for e in feeds_into_edges if e.schema_validated)
    metrics["schema_coverage_pct"] = round(
        validated / max(len(feeds_into_edges), 1), 3
    )

    return metrics


# ---------------------------------------------------------------------------
# Per-node metrics (spec Section 7 — 10 fields)
# ---------------------------------------------------------------------------

def compute_per_node_metrics(graph: RiskGraph) -> dict[str, dict[str, float | int]]:
    """Compute per-node metrics for all agent nodes per spec AgentMetrics.

    Returns dict of agent_id -> {metric_name: value}.
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

    # Transitive capabilities
    tc = compute_transitive_capabilities(graph)

    # Build edge indices
    agent_guardrails: dict[str, int] = defaultdict(int)
    agent_observability: dict[str, int] = defaultdict(int)
    agent_implicit_auth: dict[str, int] = defaultdict(int)

    for edge in graph.edges:
        if edge.edge_type in (EdgeType.GATED_BY, EdgeType.FILTERED_BY,
                              EdgeType.APPROVAL_REQUIRED):
            if edge.source in agents:
                agent_guardrails[edge.source] += 1
        elif edge.edge_type == EdgeType.OBSERVED_BY:
            if edge.source in agents:
                agent_observability[edge.source] += 1
        elif edge.edge_type == EdgeType.IMPLICIT_AUTHORITY_OVER:
            if edge.source in agents:
                agent_implicit_auth[edge.source] += 1

    # Delegation depth downstream
    delegation_adj: dict[str, set[str]] = defaultdict(set)
    for edge in graph.edges:
        if edge.edge_type == EdgeType.DELEGATES_TO:
            delegation_adj[edge.source].add(edge.target)

    def _max_depth(node_id: str, visited: set[str]) -> int:
        if node_id in visited:
            return 0
        visited.add(node_id)
        children = delegation_adj.get(node_id, set())
        if not children:
            return 0
        return 1 + max(_max_depth(c, visited) for c in children)

    # Closeness centrality (simplified: inverse of avg shortest path length)
    # Build full adjacency
    adj: dict[str, set[str]] = defaultdict(set)
    for edge in graph.edges:
        adj[edge.source].add(edge.target)

    def _avg_shortest_path(start: str) -> float:
        """BFS to compute average shortest path from start to all reachable nodes."""
        distances: dict[str, int] = {start: 0}
        queue = [start]
        while queue:
            current = queue.pop(0)
            for neighbor in adj.get(current, set()):
                if neighbor not in distances:
                    distances[neighbor] = distances[current] + 1
                    queue.append(neighbor)
        if len(distances) <= 1:
            return 0.0
        return sum(distances.values()) / (len(distances) - 1)

    # PageRank (simplified iterative)
    all_nodes = list(graph.nodes.keys())
    n = len(all_nodes)
    if n > 0:
        pagerank: dict[str, float] = {nid: 1.0 / n for nid in all_nodes}
        damping = 0.85
        for _ in range(20):  # 20 iterations
            new_pr: dict[str, float] = {}
            for nid in all_nodes:
                rank = (1 - damping) / n
                for src in all_nodes:
                    if nid in adj.get(src, set()):
                        out_degree = len(adj.get(src, set()))
                        if out_degree > 0:
                            rank += damping * pagerank[src] / out_degree
                new_pr[nid] = rank
            pagerank = new_pr
    else:
        pagerank = {}

    for agent_id in agents:
        node = agents[agent_id]
        m: dict[str, float | int] = {}

        m["betweenness_centrality"] = round(centrality.get(agent_id, 0.0), 4)

        # Closeness centrality
        avg_path = _avg_shortest_path(agent_id)
        m["closeness_centrality"] = round(1.0 / avg_path if avg_path > 0 else 0.0, 4)

        # PageRank
        m["pagerank"] = round(pagerank.get(agent_id, 0.0), 4)

        # Delegation depth downstream
        m["delegation_depth_downstream"] = _max_depth(agent_id, set())

        # Critical capabilities reachable
        if agent_id in tc:
            _, effective = tc[agent_id]
            critical_count = sum(
                1 for tid in effective
                if graph.nodes.get(tid) and graph.nodes[tid].reversibility == "irreversible"
            )
            m["critical_capabilities_reachable"] = critical_count
        else:
            m["critical_capabilities_reachable"] = 0

        m["implicit_authorities"] = agent_implicit_auth.get(agent_id, 0)
        m["guardrail_count"] = agent_guardrails.get(agent_id, 0)
        m["observability_count"] = agent_observability.get(agent_id, 0)

        # Error blast radius: how many agents downstream in error propagation
        error_reachable: set[str] = set()
        queue = [agent_id]
        visited_err: set[str] = set()
        while queue:
            current = queue.pop(0)
            if current in visited_err:
                continue
            visited_err.add(current)
            for edge in graph.edges:
                if edge.source == current and edge.edge_type in (
                    EdgeType.FEEDS_INTO, EdgeType.ERROR_BOUNDARY
                ):
                    tgt = graph.nodes.get(edge.target)
                    if tgt and tgt.node_type == NodeType.AGENT:
                        error_reachable.add(edge.target)
                        queue.append(edge.target)
        m["error_blast_radius"] = len(error_reachable)

        # Also update the node's computed fields
        node.betweenness_centrality = m["betweenness_centrality"]
        node.closeness_centrality = m["closeness_centrality"]
        node.pagerank = m["pagerank"]
        node.delegation_depth_downstream = m["delegation_depth_downstream"]
        node.critical_capabilities_reachable = m["critical_capabilities_reachable"]
        node.implicit_authorities = m["implicit_authorities"]
        node.error_blast_radius = m["error_blast_radius"]

        result[agent_id] = m

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
    anomaly_count: int = 0,
) -> dict:
    """Build the repo_profile structure for JSON output."""
    def count_by_severity(findings: list[Finding]) -> dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            if sev in counts:
                counts[sev] += 1
        return counts

    sec_score = compute_risk_score(security_findings)
    rel_score = compute_risk_score(reliability_findings, composite_findings, anomaly_count)
    gap_class = classify_gap(sec_score, rel_score)

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
    }
