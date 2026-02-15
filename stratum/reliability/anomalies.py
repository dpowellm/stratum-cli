"""Structural anomaly detection for reliability analysis.

Three anomaly detection types per spec Section 11:
1. Framework-relative z-scores (emit metric values; z-scores computed post-hoc)
2. Topological anomalies (7 types, per-repo, no baseline needed)
3. Novel motif detection (canonical subgraph patterns, size 3-5)
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from itertools import combinations

from stratum.graph.models import EdgeType, NodeType, RiskGraph
from stratum.models import Confidence, Finding, RiskCategory, Severity


# ---------------------------------------------------------------------------
# Reference statistics (bootstrapped from taxonomy hypothetical benchmarks)
# ---------------------------------------------------------------------------

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
    if std == 0:
        return 0.0
    return (value - mean) / std


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def detect_structural_anomalies(graph: RiskGraph) -> list[Finding]:
    """Run all anomaly detection passes."""
    findings: list[Finding] = []
    findings.extend(_z_score_anomalies(graph))
    findings.extend(_topological_anomalies(graph))
    return findings


def extract_motifs(graph: RiskGraph) -> list[dict]:
    """Extract structural motifs for novel pattern detection (spec Section 11).

    Returns list of GraphMotif dicts. Performance guard: skip for >100 nodes,
    limit to size-3 for >50 nodes.
    """
    n_nodes = len(graph.nodes)
    if n_nodes > 100:
        return []  # Skip entirely for large graphs
    max_size = 3 if n_nodes > 50 else 5
    return _extract_motifs(graph, max_size)


# ---------------------------------------------------------------------------
# Z-score anomalies
# ---------------------------------------------------------------------------

def _z_score_anomalies(graph: RiskGraph) -> list[Finding]:
    """Detect metrics that deviate significantly from framework baselines."""
    agents = {nid for nid, n in graph.nodes.items() if n.node_type == NodeType.AGENT}
    if not agents:
        return []

    capabilities = {nid for nid, n in graph.nodes.items() if n.node_type == NodeType.CAPABILITY}
    externals = {nid for nid, n in graph.nodes.items()
                 if n.node_type == NodeType.EXTERNAL_SERVICE}
    guardrails = {nid for nid, n in graph.nodes.items() if n.node_type == NodeType.GUARDRAIL}

    observed: dict[str, float] = {
        "agent_count": len(agents),
        "tool_per_agent_ratio": len(capabilities) / max(len(agents), 1),
        "external_service_ratio": len(externals) / max(len(agents), 1),
        "guardrail_coverage": len(guardrails) / max(len(agents), 1),
    }

    from stratum.reliability.traversals import find_paths
    chain_edges = {EdgeType.DELEGATES_TO.value, EdgeType.FEEDS_INTO.value}
    paths = find_paths(graph, chain_edges, source_filter="agent", min_length=2, max_length=10)
    observed["max_chain_depth"] = max((len(p) for p in paths), default=0)

    delegation_count = sum(
        1 for e in graph.edges
        if e.edge_type in (EdgeType.DELEGATES_TO, EdgeType.FEEDS_INTO)
    )
    observed["delegation_edges_per_agent"] = delegation_count / max(len(agents), 1)

    observed_agents = {
        e.source for e in graph.edges
        if e.edge_type == EdgeType.OBSERVED_BY and e.source in agents
    }
    observed["observability_coverage"] = len(observed_agents) / max(len(agents), 1)

    findings: list[Finding] = []
    z_threshold = 2.0

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
                f"{direction} the reference baseline (mean={mean:.2f}, std={std:.2f})."
            ),
            evidence=[f"z-score: {z:.2f}", f"observed: {value:.2f}", f"baseline: {mean:.2f}"],
            remediation="Review the architecture for this metric.",
            effort="low",
            finding_class="reliability",
        ))

    return findings


# ---------------------------------------------------------------------------
# Topological anomalies (spec Section 11 — 7 types)
# ---------------------------------------------------------------------------

def _topological_anomalies(graph: RiskGraph) -> list[Finding]:
    """Detect 7 topological anomaly types per spec."""
    findings: list[Finding] = []
    agents = {nid for nid, n in graph.nodes.items() if n.node_type == NodeType.AGENT}

    if len(graph.nodes) < 2:
        return []

    findings.extend(_anomaly_unreachable_subgraphs(graph, agents))
    findings.extend(_anomaly_hub_spoke_asymmetry(graph, agents))
    findings.extend(_anomaly_write_only_store(graph))
    findings.extend(_anomaly_orphaned_capability(graph))
    findings.extend(_anomaly_empty_agent(graph, agents))
    findings.extend(_anomaly_long_linear_chain(graph, agents))
    findings.extend(_anomaly_dense_mesh(graph, agents))

    return findings[:7]


def _anomaly_unreachable_subgraphs(graph: RiskGraph, agents: set[str]) -> list[Finding]:
    """1. Unreachable subgraphs: connected components with no path to/from main graph."""
    if len(agents) < 3:
        return []

    # Build undirected adjacency
    adj: dict[str, set[str]] = defaultdict(set)
    for edge in graph.edges:
        adj[edge.source].add(edge.target)
        adj[edge.target].add(edge.source)

    # Find connected components via BFS
    visited: set[str] = set()
    components: list[set[str]] = []
    for nid in graph.nodes:
        if nid in visited:
            continue
        component: set[str] = set()
        queue = [nid]
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            component.add(current)
            queue.extend(adj.get(current, set()) - visited)
        components.append(component)

    if len(components) <= 1:
        return []

    # The largest component is the "main" graph
    main = max(components, key=len)
    disconnected = [c for c in components if c is not main]

    findings: list[Finding] = []
    for comp in disconnected:
        agent_nodes = comp & agents
        if not agent_nodes:
            continue
        labels = [graph.nodes[nid].label for nid in agent_nodes if nid in graph.nodes]
        findings.append(Finding(
            id="STRAT-ANOMALY-UNREACHABLE",
            severity=Severity.LOW,
            confidence=Confidence.HEURISTIC,
            category=RiskCategory.OPERATIONAL,
            title="Unreachable Subgraph",
            path=", ".join(labels[:3]),
            description=f"Disconnected subgraph with {len(comp)} nodes "
                        f"({len(agent_nodes)} agents) has no path to the main graph.",
            evidence=[f"Disconnected agents: {', '.join(labels[:3])}"],
            remediation="Verify these agents are intentionally standalone.",
            effort="low",
            finding_class="reliability",
        ))

    return findings[:2]


def _anomaly_hub_spoke_asymmetry(graph: RiskGraph, agents: set[str]) -> list[Finding]:
    """2. Hub-and-spoke asymmetry: high out-degree, zero in-degree, not entry point."""
    out_degree: dict[str, int] = defaultdict(int)
    in_degree: dict[str, int] = defaultdict(int)

    for edge in graph.edges:
        if edge.edge_type in (EdgeType.DELEGATES_TO, EdgeType.FEEDS_INTO):
            if edge.source in agents:
                out_degree[edge.source] += 1
            if edge.target in agents:
                in_degree[edge.target] += 1

    findings: list[Finding] = []
    for nid in agents:
        if out_degree.get(nid, 0) >= 3 and in_degree.get(nid, 0) == 0:
            node = graph.nodes.get(nid)
            if not node:
                continue
            findings.append(Finding(
                id="STRAT-ANOMALY-HUB-SPOKE",
                severity=Severity.LOW,
                confidence=Confidence.HEURISTIC,
                category=RiskCategory.OPERATIONAL,
                title="Hub-and-Spoke Asymmetry",
                path=node.label,
                description=f"{node.label} has out-degree {out_degree[nid]} but zero in-degree. "
                            f"Potential uncontrolled entry point.",
                evidence=[f"out_degree={out_degree[nid]}", "in_degree=0"],
                remediation="Verify this agent's role as entry point.",
                effort="low",
                finding_class="reliability",
            ))
    return findings[:2]


def _anomaly_write_only_store(graph: RiskGraph) -> list[Finding]:
    """3. Data store with many writers, no readers."""
    findings: list[Finding] = []
    for nid, node in graph.nodes.items():
        if node.node_type != NodeType.DATA_STORE:
            continue
        writers = sum(1 for e in graph.edges if e.edge_type == EdgeType.WRITES_TO and e.target == nid)
        readers = sum(1 for e in graph.edges if e.edge_type == EdgeType.READS_FROM and e.source == nid)
        if writers >= 2 and readers == 0:
            findings.append(Finding(
                id="STRAT-ANOMALY-WRITEONLY",
                severity=Severity.LOW,
                confidence=Confidence.HEURISTIC,
                category=RiskCategory.OPERATIONAL,
                title="Write-Only Data Store",
                path=node.label,
                description=f"{node.label} has {writers} writers but zero readers.",
                evidence=[f"writers={writers}", "readers=0"],
                remediation="Verify this store serves a purpose (logging is OK).",
                effort="low",
                finding_class="reliability",
            ))
    return findings[:2]


def _anomaly_orphaned_capability(graph: RiskGraph) -> list[Finding]:
    """4. Capability with no agent (orphaned tool)."""
    findings: list[Finding] = []
    owned_caps = {e.source for e in graph.edges if e.edge_type == EdgeType.TOOL_OF}
    for nid, node in graph.nodes.items():
        if node.node_type == NodeType.CAPABILITY and nid not in owned_caps:
            findings.append(Finding(
                id="STRAT-ANOMALY-ORPHAN-CAP",
                severity=Severity.LOW,
                confidence=Confidence.HEURISTIC,
                category=RiskCategory.OPERATIONAL,
                title="Orphaned Capability",
                path=node.label,
                description=f"{node.label} has no tool_of edge — no agent owns it.",
                evidence=[f"capability: {node.label}"],
                remediation="Connect to an agent or remove if unused.",
                effort="low",
                finding_class="reliability",
            ))
    return findings[:3]


def _anomaly_empty_agent(graph: RiskGraph, agents: set[str]) -> list[Finding]:
    """5. Agent with no capabilities (delegates everything)."""
    findings: list[Finding] = []
    agents_with_tools = {e.target for e in graph.edges if e.edge_type == EdgeType.TOOL_OF}
    for nid in agents:
        if nid not in agents_with_tools:
            node = graph.nodes.get(nid)
            if not node:
                continue
            findings.append(Finding(
                id="STRAT-ANOMALY-EMPTY-AGENT",
                severity=Severity.LOW,
                confidence=Confidence.HEURISTIC,
                category=RiskCategory.OPERATIONAL,
                title="Agent With No Capabilities",
                path=node.label,
                description=f"{node.label} has no tools — delegates everything.",
                evidence=[f"agent: {node.label}"],
                remediation="Verify this agent has a coordination-only role.",
                effort="low",
                finding_class="reliability",
            ))
    return findings[:3]


def _anomaly_long_linear_chain(graph: RiskGraph, agents: set[str]) -> list[Finding]:
    """6. Long chains with no branching (>4 agents, no error recovery paths)."""
    from stratum.reliability.traversals import find_paths
    chain_edges = {EdgeType.DELEGATES_TO.value, EdgeType.FEEDS_INTO.value}
    paths = find_paths(graph, chain_edges, source_filter="agent", min_length=5, max_length=10)

    findings: list[Finding] = []
    for path in paths:
        if not all(graph.nodes.get(n) and graph.nodes[n].node_type == NodeType.AGENT for n in path):
            continue
        # Check for branching: does any node in the path have out-degree > 1?
        out_degree: dict[str, int] = defaultdict(int)
        for edge in graph.edges:
            if edge.edge_type in (EdgeType.DELEGATES_TO, EdgeType.FEEDS_INTO):
                if edge.source in path:
                    out_degree[edge.source] += 1
        has_branching = any(out_degree.get(n, 0) > 1 for n in path[:-1])
        if has_branching:
            continue

        labels = [graph.nodes[n].label for n in path if n in graph.nodes]
        findings.append(Finding(
            id="STRAT-ANOMALY-LINEAR",
            severity=Severity.MEDIUM,
            confidence=Confidence.HEURISTIC,
            category=RiskCategory.OPERATIONAL,
            title="Long Linear Chain Without Branching",
            path=" \u2192 ".join(labels),
            description=f"Linear pipeline of {len(path)} agents with no error recovery paths.",
            evidence=[f"chain_length={len(path)}"],
            remediation="Add error recovery paths or parallel evaluation branches.",
            effort="med",
            finding_class="reliability",
        ))
        break  # One is enough

    return findings[:1]


def _anomaly_dense_mesh(graph: RiskGraph, agents: set[str]) -> list[Finding]:
    """7. Dense cross-connections without hierarchy (flat mesh topology)."""
    if len(agents) < 4:
        return []

    # Count agent-to-agent edges
    agent_edges = sum(
        1 for e in graph.edges
        if e.edge_type in (EdgeType.DELEGATES_TO, EdgeType.FEEDS_INTO)
        and e.source in agents and e.target in agents
    )
    max_edges = len(agents) * (len(agents) - 1)
    if max_edges == 0:
        return []

    density = agent_edges / max_edges
    if density < 0.6:
        return []

    return [Finding(
        id="STRAT-ANOMALY-MESH",
        severity=Severity.MEDIUM,
        confidence=Confidence.HEURISTIC,
        category=RiskCategory.OPERATIONAL,
        title="Dense Mesh Topology Without Hierarchy",
        path="",
        description=f"Agent graph density is {density:.2f} — all agents delegate to "
                    f"most others. Suggests unclear authority structure.",
        evidence=[f"density={density:.2f}", f"agent_edges={agent_edges}"],
        remediation="Establish clear hierarchy with designated coordinators.",
        effort="med",
        finding_class="reliability",
    )]


# ---------------------------------------------------------------------------
# Motif extraction (spec Section 11)
# ---------------------------------------------------------------------------

def _extract_motifs(graph: RiskGraph, max_size: int = 5) -> list[dict]:
    """Extract canonical motifs of size 3 to max_size.

    Returns list of GraphMotif dicts sorted by instance count.
    """
    # Build adjacency with edge types
    adj: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for edge in graph.edges:
        etype = edge.edge_type.value if hasattr(edge.edge_type, 'value') else edge.edge_type
        adj[edge.source].append((edge.target, etype))

    all_nodes = list(graph.nodes.keys())
    motif_instances: dict[str, list[list[str]]] = defaultdict(list)
    motif_meta: dict[str, dict] = {}

    # Enumerate connected subgraphs of each size
    for size in range(3, min(max_size + 1, 6)):
        for combo in combinations(all_nodes, size):
            combo_set = set(combo)
            # Check connectivity
            edges_in_subgraph = []
            for src in combo:
                for tgt, etype in adj.get(src, []):
                    if tgt in combo_set:
                        edges_in_subgraph.append((src, tgt, etype))

            if len(edges_in_subgraph) < size - 1:
                continue  # Not connected

            # Build canonical form
            node_types = sorted(
                graph.nodes[n].node_type.value for n in combo if n in graph.nodes
            )
            edge_types_sorted = sorted(e[2] for e in edges_in_subgraph)

            # Create index-based edge pairs
            combo_list = sorted(combo)
            edge_pairs = []
            for src, tgt, _ in edges_in_subgraph:
                si = combo_list.index(src)
                ti = combo_list.index(tgt)
                edge_pairs.append((si, ti))
            edge_pairs.sort()

            # Hash canonical form
            canonical = str((tuple(node_types), tuple(edge_types_sorted), tuple(edge_pairs)))
            motif_id = hashlib.md5(canonical.encode()).hexdigest()[:12]

            motif_instances[motif_id].append(list(combo))

            if motif_id not in motif_meta:
                motif_meta[motif_id] = {
                    "motif_id": motif_id,
                    "node_types": node_types,
                    "edge_types": edge_types_sorted,
                    "edge_pairs": edge_pairs,
                }

    # Build output with enrichment summaries
    result = []
    for motif_id, instances in sorted(
        motif_instances.items(),
        key=lambda x: len(x[1]),
        reverse=True,
    ):
        meta = motif_meta[motif_id]

        # Compute enrichment summary across instances
        has_fail_silent = False
        has_irreversible = False
        centrality_sum = 0.0
        centrality_count = 0
        has_trust_crossing = False
        has_guardrail = False

        for instance_nodes in instances:
            for nid in instance_nodes:
                node = graph.nodes.get(nid)
                if not node:
                    continue
                if node.node_type == NodeType.AGENT:
                    if node.error_handling_pattern == "fail_silent":
                        has_fail_silent = True
                    centrality_sum += node.betweenness_centrality
                    centrality_count += 1
                elif node.node_type == NodeType.CAPABILITY:
                    if node.reversibility == "irreversible":
                        has_irreversible = True

            # Check edges in this instance
            instance_set = set(instance_nodes)
            for edge in graph.edges:
                if edge.source in instance_set and edge.target in instance_set:
                    if edge.trust_crossing:
                        has_trust_crossing = True
                    if edge.edge_type in (EdgeType.GATED_BY, EdgeType.FILTERED_BY):
                        has_guardrail = True

        enrichment = {
            "has_fail_silent": has_fail_silent,
            "has_irreversible": has_irreversible,
            "avg_centrality": round(centrality_sum / max(centrality_count, 1), 4),
            "has_trust_crossing": has_trust_crossing,
            "has_guardrail": has_guardrail,
        }

        result.append({
            "motif_id": meta["motif_id"],
            "node_types": meta["node_types"],
            "edge_types": meta["edge_types"],
            "edge_pairs": meta["edge_pairs"],
            "instances": len(instances),
            "instance_node_ids": instances[:10],  # Cap at 10 instances
            "enrichment_summary": enrichment,
        })

    return result[:20]  # Cap total motifs
