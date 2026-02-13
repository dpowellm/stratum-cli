"""Aggregate risk surface computation from a RiskGraph."""
from __future__ import annotations

from stratum.graph.models import (
    EdgeType, NodeType, RiskGraph, RiskSurface,
)

TRUST_RANK: dict[str, int] = {
    "privileged": 4,
    "restricted": 3,
    "internal": 2,
    "external": 1,
    "public": 0,
}


def compute_risk_surface(
    graph: RiskGraph,
    blast_radii: list | None = None,
    crews: list | None = None,
) -> RiskSurface:
    """Compute aggregate risk surface from the graph."""
    surface = RiskSurface(
        total_nodes=len(graph.nodes),
        total_edges=len(graph.edges),
    )

    # Path metrics
    surface.uncontrolled_path_count = len(graph.uncontrolled_paths)
    if graph.uncontrolled_paths:
        surface.max_path_hops = max(p.hops for p in graph.uncontrolled_paths)

    surface.sensitive_data_types = sorted(set(
        p.source_sensitivity for p in graph.uncontrolled_paths
        if p.source_sensitivity not in ("unknown", "public")
    ))

    surface.external_sink_count = len([
        n for n in graph.nodes.values()
        if n.node_type in (NodeType.EXTERNAL_SERVICE, NodeType.MCP_SERVER)
    ])

    # Control coverage — check both has_control flag AND guardrail edges
    # Build set of nodes that have guardrail coverage (GATED_BY/FILTERED_BY)
    guarded_nodes: set[str] = set()
    for e in graph.edges:
        if e.edge_type in (EdgeType.GATED_BY, EdgeType.FILTERED_BY):
            guarded_nodes.add(e.source)  # The capability being guarded

    needs_control = [e for e in graph.edges if _edge_needs_control(e, graph)]
    has_control_count = sum(
        1 for e in needs_control
        if e.has_control or e.source in guarded_nodes or e.target in guarded_nodes
    )
    surface.edges_needing_controls = len(needs_control)
    surface.edges_with_controls = has_control_count
    surface.control_coverage_pct = (
        has_control_count / len(needs_control) * 100
    ) if needs_control else 100.0

    # Regulatory
    all_flags: set[str] = set()
    for path in graph.uncontrolled_paths:
        all_flags.update(path.regulatory_flags)
    surface.regulatory_frameworks = sorted(all_flags)

    # Trust boundaries (use pre-computed trust_crossing from builder)
    for edge in graph.edges:
        if edge.trust_crossing:
            surface.trust_boundary_crossings += 1
            if edge.crossing_direction == "outward":
                surface.outward_crossings += 1
                surface.downward_crossings += 1
            elif edge.crossing_direction == "inward":
                surface.inward_crossings += 1

    # Topology metrics (v0.2)
    n = surface.total_nodes
    if n > 1:
        surface.edge_density = round(surface.total_edges / (n * (n - 1)), 4)

    if blast_radii:
        surface.max_fan_out_per_crew = max(
            (br.agent_count for br in blast_radii), default=0
        )

    if crews:
        surface.crew_count = len(crews)

    # max_chain_depth: longest chain of FEEDS_INTO edges
    feeds_into = [e for e in graph.edges if e.edge_type == EdgeType.FEEDS_INTO]
    if feeds_into:
        adj: dict[str, list[str]] = {}
        for e in feeds_into:
            adj.setdefault(e.source, []).append(e.target)
        longest = 0
        for start in adj:
            stack = [(start, 1)]
            while stack:
                node, depth = stack.pop()
                longest = max(longest, depth)
                for nxt in adj.get(node, []):
                    if depth < 10:  # safety bound
                        stack.append((nxt, depth + 1))
        surface.max_chain_depth = longest

    return surface


def _edge_needs_control(edge, graph: RiskGraph) -> bool:
    """Determine if an edge should have a control on it."""
    src = graph.nodes.get(edge.source)
    tgt = graph.nodes.get(edge.target)
    if not src or not tgt:
        return False

    # Edges to external services or MCP servers need controls
    if tgt.node_type in (NodeType.EXTERNAL_SERVICE, NodeType.MCP_SERVER):
        return True

    # Edges carrying sensitive data to any non-data-store destination
    if edge.data_sensitivity in ("personal", "financial", "credentials"):
        if tgt.node_type != NodeType.DATA_STORE:
            return True

    return False
