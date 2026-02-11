"""Multi-hop path discovery: BFS from sensitive sources to external sinks."""
from __future__ import annotations

from stratum.graph.models import (
    EdgeType, GraphEdge, NodeType, RiskGraph, RiskPath,
)
from stratum.graph.regulatory import compute_regulatory_flags


def find_uncontrolled_paths(graph: RiskGraph) -> list[RiskPath]:
    """Find all paths from sensitive sources to external destinations
    where controls are missing.

    Algorithm:
    1. Identify all data source nodes (DATA_STORE with sensitivity != 'public')
    2. BFS from each source toward EXTERNAL_SERVICE or MCP_SERVER nodes
    3. For each path found, check which controls exist and which are missing
    4. Score the path based on sensitivity, trust gap, hops, and missing controls
    5. Return paths sorted by severity
    """
    # Step 1: Find all source nodes
    sources = [
        nid for nid, node in graph.nodes.items()
        if node.node_type == NodeType.DATA_STORE
        and node.data_sensitivity not in ("public", "unknown")
    ]

    # Step 2: Find all sink nodes
    sinks = {
        nid for nid, node in graph.nodes.items()
        if node.node_type in (NodeType.EXTERNAL_SERVICE, NodeType.MCP_SERVER)
    }

    # Step 3: BFS from each source to each reachable sink
    paths: list[RiskPath] = []
    for source_id in sources:
        reachable = _bfs_to_sinks(graph, source_id, sinks, max_hops=6)
        for path_nodes, path_edges in reachable:
            risk_path = _analyze_path(graph, path_nodes, path_edges)
            if risk_path.severity != "NONE":
                paths.append(risk_path)

    # Step 5: Deduplicate overlapping paths
    paths = _deduplicate_paths(paths)

    # Step 6: Sort by severity, then sink priority, then hops
    paths.sort(key=lambda p: (
        {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(p.severity, 0),
        _sink_priority(p, graph),
        p.hops,
    ), reverse=True)

    return paths[:10]


def _bfs_to_sinks(
    graph: RiskGraph,
    source_id: str,
    sinks: set[str],
    max_hops: int,
) -> list[tuple[list[str], list[GraphEdge]]]:
    """BFS from source to all reachable sink nodes within max_hops."""
    results: list[tuple[list[str], list[GraphEdge]]] = []
    queue: list[tuple[str, list[str], list[GraphEdge]]] = [
        (source_id, [source_id], []),
    ]
    visited_paths: set[str] = set()

    while queue:
        current, path, edges = queue.pop(0)

        if len(edges) > max_hops:
            continue

        if current in sinks and len(edges) > 0:
            path_key = "\u2192".join(path)
            if path_key not in visited_paths:
                visited_paths.add(path_key)
                results.append((list(path), list(edges)))

        for edge in graph.edges:
            if edge.source == current and edge.target not in path:
                queue.append((
                    edge.target,
                    path + [edge.target],
                    edges + [edge],
                ))

    return results


def _analyze_path(
    graph: RiskGraph,
    path_nodes: list[str],
    path_edges: list[GraphEdge],
) -> RiskPath:
    """Analyze a discovered path for risk severity."""
    source_node = graph.nodes[path_nodes[0]]
    dest_node = graph.nodes[path_nodes[-1]]

    sensitivity = source_node.data_sensitivity
    dest_trust = dest_node.trust_level.value

    # What controls are missing?
    missing: list[str] = []
    has_output_filter = any(
        e.has_control and e.control_type == "output_filter" for e in path_edges
    )
    has_hitl = any(
        e.has_control and e.control_type == "hitl" for e in path_edges
    )

    if not has_output_filter:
        missing.append("output_filter")
    if not has_hitl and sensitivity in ("personal", "financial", "credentials"):
        missing.append("hitl")

    # Severity computation
    if sensitivity in ("credentials", "personal") and dest_trust == "external" and not has_output_filter:
        severity = "CRITICAL"
    elif sensitivity == "financial" and dest_trust == "external" and not has_hitl:
        severity = "CRITICAL"
    elif sensitivity in ("personal", "financial") and not has_output_filter:
        severity = "HIGH"
    elif sensitivity == "internal" and dest_trust == "external" and not has_output_filter:
        severity = "HIGH"
    elif len(missing) > 0:
        severity = "MEDIUM"
    else:
        severity = "NONE"

    # Build description
    node_labels = [graph.nodes[nid].label for nid in path_nodes]
    description = _build_path_description(node_labels, sensitivity, missing)

    # Build what-happens narrative
    plain_description = _build_what_happens(graph, path_nodes, sensitivity, missing)

    # Regulatory flags
    regulatory_flags = compute_regulatory_flags(
        sensitivity, dest_trust, missing, path_edges,
    )

    return RiskPath(
        nodes=path_nodes,
        edges=path_edges,
        hops=len(path_edges),
        source_sensitivity=sensitivity,
        destination_trust=dest_trust,
        missing_controls=missing,
        severity=severity,
        description=description,
        plain_description=plain_description,
        regulatory_flags=regulatory_flags,
    )


def _build_path_description(
    node_labels: list[str],
    sensitivity: str,
    missing: list[str],
) -> str:
    """Build a human-readable description of a risk path."""
    path_str = " \u2192 ".join(node_labels)
    missing_str = ", ".join(missing) if missing else "none"
    sens_upper = sensitivity.upper() if sensitivity != "unknown" else "data"
    return (
        f"{sens_upper} flows through: {path_str}. "
        f"Missing controls: {missing_str}."
    )


def _build_what_happens(
    graph: RiskGraph,
    path_nodes: list[str],
    sensitivity: str,
    missing: list[str],
) -> str:
    """Build a vivid second-person scenario description for a risk path.

    Uses friendly node labels to produce text like:
    "Someone sends your agent a crafted email. The agent reads your
    gmail inbox and forwards sensitive content to an external address
    via Gmail outbound."
    """
    if len(path_nodes) < 2:
        return ""

    source = graph.nodes[path_nodes[0]]
    dest = graph.nodes[path_nodes[-1]]
    source_label = source.label.lower()
    dest_label = dest.label

    # Determine source context
    if "mail" in source_label or "email" in source_label or "gmail" in source_label:
        trigger = "Someone sends your agent a crafted email"
        reads = f"reads your {source.label.lower()}"
    elif "slack" in source_label:
        trigger = "Someone sends your agent a crafted Slack message"
        reads = f"reads your {source.label.lower()}"
    elif "database" in source_label or "sql" in source_label or "postgres" in source_label:
        trigger = "An attacker injects a crafted prompt"
        reads = f"queries your {source.label.lower()}"
    else:
        trigger = "An attacker crafts malicious input"
        reads = f"reads from {source.label}"

    # Determine exfiltration method
    dl = dest_label.lower()
    if any(t in dl for t in ("mail", "email", "smtp", "gmail")):
        exfil = (
            f"forwards sensitive content to an external address via "
            f"{dest_label} \u2014 an attacker-controlled destination embedded "
            f"in the injected instructions"
        )
    elif any(t in dl for t in ("search", "serper", "tavily", "duckduckgo")):
        exfil = (
            f"search for your private {sensitivity} content on {dest_label} "
            f"\u2014 leaking it through the search query string"
        )
    elif any(t in dl for t in ("slack", "discord", "telegram", "teams")):
        exfil = (
            f"send your private data to an attacker-controlled channel via "
            f"{dest_label}"
        )
    elif any(t in dl for t in ("http", "api", "webhook")):
        exfil = f"exfiltrate data to {dest_label}"
    else:
        exfil = f"leak data to {dest_label}"

    no_filter = " with no output filter" if "output_filter" in missing else ""

    return (
        f"{trigger}. The agent {reads}, and the injected instructions cause it to "
        f"{exfil}{no_filter}."
    )


def _sink_priority(path: RiskPath, graph: RiskGraph) -> int:
    """Higher priority for more dangerous exfiltration sinks.

    Direct messaging (email, Slack) > generic HTTP > search APIs.
    Email forwarding leaks full content; search query exfiltration is
    bandwidth-limited to query string length.
    """
    dest_id = path.nodes[-1]
    dest = graph.nodes.get(dest_id)
    if not dest:
        return 0

    label = dest.label.lower()

    # Direct messaging: full content exfiltration
    if any(t in label for t in ("mail", "email", "smtp", "slack", "discord", "telegram", "teams")):
        return 3

    # Generic HTTP: flexible exfiltration
    if any(t in label for t in ("http", "api", "webhook")):
        return 2

    # Search: query-string limited
    if any(t in label for t in ("search", "serper", "tavily", "duckduckgo", "google", "brave")):
        return 1

    return 0


def _deduplicate_paths(paths: list[RiskPath]) -> list[RiskPath]:
    """Deduplicate overlapping paths, keeping the most severe."""
    if not paths:
        return paths

    seen_endpoints: dict[tuple[str, str], RiskPath] = {}
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}

    for path in paths:
        if not path.nodes:
            continue
        key = (path.nodes[0], path.nodes[-1])
        existing = seen_endpoints.get(key)
        if existing is None:
            seen_endpoints[key] = path
        else:
            # Keep longer path or more severe
            existing_rank = severity_rank.get(existing.severity, 0)
            new_rank = severity_rank.get(path.severity, 0)
            if new_rank > existing_rank or (new_rank == existing_rank and path.hops > existing.hops):
                seen_endpoints[key] = path

    return list(seen_endpoints.values())
