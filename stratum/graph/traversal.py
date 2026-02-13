"""Multi-hop path discovery: BFS from sensitive sources to external sinks."""
from __future__ import annotations

from stratum.models import BlastRadius
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
        reads = f"reads your {source.label}"
    elif "slack" in source_label:
        trigger = "Someone sends your agent a crafted Slack message"
        reads = f"reads your {source.label}"
    elif "database" in source_label or "sql" in source_label or "postgres" in source_label:
        trigger = "An attacker injects a crafted prompt"
        reads = f"queries your {source.label}"
    else:
        trigger = "An attacker crafts malicious input"
        reads = f"reads from {source.label}"

    # Build full scenario based on destination type
    dl = dest_label.lower()
    if any(t in dl for t in ("mail", "email", "smtp", "gmail")):
        return (
            f"{trigger}. The agent {reads} and forwards sensitive content "
            f"via {dest_label} \u2014 to an attacker-controlled address "
            f"embedded in the injected instructions."
        )
    elif any(t in dl for t in ("search", "serper", "tavily", "duckduckgo")):
        return (
            f"{trigger}. The agent {reads} and the injected instructions "
            f"cause it to search for your email content on {dest_label} "
            f"\u2014 leaking it in the query string."
        )
    elif any(t in dl for t in ("slack", "discord", "telegram", "teams")):
        return (
            f"{trigger}. The agent {reads} and sends your data "
            f"to an attacker-controlled channel via {dest_label}."
        )
    elif any(t in dl for t in ("http", "api", "webhook")):
        return (
            f"{trigger}. The agent {reads} and exfiltrates data "
            f"to {dest_label}."
        )
    else:
        return (
            f"{trigger}. The agent {reads} and sends the content to "
            f"{dest_label} with no check on what leaves."
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


# ---------------------------------------------------------------------------
# Blast radius computation
# ---------------------------------------------------------------------------

def find_blast_radii(graph: RiskGraph, crews: list) -> list[BlastRadius]:
    """Find shared tools that fan out to multiple agents, **per-crew**.

    For each (tool, crew) pair where 2+ agents in that crew share the tool,
    compute the blast radius within that crew only.  No more cross-crew
    inflation (e.g. "SerperDevTool → 9 agents" across 5 independent crews).
    """
    # Build tool -> agents map from TOOL_OF edges
    tool_agents: dict[str, list[str]] = {}
    for edge in graph.edges:
        if edge.edge_type == EdgeType.TOOL_OF:
            tool_agents.setdefault(edge.source, []).append(edge.target)

    # Build agent -> crew mapping
    agent_to_crew: dict[str, str] = {}
    for crew in crews:
        for name in crew.agent_names:
            aid = f"agent_{name.lower().replace(' ', '_')}"
            agent_to_crew[aid] = crew.name

    # Build agent -> downstream externals map
    agent_externals: dict[str, set[str]] = {}
    for agent_id, node in graph.nodes.items():
        if node.node_type != NodeType.AGENT:
            continue
        externals: set[str] = set()
        agent_tools = [
            e.source for e in graph.edges
            if e.edge_type == EdgeType.TOOL_OF and e.target == agent_id
        ]
        for tid in agent_tools:
            for e in graph.edges:
                if e.source == tid and e.edge_type == EdgeType.SENDS_TO:
                    externals.add(e.target)
        agent_externals[agent_id] = externals

    results: list[BlastRadius] = []
    for tool_id, agent_ids in tool_agents.items():
        tool_node = graph.nodes.get(tool_id)
        if not tool_node:
            continue

        # Partition agents by crew
        crew_groups: dict[str, list[str]] = {}
        for aid in agent_ids:
            cname = agent_to_crew.get(aid, "(default)")
            crew_groups.setdefault(cname, []).append(aid)

        for crew_name, crew_agent_ids in crew_groups.items():
            if len(crew_agent_ids) < 2:
                continue

            all_externals: set[str] = set()
            agent_labels = []
            for aid in crew_agent_ids:
                anode = graph.nodes.get(aid)
                if anode:
                    agent_labels.append(anode.label)
                all_externals.update(agent_externals.get(aid, set()))

            ext_labels = []
            for eid in all_externals:
                enode = graph.nodes.get(eid)
                if enode:
                    ext_labels.append(enode.label)

            results.append(BlastRadius(
                source_node_id=tool_id,
                source_label=tool_node.label,
                affected_agent_ids=crew_agent_ids,
                affected_agent_labels=sorted(agent_labels),
                downstream_external_ids=sorted(all_externals),
                downstream_external_labels=sorted(ext_labels),
                agent_count=len(crew_agent_ids),
                external_count=len(all_externals),
                crew_name=crew_name if crew_name != "(default)" else "",
            ))

    results.sort(key=lambda br: (br.agent_count, br.external_count), reverse=True)
    return results


# ---------------------------------------------------------------------------
# Control bypass detection
# ---------------------------------------------------------------------------

def find_control_bypasses(graph: RiskGraph, crews: list) -> list[dict]:
    """Find cases where downstream agents bypass upstream filter agents.

    Pattern: In a sequential crew [A, B, C], if A reads from data_store X
    and B or C also reads from X directly, then A's filtering is irrelevant
    because downstream agents have unfiltered access to the same source.
    """
    bypasses: list[dict] = []

    # Build node -> reads_from data stores
    agent_data_sources: dict[str, set[str]] = {}
    for edge in graph.edges:
        if edge.edge_type != EdgeType.TOOL_OF:
            continue
        agent_id = edge.target
        tool_id = edge.source
        # Find what data stores this tool reads from
        for e2 in graph.edges:
            if e2.source == tool_id and e2.edge_type == EdgeType.READS_FROM:
                # tool reads from data store — but READS_FROM goes ds -> tool
                pass
        # READS_FROM edges go data_store -> capability
        # TOOL_OF edges go capability -> agent
        # So: ds --reads_from--> cap --tool_of--> agent
        for e2 in graph.edges:
            if e2.target == tool_id and e2.edge_type == EdgeType.READS_FROM:
                agent_data_sources.setdefault(agent_id, set()).add(e2.source)

    for crew in crews:
        if crew.process_type != "sequential" or len(crew.agent_names) < 2:
            continue

        # Get agent IDs in crew order
        agent_ids = [
            f"agent_{name.lower().replace(' ', '_')}"
            for name in crew.agent_names
        ]

        # Check each upstream agent against all downstream agents
        for i, upstream_id in enumerate(agent_ids):
            upstream_sources = agent_data_sources.get(upstream_id, set())
            if not upstream_sources:
                continue

            for j in range(i + 1, len(agent_ids)):
                downstream_id = agent_ids[j]
                downstream_sources = agent_data_sources.get(downstream_id, set())
                shared_sources = upstream_sources & downstream_sources
                if not shared_sources:
                    continue

                upstream_node = graph.nodes.get(upstream_id)
                downstream_node = graph.nodes.get(downstream_id)
                if not upstream_node or not downstream_node:
                    continue

                for ds_id in shared_sources:
                    ds_node = graph.nodes.get(ds_id)
                    ds_label = ds_node.label if ds_node else ds_id

                    bypasses.append({
                        "upstream_agent": upstream_node.label,
                        "downstream_agent": downstream_node.label,
                        "data_source": ds_label,
                        "data_source_id": ds_id,
                        "crew_name": crew.name,
                        "upstream_id": upstream_id,
                        "downstream_id": downstream_id,
                    })

    # Deduplicate by (upstream, downstream, data_source)
    seen: set[tuple] = set()
    unique: list[dict] = []
    for bp in bypasses:
        key = (bp["upstream_id"], bp["downstream_id"], bp["data_source_id"])
        if key not in seen:
            seen.add(key)
            unique.append(bp)

    return unique
