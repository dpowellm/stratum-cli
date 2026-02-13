"""Per-crew ASCII flow diagrams in bordered boxes.

Renders data flow through agent chains with annotations for
bypasses, shared tools (blast radii), and incident matches.
"""
from __future__ import annotations

from stratum.graph.models import EdgeType, NodeType, RiskGraph
from stratum.models import BlastRadius, CrewDefinition, Finding, IncidentMatch, Severity


MAX_WIDTH = 70


def render_all_crew_maps(
    crews: list[CrewDefinition],
    graph: RiskGraph | None,
    findings: list[Finding],
    blast_radii: list[BlastRadius],
    control_bypasses: list[dict],
    incident_matches: list[IncidentMatch],
) -> str:
    """Render flow maps for crews that have findings. Max 4 crews."""
    if not crews or graph is None:
        return ""

    ranked = _rank_crews_by_severity(crews, findings)
    if not ranked:
        return ""

    maps: list[str] = []
    for crew in ranked[:4]:
        m = render_crew_flow_map(
            crew, graph, blast_radii, control_bypasses, incident_matches,
        )
        if m:
            maps.append(m)

    return "\n\n".join(maps)


def render_crew_flow_map(
    crew: CrewDefinition,
    graph: RiskGraph,
    blast_radii: list[BlastRadius],
    control_bypasses: list[dict],
    incident_matches: list[IncidentMatch],
    max_width: int = MAX_WIDTH,
) -> str:
    """Render a single crew's flow diagram in a bordered box."""
    lines: list[str] = []
    crew_name = crew.name
    agent_names = crew.agent_names
    process_type = crew.process_type or "sequential"

    # Header
    header = f"{crew_name} ({len(agent_names)} agents, {process_type})"
    lines.append(f" {header}")
    lines.append(f" \u250c{'\u2500' * (max_width - 3)}\u2510")
    lines.append(_pad("", max_width))

    # Get data sources and external sinks from graph
    agent_labels = _get_agent_labels(graph, agent_names)
    data_sources = _get_crew_data_sources(graph, agent_names)
    external_sinks = _get_crew_external_sinks(graph, agent_names)

    # Agent chain
    chain = " \u2500\u2500\u25b6 ".join(agent_labels) if agent_labels else " \u2500\u2500\u25b6 ".join(agent_names)

    if data_sources:
        for ds in data_sources:
            sens = f" ({ds['sensitivity']})" if ds.get("sensitivity", "unknown") != "unknown" else ""
            lines.append(_pad(f"  {ds['label']}{sens}", max_width))
            lines.append(_pad(f"    \u2514\u2500\u2500\u25b6 {chain}", max_width))
    else:
        lines.append(_pad(f"  {chain}", max_width))

    # External sinks with gate markers
    for sink in external_sinks:
        control_marker = "\u2713 gated" if sink.get("has_control") else "\u26a0 no gate"
        via = sink.get("via_agent", "")
        pos = _find_agent_position(agent_names, via)
        indent = "      " + "     " * pos
        lines.append(_pad(f"{indent}\u251c\u2500\u2500\u25b6 {sink['label']}  {control_marker}", max_width))

    lines.append(_pad("", max_width))

    # Crew-specific bypasses
    crew_bypasses = [
        b for b in control_bypasses
        if crew_name in str(b.get("evidence", []))
        or crew_name == b.get("crew_name", "")
    ]
    for bypass in crew_bypasses:
        bypasser = bypass.get("downstream_agent", bypass.get("downstream", "?"))
        source = bypass.get("data_source", bypass.get("shared_source", "?"))
        lines.append(_pad(f"  \u26a0 BYPASS: {bypasser} reads {source} directly", max_width))

    # Crew-specific blast radii (deduplicated by tool name)
    crew_brs = [br for br in blast_radii if br.crew_name == crew_name]
    seen_tools: set[str] = set()
    for br in crew_brs:
        if br.source_label in seen_tools:
            continue
        seen_tools.add(br.source_label)
        lines.append(
            _pad(f"  \U0001f534 {br.source_label} shared by {br.agent_count} agents", max_width)
        )

    # Crew-specific incidents
    crew_incidents = _get_crew_incidents(incident_matches, crew_name, graph, agent_names)
    for incident in crew_incidents:
        lines.append(_pad(f"  \U0001f4ce Matches: {incident['name']}", max_width))

    # Add spacing if we had annotations
    if crew_bypasses or crew_brs or crew_incidents:
        lines.append(_pad("", max_width))

    # Footer
    lines.append(f" \u2514{'\u2500' * (max_width - 3)}\u2518")

    return "\n".join(lines)


def _pad(text: str, width: int) -> str:
    """Pad a line to fit within box borders."""
    inner = text[:width - 5]
    padding = width - 5 - len(inner)
    if padding < 0:
        padding = 0
    return f" \u2502 {inner}{' ' * padding} \u2502"


def _get_agent_labels(
    graph: RiskGraph, agent_names: list[str], max_total: int = 62,
) -> list[str]:
    """Get display labels for agents from graph nodes.

    Shortens names so the full chain fits within max_total characters.
    """
    # Resolve names from graph
    raw_labels: list[str] = []
    for name in agent_names:
        found = False
        for node in graph.nodes.values():
            if node.node_type == NodeType.AGENT and (
                node.label == name or node.id == name
            ):
                raw_labels.append(node.label)
                found = True
                break
        if not found:
            raw_labels.append(name)

    if not raw_labels:
        return raw_labels

    # Calculate how much space we have per agent
    # Chain = "A ──▶ B ──▶ C" — separator is " ──▶ " (5 chars)
    separator_total = (len(raw_labels) - 1) * 5
    available = max_total - separator_total
    max_per = max(8, available // len(raw_labels))

    labels: list[str] = []
    for label in raw_labels:
        if len(label) > max_per:
            labels.append(label[:max_per - 2] + "..")
        else:
            labels.append(label)
    return labels


def _get_crew_data_sources(
    graph: RiskGraph, agent_names: list[str],
) -> list[dict]:
    """Find data stores that feed into this crew's agents."""
    sources: list[dict] = []
    seen: set[str] = set()

    # Find agent node IDs
    agent_ids = _resolve_agent_ids(graph, agent_names)

    # Find capabilities (tools) of these agents
    cap_ids: set[str] = set()
    for edge in graph.edges:
        if edge.edge_type == EdgeType.TOOL_OF and edge.target in agent_ids:
            cap_ids.add(edge.source)

    # Find data stores that connect to these capabilities or agents
    for edge in graph.edges:
        if edge.edge_type == EdgeType.READS_FROM:
            # capability reads_from data_store
            if edge.source in cap_ids or edge.source in agent_ids:
                ds_node = graph.nodes.get(edge.target)
                if ds_node and ds_node.id not in seen:
                    seen.add(ds_node.id)
                    sources.append({
                        "label": ds_node.label,
                        "sensitivity": ds_node.data_sensitivity,
                    })

    return sources


def _get_crew_external_sinks(
    graph: RiskGraph, agent_names: list[str],
) -> list[dict]:
    """Find external services this crew's agents send data to."""
    sinks: list[dict] = []
    seen: set[str] = set()

    agent_ids = _resolve_agent_ids(graph, agent_names)

    # Find capabilities of these agents
    cap_to_agent: dict[str, str] = {}
    for edge in graph.edges:
        if edge.edge_type == EdgeType.TOOL_OF and edge.target in agent_ids:
            cap_to_agent[edge.source] = edge.target

    # Find external services reachable from capabilities
    for edge in graph.edges:
        if edge.edge_type in (EdgeType.SENDS_TO, EdgeType.CALLS, EdgeType.WRITES_TO):
            if edge.source in cap_to_agent:
                ext_node = graph.nodes.get(edge.target)
                if ext_node and ext_node.node_type in (
                    NodeType.EXTERNAL_SERVICE, NodeType.MCP_SERVER,
                ) and ext_node.id not in seen:
                    seen.add(ext_node.id)
                    # Find which agent this goes through
                    via_agent_id = cap_to_agent[edge.source]
                    via_agent_name = _agent_id_to_name(graph, via_agent_id, agent_names)
                    sinks.append({
                        "label": ext_node.label,
                        "has_control": edge.has_control,
                        "via_agent": via_agent_name,
                    })

    return sinks


def _resolve_agent_ids(graph: RiskGraph, agent_names: list[str]) -> set[str]:
    """Resolve agent names to graph node IDs."""
    ids: set[str] = set()
    for name in agent_names:
        for node in graph.nodes.values():
            if node.node_type == NodeType.AGENT and (
                node.label == name or node.id == name
            ):
                ids.add(node.id)
                break
    return ids


def _agent_id_to_name(
    graph: RiskGraph, agent_id: str, agent_names: list[str],
) -> str:
    """Convert agent node ID back to a display name."""
    node = graph.nodes.get(agent_id)
    if node:
        return node.label
    return agent_id


def _find_agent_position(agent_names: list[str], via_agent: str) -> int:
    """Find position of an agent in the chain for indentation."""
    for i, name in enumerate(agent_names):
        if name == via_agent or via_agent in name or name in via_agent:
            return i
    return 0


def _get_crew_incidents(
    incident_matches: list[IncidentMatch],
    crew_name: str,
    graph: RiskGraph,
    agent_names: list[str],
) -> list[dict]:
    """Find incidents related to this crew."""
    results: list[dict] = []
    crew_lower = crew_name.lower()

    for m in incident_matches:
        if m.confidence < 0.5:
            continue
        # Check if crew name appears in matching files or capabilities
        files_str = " ".join(getattr(m, "matching_files", [])).lower()
        caps_str = " ".join(getattr(m, "matching_capabilities", [])).lower()
        reason = (m.match_reason or "").lower()

        if (crew_lower in files_str or crew_lower in caps_str
                or crew_lower in reason
                or any(a.lower() in reason for a in agent_names)):
            results.append({
                "name": m.name,
                "confidence": m.confidence,
            })
            break  # One incident per crew

    return results


def _rank_crews_by_severity(
    crews: list[CrewDefinition], findings: list[Finding],
) -> list[CrewDefinition]:
    """Return crews sorted by severity of findings associated with them."""
    severity_scores = {
        Severity.CRITICAL: 100, Severity.HIGH: 50,
        Severity.MEDIUM: 10, Severity.LOW: 1,
    }
    scored: list[tuple[CrewDefinition, int]] = []
    for crew in crews:
        score = 0
        for f in findings:
            if (crew.name in str(f.evidence)
                    or crew.name in f.title
                    or any(a in f.title for a in crew.agent_names)):
                score += severity_scores.get(f.severity, 0)
        if score > 0:
            scored.append((crew, score))

    scored.sort(key=lambda x: -x[1])
    return [c for c, _ in scored]
