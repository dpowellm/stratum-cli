"""ASCII flow map renderer — the viral screenshot artifact.

Renders data flow paths as tree-style diagrams with risk markers.
"""
from __future__ import annotations

from stratum.graph.models import NodeType, RiskGraph, RiskPath
from stratum.models import BlastRadius


def render_flow_map(
    graph: RiskGraph,
    blast_radii: list[BlastRadius],
    control_bypasses: list[dict],
) -> list[str]:
    """Render flow map sections for terminal output.

    Returns a list of Rich-formatted strings, one per data source group.
    Each group shows a tree-style diagram of data flows from that source.
    """
    sections: list[str] = []

    # Render blast radius diagrams (highest impact first, top 3)
    rendered_tools: set[str] = set()
    br_count = 0
    for br in blast_radii:
        if br.agent_count < 2 or br_count >= 3:
            continue
        section = _render_blast_radius(graph, br)
        if section:
            sections.append(section)
            rendered_tools.add(br.source_node_id)
            br_count += 1

    # Render control bypass diagrams
    rendered_bypasses: set[str] = set()
    for bp in control_bypasses:
        key = f"{bp['upstream_agent']}-{bp['downstream_agent']}"
        if key in rendered_bypasses:
            continue
        rendered_bypasses.add(key)
        section = _render_bypass(bp)
        if section:
            sections.append(section)

    # Render uncontrolled path trees (grouped by data source)
    if graph.uncontrolled_paths:
        source_groups = _group_paths_by_source(graph)
        for source_id, paths in source_groups.items():
            if source_id in rendered_tools:
                continue
            section = _render_source_tree(graph, source_id, paths)
            if section:
                sections.append(section)

    return sections[:6]  # Cap at 6 sections to avoid wall of text


def _render_blast_radius(graph: RiskGraph, br: BlastRadius) -> str:
    """Render a blast radius diagram showing tool fan-out to agents."""
    lines: list[str] = []

    # Header
    lines.append(
        f"  [bold red]BLAST RADIUS[/bold red]: "
        f"[bold]{br.source_label}[/bold] -> "
        f"{br.agent_count} agents -> {br.external_count} external services"
    )
    lines.append("")

    # Tree: tool -> agents -> externals
    lines.append(f"  [bold]{br.source_label}[/bold] (shared tool)")

    # Build per-agent external services
    agent_externals: dict[str, list[str]] = {}
    for aid, alabel in zip(br.affected_agent_ids, br.affected_agent_labels):
        exts: list[str] = []
        # Find tools this agent owns
        agent_tools = [
            e.source for e in graph.edges
            if e.edge_type.value == "tool_of" and e.target == aid
        ]
        for tool_id in agent_tools:
            for e in graph.edges:
                if e.source == tool_id and e.edge_type.value == "sends_to":
                    ext_node = graph.nodes.get(e.target)
                    if ext_node:
                        exts.append(ext_node.label)
        agent_externals[alabel] = sorted(set(exts))

    for i, alabel in enumerate(br.affected_agent_labels):
        is_last = i == len(br.affected_agent_labels) - 1
        branch = "    L-->" if is_last else "    |-->"
        exts = agent_externals.get(alabel, [])
        ext_str = f" -> [{', '.join(exts)}]" if exts else ""
        lines.append(f"  {branch} {alabel}{ext_str}")

    lines.append("")

    # Impact statement
    if br.agent_count >= 3:
        lines.append(
            f"  [dim]If {br.source_label} returns poisoned data, "
            f"{br.agent_count} agents are compromised simultaneously.[/dim]"
        )
    elif br.agent_count >= 2:
        lines.append(
            f"  [dim]{br.source_label} is shared by {br.agent_count} agents "
            f"with no isolation.[/dim]"
        )

    return "\n".join(lines)


def _render_bypass(bp: dict) -> str:
    """Render a control bypass diagram."""
    lines: list[str] = []
    lines.append(
        f"  [bold yellow]BYPASS[/bold yellow]: "
        f"[bold]{bp['downstream_agent']}[/bold] reads "
        f"[bold]{bp['data_source']}[/bold] directly, "
        f"bypassing [bold]{bp['upstream_agent']}[/bold]"
    )
    lines.append("")
    lines.append(f"  {bp['data_source']}")
    lines.append(f"    |-->[dim] {bp['upstream_agent']}[/dim]  (intended filter)")
    lines.append(f"    L-->[bold] {bp['downstream_agent']}[/bold]  [red](direct access)[/red]")
    lines.append("")
    lines.append(
        f"  [dim]The filter is architecturally irrelevant -- "
        f"data reaches {bp['downstream_agent']} unfiltered.[/dim]"
    )
    return "\n".join(lines)


def _group_paths_by_source(graph: RiskGraph) -> dict[str, list[RiskPath]]:
    """Group uncontrolled paths by their source data store."""
    groups: dict[str, list[RiskPath]] = {}
    for path in graph.uncontrolled_paths:
        if path.nodes:
            source_id = path.nodes[0]
            groups.setdefault(source_id, []).append(path)
    return groups


def _render_source_tree(
    graph: RiskGraph, source_id: str, paths: list[RiskPath],
) -> str:
    """Render a tree of paths from a single data source."""
    source_node = graph.nodes.get(source_id)
    if not source_node:
        return ""

    lines: list[str] = []
    sensitivity = source_node.data_sensitivity
    sens_tag = f" ({sensitivity})" if sensitivity not in ("unknown", "public") else ""

    lines.append(f"  [bold]{source_node.label}[/bold]{sens_tag}")

    # Build tree of unique next-hops
    for i, path in enumerate(paths[:5]):
        is_last = i == len(paths[:5]) - 1
        branch = "    L-->" if is_last else "    |-->"

        # Show intermediate nodes and final destination
        labels = [graph.nodes[nid].label for nid in path.nodes[1:] if nid in graph.nodes]
        path_str = " --> ".join(labels)

        control_marker = ""
        if not any(e.has_control for e in path.edges):
            control_marker = "  [red]!! no gate[/red]"

        lines.append(f"  {branch} {path_str}{control_marker}")

    return "\n".join(lines)
