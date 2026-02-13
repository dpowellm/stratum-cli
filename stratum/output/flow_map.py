"""ASCII flow map renderer — the viral screenshot artifact.

Renders data flow paths as tree-style diagrams with risk markers,
grouped by crew when crew definitions are available.
"""
from __future__ import annotations

from stratum.graph.models import NodeType, RiskGraph, RiskPath
from stratum.models import BlastRadius


def render_flow_map(
    graph: RiskGraph,
    blast_radii: list[BlastRadius],
    control_bypasses: list[dict],
    crew_definitions: list | None = None,
) -> list[str]:
    """Render flow map sections for terminal output.

    Returns a list of Rich-formatted strings.  When *crew_definitions* is
    provided, diagrams are grouped under crew headers.
    """
    # Group blast_radii and bypasses by crew
    crew_brs: dict[str, list[BlastRadius]] = {}
    for br in blast_radii:
        if br.agent_count < 2:
            continue
        key = br.crew_name or "(ungrouped)"
        crew_brs.setdefault(key, []).append(br)

    crew_bps: dict[str, list[dict]] = {}
    for bp in control_bypasses:
        key = bp.get("crew_name", "") or "(ungrouped)"
        crew_bps.setdefault(key, []).append(bp)

    # Determine crew order: crews with more findings first
    all_crew_keys: list[str] = []
    seen: set[str] = set()
    for key in list(crew_brs.keys()) + list(crew_bps.keys()):
        if key not in seen:
            all_crew_keys.append(key)
            seen.add(key)

    sections: list[str] = []
    rendered_tools: set[str] = set()

    for crew_key in all_crew_keys[:4]:  # Cap at 4 crew sections
        crew_sections: list[str] = []

        # Blast radius diagrams for this crew (top 2 per crew)
        br_count = 0
        for br in crew_brs.get(crew_key, []):
            if br_count >= 2:
                break
            section = _render_blast_radius(graph, br)
            if section:
                crew_sections.append(section)
                rendered_tools.add(br.source_node_id)
                br_count += 1

        # Bypass diagrams for this crew
        rendered_bypasses: set[str] = set()
        for bp in crew_bps.get(crew_key, []):
            key = f"{bp['upstream_agent']}-{bp['downstream_agent']}"
            if key in rendered_bypasses:
                continue
            rendered_bypasses.add(key)
            section = _render_bypass(bp)
            if section:
                crew_sections.append(section)

        if crew_sections:
            if crew_key != "(ungrouped)":
                header = f"  [bold][ {crew_key} ][/bold]"
                sections.append(header + "\n" + "\n\n".join(crew_sections))
            else:
                sections.extend(crew_sections)

    # Uncontrolled path trees (not grouped by crew — global)
    if graph.uncontrolled_paths:
        source_groups = _group_paths_by_source(graph)
        for source_id, paths in source_groups.items():
            if source_id in rendered_tools:
                continue
            section = _render_source_tree(graph, source_id, paths)
            if section:
                sections.append(section)

    return sections[:6]


def _render_blast_radius(graph: RiskGraph, br: BlastRadius) -> str:
    """Render a blast radius diagram showing tool fan-out to agents."""
    lines: list[str] = []
    crew_ctx = f" in {br.crew_name}" if br.crew_name else ""

    lines.append(
        f"  [bold red]BLAST RADIUS[/bold red]: "
        f"[bold]{br.source_label}[/bold] -> "
        f"{br.agent_count} agents -> {br.external_count} external services"
    )
    lines.append("")
    lines.append(f"  [bold]{br.source_label}[/bold] (shared tool{crew_ctx})")

    # Build per-agent external services
    agent_externals: dict[str, list[str]] = {}
    for aid, alabel in zip(br.affected_agent_ids, br.affected_agent_labels):
        exts: list[str] = []
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

    for i, path in enumerate(paths[:5]):
        is_last = i == len(paths[:5]) - 1
        branch = "    L-->" if is_last else "    |-->"

        labels = [graph.nodes[nid].label for nid in path.nodes[1:] if nid in graph.nodes]
        path_str = " --> ".join(labels)

        control_marker = ""
        if not any(e.has_control for e in path.edges):
            control_marker = "  [red]!! no gate[/red]"

        lines.append(f"  {branch} {path_str}{control_marker}")

    return "\n".join(lines)
