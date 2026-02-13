"""Verbose output sections — full finding details appended after action-oriented output."""
from __future__ import annotations

from rich.console import Console

from stratum.graph.models import EdgeType, NodeType, RiskGraph
from stratum.models import Finding, ScanResult, Severity
from stratum.research.citations import get_citation


SEVERITY_LABELS = {
    Severity.CRITICAL: "[bold red]CRITICAL[/bold red]",
    Severity.HIGH: "[bold yellow]HIGH[/bold yellow]",
    Severity.MEDIUM: "[yellow]MEDIUM[/yellow]",
    Severity.LOW: "[dim]LOW[/dim]",
}


def render_verbose_sections(result: ScanResult, console: Console) -> None:
    """Append full finding details, signals, incidents, and graph topology."""
    _render_full_findings(result, console)
    _render_full_signals(result, console)
    _render_full_incidents(result, console)
    _render_graph_topology(result, console)
    _render_per_crew_scores(result, console)


def _render_section_header(title: str, console: Console) -> None:
    console.print()
    console.rule(f"[bold]{title}[/bold]", style="bold")
    console.print()


def _render_full_findings(result: ScanResult, console: Console) -> None:
    if not result.top_paths:
        return
    _render_section_header("FULL FINDING DETAILS", console)
    graph = result.graph if hasattr(result, "graph") else None
    incidents = getattr(result, "incident_matches", None)
    for finding in result.top_paths:
        _render_finding_detail(finding, graph, incidents, console)
        console.print()


def _render_full_signals(result: ScanResult, console: Console) -> None:
    if not result.signals:
        return
    _render_section_header("SIGNALS", console)
    for signal in result.signals:
        _render_finding_detail(signal, None, None, console)
        console.print()


def _render_full_incidents(result: ScanResult, console: Console) -> None:
    matches = getattr(result, "incident_matches", None)
    if not matches:
        return
    _render_section_header("INCIDENT MATCHES", console)
    for match in matches:
        confidence = match.confidence if isinstance(match.confidence, (int, float)) else 0
        pct = int(confidence * 100)
        console.print(f"  [bold]\u25cf {match.name}[/bold] (confidence: {pct}%)")
        console.print(f"    {match.attack_summary}")
        if match.match_reason:
            console.print(f"    [dim]{match.match_reason}[/dim]")
        console.print(f"    Impact: {match.impact}")
        caps = getattr(match, "matching_capabilities", [])
        if caps:
            console.print(f"    Capabilities: {', '.join(caps)}")
        files = getattr(match, "matching_files", [])
        if files:
            console.print(f"    Files: {', '.join(files)}")
        url = match.source_url.replace("https://", "").replace("http://", "")
        console.print(f"    [dim]\u2197 {url}[/dim]")
        console.print()


def _render_graph_topology(result: ScanResult, console: Console) -> None:
    graph = getattr(result, "graph", None)
    if not graph or not hasattr(graph, "risk_surface"):
        return

    rs = graph.risk_surface
    if rs.total_nodes == 0:
        return

    _render_section_header("GRAPH TOPOLOGY", console)
    console.print(f"  Nodes: {rs.total_nodes}")
    console.print(f"  Edges: {rs.total_edges}")
    console.print(
        f"  Trust boundary crossings: {rs.trust_boundary_crossings}"
    )
    coverage_str = f"{rs.control_coverage_pct:.0f}%"
    console.print(
        f"  Control coverage: {coverage_str} "
        f"({rs.edges_with_controls}/{rs.edges_needing_controls})"
    )
    console.print(f"  Max chain depth: {rs.max_chain_depth}")
    console.print(f"  Uncontrolled paths: {len(graph.uncontrolled_paths)}")

    # Sensitive data types
    sens_types: set[str] = set()
    for path in graph.uncontrolled_paths:
        if path.source_sensitivity not in ("unknown", "public"):
            sens_types.add(path.source_sensitivity)
    if sens_types:
        console.print(f"  Sensitive data types: {', '.join(sorted(sens_types))}")
    console.print()


def _render_per_crew_scores(result: ScanResult, console: Console) -> None:
    per_crew = getattr(result, "_per_crew_scores", None)
    if not per_crew:
        return

    _render_section_header("PER-CREW RISK SCORES", console)
    if isinstance(per_crew, dict):
        for name, score in sorted(per_crew.items(), key=lambda x: -x[1]):
            console.print(f"  {name}: {score}/100")
    console.print()


def _render_finding_detail(
    finding: Finding,
    graph: RiskGraph | None,
    incident_matches: list | None,
    console: Console,
) -> None:
    """Render a finding with full detail."""
    sev_label = SEVERITY_LABELS.get(finding.severity, "")
    asi_str = f" \u00b7 {finding.owasp_id}" if finding.owasp_id else ""

    console.print(
        f"  {sev_label}  {finding.id}{asi_str}  [bold]{finding.title}[/bold]"
    )
    if finding.description:
        console.print(f"    {finding.description}")
    if finding.scenario:
        console.print(f"    [dim]Scenario: {finding.scenario}[/dim]")
    if finding.business_context:
        console.print(f"    [dim]Business: {finding.business_context}[/dim]")

    # Citation
    citation = get_citation(finding.id)
    if citation:
        console.print(f"    [dim]\u25b8 {citation.stat} -- {citation.source}[/dim]")

    # Evidence
    if finding.evidence:
        evidence_str = " \u00b7 ".join(finding.evidence)
        conf = finding.confidence.value.upper()
        console.print(f"    [dim]Evidence: {evidence_str} [{conf}][/dim]")

    # Remediation
    if finding.remediation:
        console.print(f"    [green]Fix: {finding.remediation}[/green]")

    # Graph paths
    if graph and finding.graph_paths:
        for path in finding.graph_paths[:2]:
            labels = []
            for nid in path.nodes:
                node = graph.nodes.get(nid)
                if node:
                    labels.append(node.label)
            if labels:
                console.print(f"    [dim]Path: {' \u2192 '.join(labels)}[/dim]")
