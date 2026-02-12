"""Rich terminal output for Stratum scan results."""
from __future__ import annotations

import os

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from stratum.models import Finding, RiskCategory, ScanResult, Severity
from stratum.graph.models import EdgeType, NodeType, RiskGraph
from stratum.output.remediation import select_quick_wins, compute_estimated_score, QuickWin
from stratum.output.badge import generate_badge_markdown
from stratum.research.citations import get_citation
from stratum.research.mcp_risk import risk_label
from stratum.research.links import select_research_links

console = Console(force_terminal=True)

SEVERITY_ICONS = {
    Severity.CRITICAL: "[bold red]CRITICAL[/bold red]",
    Severity.HIGH: "[bold yellow]HIGH[/bold yellow]",
    Severity.MEDIUM: "[yellow]MED[/yellow]",
    Severity.LOW: "[dim]LOW[/dim]",
}

SEVERITY_DOTS = {
    Severity.CRITICAL: "[bold red]\u25cf[/bold red]",
    Severity.HIGH: "[bold yellow]\u25cf[/bold yellow]",
    Severity.MEDIUM: "[yellow]\u25cf[/yellow]",
    Severity.LOW: "[dim]\u25cf[/dim]",
}

# Finding class ordering for --dev mode (reliability-first)
FINDING_CLASS_ORDER = {
    "reliability": 0,
    "operational": 1,
    "learning": 2,
    "governance": 3,
    "security": 4,
}
FINDING_CLASS_LABELS = {
    "reliability": "RELIABILITY",
    "operational": "OPERATIONAL",
    "learning": "LEARNING & DRIFT RISK",
    "governance": "GOVERNANCE ARCHITECTURE",
    "security": "SECURITY",
}

SEVERITY_SORT = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}

# Audit summary checklist for low-finding scans (<=2 findings)
RULE_CHECKLIST = [
    ("STRATUM-001", "No data exfiltration paths"),
    ("STRATUM-002", "No unguarded destructive tools"),
    ("STRATUM-003", "No code execution via tools"),
    ("STRATUM-004", "No known MCP vulnerabilities"),
    ("STRATUM-005", "No credential exposure"),
    ("STRATUM-006", "No supply chain risk"),
    ("STRATUM-007", "No unvalidated financial ops"),
    ("STRATUM-008", "All external calls have error handling"),
    ("STRATUM-009", "All HTTP calls have timeouts"),
    ("STRATUM-010", "Agent state is persisted"),
]


def render(result: ScanResult, verbose: bool = False,
           security_mode: bool = False) -> None:
    """Render the scan result to the terminal using Rich."""
    all_findings = result.top_paths + result.signals
    quick_wins = select_quick_wins(all_findings, result)

    _render_header(result)
    _render_summary_line(result)
    _render_agent_profile(result, quick_wins)
    _render_incident_matches(result)
    _render_flow_map(result)
    _render_known_incidents(result)
    if result.diff:
        _render_progress(result)
    if len(all_findings) <= 2:
        _render_audit_summary(result, all_findings)
        _render_quick_wins(result, quick_wins)
    elif security_mode:
        _render_top_paths_security(result)
        _render_learning_governance_sections(result)
        _render_quick_wins(result, quick_wins)
        _render_signals(result, verbose, quick_wins)
    else:
        _render_top_paths_dev(result)
        _render_quick_wins(result, quick_wins)
    _render_learn_more(result)
    _render_quick_actions(result)
    _render_whats_next(result, quick_wins)
    _render_footer(result)


# ── Agent Profile ─────────────────────────────────────────────────────────────

def _render_header(result: ScanResult) -> None:
    """Render the header banner."""
    header = Text()
    header.append("  STRATUM ", style="bold white")
    header.append("v0.1 -- AI Agent Security Audit", style="dim")
    console.print(Panel(header, style="bold blue"))


def _render_summary_line(result: ScanResult) -> None:
    """Render a tweetable summary line (<=80 chars)."""
    all_findings = result.top_paths + result.signals
    sev_counts: dict[str, int] = {}
    for f in all_findings:
        sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

    parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = sev_counts.get(sev, 0)
        if count:
            parts.append(f"{count} {sev.lower()}")

    finding_str = " \u00b7 ".join(parts) if parts else "0 findings"
    guard_str = f"{result.guardrail_count} guardrails" if result.guardrail_count else "0 guardrails"
    line = f"{finding_str}    Risk: {result.risk_score}/100    {guard_str}"
    console.print(f" [bold]{line.strip()}[/bold]")
    console.print()


def _render_audit_summary(result: ScanResult, findings: list[Finding]) -> None:
    """Render checklist-style audit summary for low-finding scans.

    Called when len(findings) <= 2. Shows what was checked and what passed,
    so the user sees the tool did real work even when few risks were found.
    """
    finding_ids = {f.id for f in findings}
    finding_by_id: dict[str, Finding] = {}
    for f in findings:
        if f.id not in finding_by_id:
            finding_by_id[f.id] = f

    console.rule("[bold]AUDIT SUMMARY[/bold]", style="bold")
    console.print()

    checklist_ids = {rule_id for rule_id, _ in RULE_CHECKLIST}
    for rule_id, pass_text in RULE_CHECKLIST:
        if rule_id in finding_ids:
            f = finding_by_id[rule_id]
            # Extract file:line from evidence if available
            loc = ""
            if f.evidence:
                loc = f" \u2192 {f.evidence[0]}"
            console.print(f"  [yellow]\u26a0[/yellow]  {f.title}{loc}")
        else:
            console.print(f"  [green]\u2713[/green]  {pass_text}")

    # Show any non-core findings (governance, learning, etc.)
    other_findings = [f for f in findings if f.id not in checklist_ids]
    for f in other_findings:
        loc = ""
        if f.evidence:
            loc = f" \u2192 {f.evidence[0]}"
        console.print(f"  [yellow]\u26a0[/yellow]  {f.title}{loc}")

    console.print()

    # Scan scope line
    n_py = result.files_scanned
    n_mcp = result.mcp_configs_scanned
    n_env = result.env_files_scanned
    py_label = f"{n_py} Python file{'s' if n_py != 1 else ''}"
    mcp_label = f"{n_mcp} MCP config{'s' if n_mcp != 1 else ''}"
    env_label = f"{n_env} .env file{'s' if n_env != 1 else ''}"
    console.print(f"  Scanned {py_label}, {mcp_label}, {env_label}.")

    # Zero-finding verdict
    if len(findings) == 0:
        console.print("  No findings across 10 risk rules. Clean scan.")

    # Low-capability nudge
    if result.total_capabilities <= 2 and result.mcp_server_count == 0:
        console.print()
        console.print(
            "  [dim]Your project has a small capability surface. Stratum's value[/dim]"
        )
        console.print(
            "  [dim]increases with agent complexity \u2014 try scanning a project with[/dim]"
        )
        console.print(
            "  [dim]MCP servers, multiple tools, or shared state.[/dim]"
        )

    console.print()


def _render_agent_profile(result: ScanResult, quick_wins: list[QuickWin]) -> None:
    """Render the Agent Profile section."""
    # Count unique functions with capabilities
    func_names = set()
    for cap in result.capabilities:
        func_names.add(cap.function_name)
    func_count = len(func_names)

    console.print(" [bold]Agent Profile[/bold]")
    console.print(" " + "\u2500" * 13)

    # Framework
    if result.detected_frameworks:
        fw_str = " \u00b7 ".join(result.detected_frameworks)
        console.print(f" Framework       {fw_str}")

    # Agents (from agent definitions)
    agent_defs = getattr(result, 'agent_definitions', [])
    if agent_defs:
        agent_names = " \u00b7 ".join(ad.role or ad.name for ad in agent_defs)
        console.print(f" Agents          {agent_names}")

    # Capabilities
    console.print(f" Capabilities    {result.total_capabilities} across {func_count} functions")

    # Architecture breakdown
    arch_parts = []
    if result.outbound_count:
        arch_parts.append(f"{result.outbound_count} outbound")
    if result.data_access_count:
        arch_parts.append(f"{result.data_access_count} data access")
    if result.code_exec_count:
        arch_parts.append(f"{result.code_exec_count} code exec")
    if result.destructive_count:
        arch_parts.append(f"{result.destructive_count} destructive")
    if result.financial_count:
        arch_parts.append(f"{result.financial_count} financial")
    console.print(f" Architecture    {' \u00b7 '.join(arch_parts)}")

    # MCP Servers
    mcp_needing_attention = sum(
        1 for s in result.mcp_servers
        if not s.is_known_safe and (
            (s.npm_package and not s.package_version)
            or (s.is_remote and not s.has_auth)
            or s.env_vars_passed
        )
    )
    mcp_str = f"{result.mcp_server_count} configured"
    if mcp_needing_attention:
        mcp_str += f" ({mcp_needing_attention} need{'s' if mcp_needing_attention == 1 else ''} attention)"
    console.print(f" MCP Servers     {mcp_str}")

    # MCP composite risk (when >=2 servers)
    if result.mcp_server_count >= 2:
        rl = risk_label(result.mcp_server_count)
        if rl:
            console.print(f"                 {rl}  [dim]\\[Pynt, 2025][/dim]")
            if result.mcp_server_count >= 5:
                console.print("                 [dim]Most agent projects we see have 2-3 servers.[/dim]")

    # Data types (inferred from graph)
    graph: RiskGraph | None = result.graph  # type: ignore[assignment]
    if graph and graph.risk_surface.sensitive_data_types:
        types = graph.risk_surface.sensitive_data_types
        type_labels = []
        for t in types:
            # Find which library inferred this type
            source_lib = ""
            for node in graph.nodes.values():
                if node.data_sensitivity == t and node.node_type == NodeType.DATA_STORE:
                    source_lib = node.label
                    break
            if source_lib:
                type_labels.append(f"{t.upper()} (inferred from {source_lib})")
            else:
                type_labels.append(t.upper())
        console.print(f" Data types      {', '.join(type_labels)}")

    # Guardrails
    if result.has_any_guardrails:
        console.print(f" Guardrails      {result.guardrail_count} detected")
    else:
        console.print(" Guardrails      none detected")

    # State
    state_labels = {
        "durable": "durable (PostgresSaver or equivalent)",
        "memory_only": "in-memory only (MemorySaver)",
        "none": "no checkpointing detected",
    }
    console.print(f" State           {state_labels.get(result.checkpoint_type, result.checkpoint_type)}")

    # Archetype (from telemetry profile if available)
    archetype = getattr(result, '_archetype', None)
    if archetype and archetype != "custom":
        console.print(f" Archetype       {archetype}")

    console.print()

    # Risk score
    score = result.risk_score
    bar_filled = score // 5
    bar_empty = 20 - bar_filled
    bar = "\u2588" * bar_filled + "\u2591" * bar_empty

    if score >= 80:
        level = "[bold red]high[/bold red]"
    elif score >= 60:
        level = "[bold yellow]elevated[/bold yellow]"
    elif score >= 40:
        level = "[yellow]medium[/yellow]"
    else:
        level = "[green]low[/green]"

    console.print(f" Risk Score      {score}/100    {bar}  {level}")

    # Quick wins hint or diff info
    if result.diff:
        delta = result.diff.risk_score_delta
        arrow = "\u25bc" if delta < 0 else ("\u25b2" if delta > 0 else "\u25cf")
        sign = "+" if delta > 0 else ""
        remaining = len(quick_wins)
        console.print(
            f"                 {arrow} {sign}{delta} from last scan"
            + (f" \u00b7 {remaining} quick win{'s' if remaining != 1 else ''} available" if remaining else "")
        )
    elif quick_wins:
        estimated = compute_estimated_score(result, quick_wins)
        if estimated < result.risk_score:
            console.print(
                f"                 {len(quick_wins)} quick win{'s' if len(quick_wins) != 1 else ''} "
                f"available -> estimated {estimated} after fixes"
            )
        else:
            console.print(
                f"                 {len(quick_wins)} quick win{'s' if len(quick_wins) != 1 else ''} "
                f"available -- fix critical issues first to lower score"
            )

    console.print()


# ── Data Flow Map ───────────────────────────────────────────────────────────

def _render_flow_map(result: ScanResult) -> None:
    """Render the DATA FLOW MAP section when graph has >= 3 nodes."""
    graph: RiskGraph | None = result.graph  # type: ignore[assignment]
    if graph is None:
        return
    if len(graph.nodes) < 3:
        return
    if not graph.uncontrolled_paths:
        return

    console.rule("[bold]\u2550 HOW YOUR DATA FLOWS[/bold]", style="bold")
    console.print()

    # Group paths by agent if agents exist
    agent_nodes = {
        nid: n for nid, n in graph.nodes.items()
        if n.node_type == NodeType.AGENT
    }

    if agent_nodes:
        # Map capabilities to their owning agent
        cap_to_agent: dict[str, str] = {}
        for edge in graph.edges:
            if edge.edge_type == EdgeType.TOOL_OF:
                cap_to_agent[edge.source] = edge.target

        rendered: set[str] = set()
        for agent_id, agent_node in agent_nodes.items():
            agent_caps = {cid for cid, aid in cap_to_agent.items() if aid == agent_id}
            agent_paths = [
                p for p in graph.uncontrolled_paths
                if any(nid in agent_caps for nid in p.nodes)
            ]
            if not agent_paths:
                continue

            console.print(f" [bold][{agent_node.label}][/bold]")
            for path in agent_paths:
                line = _render_flow_path_line(path, graph)
                if line not in rendered:
                    rendered.add(line)
                    console.print(line)
            console.print()

        # Paths not assigned to any agent
        unassigned = [
            p for p in graph.uncontrolled_paths
            if not any(nid in cap_to_agent for nid in p.nodes)
        ]
        for path in unassigned:
            line = _render_flow_path_line(path, graph)
            if line not in rendered:
                rendered.add(line)
                console.print(line)
        if unassigned:
            console.print()

    else:
        # No agents - flat list of paths
        rendered: set[str] = set()
        for path in graph.uncontrolled_paths[:5]:
            line = _render_flow_path_line(path, graph)
            if line not in rendered:
                rendered.add(line)
                console.print(line)
        console.print()

    # Summary line
    if graph.uncontrolled_paths:
        top = graph.uncontrolled_paths[0]
        sink_count = _count_sinks(graph)
        sens = top.source_sensitivity.upper() if top.source_sensitivity != "unknown" else "Data"
        missing = len(top.missing_controls)
        console.print(
            f"  {sens} reaches {sink_count} external service(s) "
            f"with {missing} missing control(s)."
        )

    # Regulatory surface
    all_reg_flags: set[str] = set()
    for path in graph.uncontrolled_paths:
        all_reg_flags.update(path.regulatory_flags)
    if all_reg_flags:
        console.print(f"  Regulatory: {' \u00b7 '.join(sorted(all_reg_flags))}")
        console.print(
            "  [dim]Regulatory surface: flags where this path may "
            "intersect compliance requirements.[/dim]"
        )

    console.print()


def _render_flow_path_line(path, graph: RiskGraph) -> str:
    """Render one uncontrolled path as a flow line with arrow notation."""
    nodes = [graph.nodes[nid] for nid in path.nodes]
    source = nodes[0]
    dest = nodes[-1]
    middle = nodes[1:-1]

    # Source with sensitivity tag
    sens_tag = ""
    if source.data_sensitivity not in ("unknown", "public"):
        sens_tag = f" ({source.data_sensitivity})"

    # Build chain parts
    parts = [f"  {source.label}{sens_tag}"]
    for m in middle:
        parts.append(m.label)

    # Destination with control marker
    has_gap = any(
        not e.has_control and _edge_needs_control_marker(e, graph.nodes.get(e.source), graph.nodes.get(e.target))
        for e in path.edges
        if graph.nodes.get(e.source) and graph.nodes.get(e.target)
    )
    control = "  [yellow]\u26a0 no filter[/yellow]" if has_gap else ""
    parts.append(f"{dest.label}{control}")

    return "  \u2500\u2500\u25b6  ".join(parts)


def _edge_needs_control_marker(edge, source, target) -> bool:
    """Check if an edge should show a warning marker."""
    if target.node_type in (NodeType.EXTERNAL_SERVICE, NodeType.MCP_SERVER):
        return True
    if edge.data_sensitivity in ("personal", "financial", "credentials"):
        return True
    return False


def _count_sinks(graph: RiskGraph) -> int:
    """Count the number of external sink nodes in the graph."""
    return len([
        n for n in graph.nodes.values()
        if n.node_type in (NodeType.EXTERNAL_SERVICE, NodeType.MCP_SERVER)
    ])


# ── Incident Matches ─────────────────────────────────────────────────────────

def _render_incident_matches(result: ScanResult) -> None:
    """Render real-world incident matches from graph topology analysis."""
    matches = getattr(result, 'incident_matches', None)
    if not matches:
        return

    # Show the highest-confidence match
    top = matches[0]
    if top["confidence"] < 0.5:
        return

    console.rule("[bold red]KNOWN INCIDENT MATCH[/bold red]", style="bold red")
    console.print()
    console.print(f"  [bold]{top['name']}[/bold] ({top['date']})")
    console.print(f"  Impact: {top['impact']}")
    console.print()
    console.print(f"  {top['attack_summary']}")
    console.print()
    # Short URL for display
    url = top["source_url"].replace("https://", "").replace("http://", "")
    console.print(f"  [dim]Source: {url}[/dim]")
    console.print()


# ── Known Incidents ──────────────────────────────────────────────────────────

def _render_known_incidents(result: ScanResult) -> None:
    """Render known incident warnings for MCP servers."""
    for server in result.mcp_servers:
        if not server.known_incidents:
            continue
        for incident in server.known_incidents:
            cve_str = f" {incident.cve}" if incident.cve else ""
            cvss_str = ""
            if "CVSS" in incident.description:
                # Extract CVSS from description
                import re
                m = re.search(r"CVSS (\d+\.?\d*)", incident.description)
                if m:
                    cvss_str = f" (CVSS {m.group(1)})"
            elif incident.cve:
                cvss_str = ""

            console.print(
                f" [bold red]!!  KNOWN INCIDENT[/bold red]  "
                f"{server.name} has{cve_str}{cvss_str}"
            )
            console.print(f"    {incident.description}")
            if incident.fixed_version and incident.fixed_version not in ("removed from npm", "patched"):
                console.print(
                    f"    [green]Fix: pin to {incident.package}@{incident.fixed_version} or later.[/green]"
                )
            elif incident.fixed_version == "removed from npm":
                console.print(f"    [red]Package removed from npm. Remove from your config.[/red]")
            console.print()


# ── Top Risk Paths ────────────────────────────────────────────────────────────

def _render_top_paths_security(result: ScanResult) -> None:
    """Render the top risk paths in security mode (severity-first)."""
    if not result.top_paths:
        return

    console.rule("[bold]TOP RISK PATHS[/bold]", style="bold")
    console.print()
    graph = result.graph if hasattr(result, "graph") else None
    for finding in result.top_paths:
        _render_finding_compact(finding, graph)
        console.print()


def _render_top_paths_dev(result: ScanResult) -> None:
    """Render all findings in dev mode (reliability-first with class grouping)."""
    all_findings = result.top_paths + result.signals
    if not all_findings:
        return

    console.rule("[bold]WHAT WILL BREAK FIRST[/bold]", style="bold")
    console.print()

    # Sort findings by class then severity
    sorted_findings = sorted(
        all_findings,
        key=lambda f: (
            FINDING_CLASS_ORDER.get(f.finding_class, 2),
            SEVERITY_SORT.get(f.severity, 3),
        ),
    )

    graph = result.graph if hasattr(result, "graph") else None
    current_class = None
    for finding in sorted_findings:
        fc = finding.finding_class
        if fc != current_class:
            current_class = fc
            label = FINDING_CLASS_LABELS.get(fc, fc.upper())
            console.print(f" [bold dim]{label}[/bold dim]")
            console.print()

        _render_finding_compact(finding, graph)
        console.print()


def _render_learning_governance_sections(result: ScanResult) -> None:
    """Render LEARNING & DRIFT RISK and GOVERNANCE ARCHITECTURE sections (security mode)."""
    all_findings = result.top_paths + result.signals

    learning_findings = [f for f in all_findings if f.finding_class == "learning"]
    governance_findings = [f for f in all_findings if f.finding_class == "governance"]

    graph = result.graph if hasattr(result, "graph") else None
    if learning_findings:
        console.rule("[bold]LEARNING & DRIFT RISK[/bold]", style="bold")
        console.print()
        for finding in learning_findings:
            _render_finding_compact(finding, graph)
            console.print()

    if governance_findings:
        console.rule("[bold]GOVERNANCE ARCHITECTURE[/bold]", style="bold")
        console.print()
        for finding in governance_findings:
            _render_finding_compact(finding, graph)
            console.print()


def _render_finding_compact(finding: Finding, graph: RiskGraph | None = None) -> None:
    """Render a finding in compact attack-scenario format with ASI ID and citation."""
    sev_label = {
        Severity.CRITICAL: "[bold red]CRITICAL[/bold red]",
        Severity.HIGH: "[bold yellow]HIGH    [/bold yellow]",
        Severity.MEDIUM: "[yellow]MEDIUM  [/yellow]",
        Severity.LOW: "[dim]LOW     [/dim]",
    }.get(finding.severity, "")

    # Include ASI ID after STRATUM ID
    asi_str = f" \u00b7 {finding.owasp_id}" if finding.owasp_id else ""

    # Graph-enhanced annotation for path-based findings
    graph_annotation = _get_graph_annotation(finding, graph)

    console.print(f"  {sev_label}  {finding.id}{asi_str}  [bold]{finding.title}[/bold]{graph_annotation}")

    # Graph-enhanced path display
    graph_path = _get_graph_path(finding, graph)
    if graph_path:
        console.print(f"  {graph_path}")
    elif finding.description:
        console.print(f"  {finding.description}")

    # Citation line (dimmed)
    citation = get_citation(finding.id)
    if citation:
        console.print(f"  [dim]\u25b8 {citation.stat} -- {citation.source}[/dim]")

    # Regulatory flags from graph
    reg_flags = _get_regulatory_flags(finding, graph)
    if reg_flags:
        console.print(f"  [dim]Regulatory: {' \u00b7 '.join(reg_flags)}[/dim]")

    if finding.evidence:
        evidence_str = " \u00b7 ".join(finding.evidence)
        conf = finding.confidence.value.upper()
        console.print(f"  [dim]Evidence: {evidence_str}[/dim] [dim]\\[{conf}][/dim]")


def _get_graph_annotation(finding: Finding, graph: RiskGraph | None) -> str:
    """Get graph-enhanced annotation like '(2 hops, PII)' for path findings."""
    if graph is None or not graph.uncontrolled_paths:
        return ""
    if finding.id not in ("STRATUM-001", "STRATUM-002", "STRATUM-007"):
        return ""

    for path in graph.uncontrolled_paths:
        if _path_matches_finding(path, finding, graph):
            sens = path.source_sensitivity.upper() if path.source_sensitivity != "unknown" else ""
            parts = []
            parts.append(f"{path.hops} hop{'s' if path.hops != 1 else ''}")
            if sens:
                parts.append(sens)
            return f"  [dim]({', '.join(parts)})[/dim]"
    return ""


def _get_graph_path(finding: Finding, graph: RiskGraph | None) -> str:
    """Get graph-enhanced path display with full node labels."""
    if graph is None or not graph.uncontrolled_paths:
        return ""
    if finding.id not in ("STRATUM-001", "STRATUM-002", "STRATUM-007"):
        return ""

    for path in graph.uncontrolled_paths:
        if _path_matches_finding(path, finding, graph):
            labels = []
            for nid in path.nodes:
                node = graph.nodes.get(nid)
                if node:
                    labels.append(node.label)
            # Insert control gap markers between nodes
            parts: list[str] = []
            for i, label in enumerate(labels):
                if i > 0 and i - 1 < len(path.edges):
                    edge = path.edges[i - 1]
                    if not edge.has_control and edge.edge_type in (EdgeType.SENDS_TO, EdgeType.CALLS):
                        parts.append("\\[no filter]")
                parts.append(label)
            return " \u2192 ".join(parts)
    return ""


def _get_regulatory_flags(finding: Finding, graph: RiskGraph | None) -> list[str]:
    """Get regulatory flags for a finding from graph paths."""
    if graph is None or not graph.uncontrolled_paths:
        return []
    if finding.id not in ("STRATUM-001", "STRATUM-002", "STRATUM-007"):
        return []

    for path in graph.uncontrolled_paths:
        if _path_matches_finding(path, finding, graph):
            return path.regulatory_flags
    return []


def _path_matches_finding(path, finding: Finding, graph: RiskGraph) -> bool:
    """Check if a graph risk path corresponds to a specific finding."""
    if finding.id == "STRATUM-001":
        # Exfiltration: path from data_store to external_service
        if path.nodes:
            src = graph.nodes.get(path.nodes[0])
            dst = graph.nodes.get(path.nodes[-1])
            if (src and dst
                    and src.node_type == NodeType.DATA_STORE
                    and dst.node_type == NodeType.EXTERNAL_SERVICE):
                return True
    elif finding.id == "STRATUM-002":
        # Destructive: path ending at a destructive write
        for nid in path.nodes:
            node = graph.nodes.get(nid)
            if node and node.node_type == NodeType.CAPABILITY and "destructive" in node.id:
                return True
    elif finding.id == "STRATUM-007":
        # Financial: path involving financial nodes
        for nid in path.nodes:
            node = graph.nodes.get(nid)
            if node and node.data_sensitivity == "financial":
                return True
    return False


# ── Quick Wins ────────────────────────────────────────────────────────────────

def _render_quick_wins(result: ScanResult, quick_wins: list[QuickWin]) -> None:
    """Render the Quick Wins section with diffs."""
    if not quick_wins:
        return

    total_impact = sum(qw.score_impact for qw in quick_wins)
    total_effort = _sum_effort(quick_wins)

    impact_str = f" \u00b7 {total_impact:+d} points" if total_impact != 0 else ""
    console.rule(
        f"[bold]QUICK WINS[/bold]                              "
        f"{total_effort} total{impact_str}",
        style="bold",
    )
    console.print()

    for qw in quick_wins:
        pts_str = f" \u00b7 {qw.score_impact:+d} pts" if qw.score_impact != 0 else ""
        console.print(
            f" {qw.rank}. [bold]{qw.title}[/bold]"
            f"{'':>30}{qw.effort_label}{pts_str}"
        )
        console.print(f"    {qw.description}")

        if qw.command:
            console.print(f"    [cyan]$ {qw.command}[/cyan]")
            console.print()
            continue

        # Render diffs from remediations
        for rem in qw.remediations:
            console.print()
            if rem.line_number:
                console.print(f"    [dim]{rem.file_path}:{rem.line_number}[/dim]")
            elif rem.file_path and rem.file_path != "(multiple files)" and rem.file_path != "(financial tool file)" and rem.file_path != "MCP config":
                console.print(f"    [dim]{rem.file_path}[/dim]")

            for line in rem.diff_lines:
                if line.startswith("- "):
                    console.print(f"    [red]{line}[/red]")
                elif line.startswith("+ "):
                    console.print(f"    [green]{line}[/green]")
                else:
                    console.print(f"    [dim]{line}[/dim]")

        console.print()


def _sum_effort(quick_wins: list[QuickWin]) -> str:
    """Sum effort labels into a human-readable total."""
    from stratum.output.remediation import EFFORT_SECONDS, DESCRIPTIONS
    total_seconds = 0
    for qw in quick_wins:
        # Find matching fix type
        for fix_type, desc in DESCRIPTIONS.items():
            if desc == qw.title:
                total_seconds += EFFORT_SECONDS.get(fix_type, 60)
                break
        else:
            total_seconds += 60

    if total_seconds < 60:
        return f"~{total_seconds} sec"
    minutes = total_seconds // 60
    return f"~{minutes} min"


# ── Signals ───────────────────────────────────────────────────────────────────

def _render_signals(result: ScanResult, verbose: bool, quick_wins: list[QuickWin]) -> None:
    """Render the OTHER SIGNALS section."""
    if not result.signals:
        return

    # Find which finding IDs are covered by quick wins
    qw_ids = set()
    for qw in quick_wins:
        for rem in qw.remediations:
            qw_ids.add(rem.finding_id)

    console.rule(f"[bold]OTHER SIGNALS[/bold]", style="bold")
    console.print()

    if verbose:
        for finding in result.signals:
            _render_finding_full(finding)
            console.print("\u2500" * 60)
            console.print()
    else:
        for finding in result.signals:
            sev_short = {
                Severity.CRITICAL: "[bold red]CRIT[/bold red]",
                Severity.HIGH: "[bold yellow]HIGH[/bold yellow]",
                Severity.MEDIUM: "[yellow]MED [/yellow]",
                Severity.LOW: "[dim]LOW [/dim]",
            }.get(finding.severity, "")

            qw_note = ""
            if finding.id in qw_ids:
                qw_note = " [dim](see quick wins)[/dim]"

            asi_str = f" \u00b7 {finding.owasp_id}" if finding.owasp_id else ""
            console.print(
                f"  {sev_short}      {finding.id}{asi_str}  {finding.title}"
                f"   {finding.category.value} \u00b7 {finding.confidence.value}"
                f"{qw_note}"
            )

    console.print()
    if not verbose:
        console.print(" [dim]--verbose for details[/dim]")
        console.print()


def _render_finding_full(finding: Finding) -> None:
    """Render a single finding in full detail."""
    sev = SEVERITY_DOTS.get(finding.severity, "")
    sev_label = SEVERITY_ICONS.get(finding.severity, "")

    asi_str = f" \u00b7 {finding.owasp_id}" if finding.owasp_id else ""
    console.print(
        f" {sev} {sev_label} \u00b7 {finding.confidence.value} \u00b7 "
        f"{finding.category.value}              {finding.id}{asi_str}"
    )
    console.print(f" [bold]{finding.title}[/bold]")
    console.print()
    console.print(f" {finding.path}")
    console.print()

    if finding.description:
        console.print(f" {finding.description}")
        console.print()

    # Citation
    citation = get_citation(finding.id)
    if citation:
        console.print(f" [dim]\u25b8 {citation.stat} -- {citation.source}[/dim]")
        console.print()

    if finding.evidence:
        evidence_str = " \u00b7 ".join(finding.evidence)
        console.print(f" [dim]Evidence: {evidence_str}[/dim]")

    if finding.remediation:
        console.print(f" [green]Fix: {finding.remediation}[/green]")

    refs = []
    if finding.owasp_id:
        refs.append(finding.owasp_id)
    for url in finding.references:
        short = url.replace("https://", "").replace("http://", "")
        refs.append(short)
    if refs:
        console.print(f" [dim]Refs: {' \u00b7 '.join(refs)}[/dim]")

    console.print()


# ── Learn More ───────────────────────────────────────────────────────────────

def _render_learn_more(result: ScanResult) -> None:
    """Render the LEARN MORE section with contextual research links."""
    all_findings = result.top_paths + result.signals
    if not all_findings:
        return

    links = select_research_links(all_findings)
    if not links:
        return

    console.rule("[bold]LEARN MORE[/bold]", style="bold")
    console.print()
    console.print("  These findings map to published research, not Stratum's opinion:")
    console.print()

    for link in links:
        console.print(f"  [bold]{link.title}[/bold]")
        # Extract domain from URL for display
        short_url = link.url.replace("https://", "").replace("http://", "")
        if "/" in short_url:
            domain = short_url.split("/")[0]
        else:
            domain = short_url
        console.print(f"  [dim]{domain} -> {link.relevance}[/dim]")
        console.print()


# ── Progress (re-scans) ──────────────────────────────────────────────────────

def _render_progress(result: ScanResult) -> None:
    """Render the PROGRESS section on re-scans."""
    if not result.diff:
        return

    resolved = result.diff.resolved_finding_ids
    if not resolved:
        return

    console.rule("[bold]PROGRESS[/bold]", style="bold")
    console.print()

    for fid in resolved:
        console.print(f"  [green]\u2713[/green] {fid}  [green]Fixed[/green]")

    n = len(resolved)
    console.print()
    console.print(f"  Nice work. {n} issue{'s' if n != 1 else ''} resolved in one pass.")
    console.print()


# ── Quick Actions ─────────────────────────────────────────────────────────────

def _render_quick_actions(result: ScanResult) -> None:
    """Render the QUICK ACTIONS section with CLI commands."""
    all_findings = result.top_paths + result.signals
    if not all_findings:
        return

    console.rule("[bold]QUICK ACTIONS[/bold]", style="bold")
    console.print()
    console.print("  [cyan]stratum scan . --fix[/cyan]          Apply fixes automatically")
    console.print("  [cyan]stratum scan . --format sarif[/cyan] Export for GitHub Code Scanning")
    console.print()


# ── What's Next ───────────────────────────────────────────────────────────────

def _render_whats_next(result: ScanResult, quick_wins: list[QuickWin]) -> None:
    """Render WHAT'S NEXT section with badge and CI suggestion."""
    console.rule("[bold]WHAT'S NEXT[/bold]", style="bold")
    console.print()

    if quick_wins:
        console.print(
            f"  Apply the {len(quick_wins)} quick win{'s' if len(quick_wins) != 1 else ''} "
            f"above, then re-scan:"
        )
        console.print("  [cyan]$ stratum scan .[/cyan]")
        console.print()

    # Badge
    badge_md = generate_badge_markdown(result.risk_score)
    console.print("  Badge for your README:")
    console.print(f"  [dim]{badge_md}[/dim]")
    console.print()

    # CI
    console.print("  Add to CI:")
    console.print("  [cyan]$ cp docs/github-action.yml .github/workflows/stratum.yml[/cyan]")
    console.print()


# ── Footer ────────────────────────────────────────────────────────────────────

def _render_footer(result: ScanResult) -> None:
    """Render the footer."""
    console.rule(style="dim")
    stratum_dir = os.path.join(result.directory, ".stratum")
    history_file = os.path.join(stratum_dir, "history.jsonl")
    if os.path.exists(history_file):
        try:
            with open(history_file, "r") as f:
                count = sum(1 for _ in f)
            console.print(f" .stratum/history.jsonl saved ({count} scans)")
        except OSError:
            console.print(" .stratum/history.jsonl saved")
    else:
        console.print(" .stratum/history.jsonl saved")

    # Right-aligned repo URL
    console.print()
    console.print(
        "[dim]                                     "
        "stratum v0.1 \u00b7 github.com/stratum-systems/stratum-cli[/dim]"
    )


def print_first_run_notice(file=None) -> None:
    """Print telemetry disclosure on first run.

    Args:
        file: Output stream. Default stdout, stderr for --json/--ci.
    """
    import sys
    out = file or sys.stdout
    c = Console(file=out, force_terminal=(file is None))
    notice = (
        "  \u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510\n"
        "  \u2502  Stratum sends anonymized scan statistics to improve agent   \u2502\n"
        "  \u2502  security research. No source code, file paths, or secrets   \u2502\n"
        "  \u2502  are collected. See: docs/telemetry.md                       \u2502\n"
        "  \u2502                                                              \u2502\n"
        "  \u2502  Disable:  stratum config set telemetry off                  \u2502\n"
        "  \u2502  One-time: stratum scan . --no-telemetry                     \u2502\n"
        "  \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518"
    )
    c.print(notice, style="dim")


def print_comparison_url(scan_id: str) -> None:
    """Print comparison URL after successful telemetry submission."""
    console.print()
    console.print(
        f"  [dim blue]Compare your scan: https://stratum.dev/compare/{scan_id}[/dim blue]",
    )
