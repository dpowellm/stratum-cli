"""Rich terminal output for Stratum scan results."""
from __future__ import annotations

import json
import os

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table

from stratum.models import Finding, RiskCategory, ScanResult, Severity

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

BENCHMARK_TEASER = (
    " [bold]Community risk benchmarks coming soon[/bold]\n"
    "    How does your agent compare? Track progress at\n"
    "    [cyan]stratum.dev/benchmarks[/cyan]"
)


def render(result: ScanResult, verbose: bool = False, shared: bool = False) -> None:
    """Render the scan result to the terminal using Rich."""
    _render_header(result)
    _render_summary(result)
    _render_top_paths(result)
    _render_signals(result, verbose)
    _render_footer(result)
    _render_nudges(result, shared=shared)


def _render_header(result: ScanResult) -> None:
    """Render the header banner."""
    header = Text()
    header.append("  STRATUM ", style="bold white")
    header.append("\u00b7 Agent Risk Profiler", style="dim")
    header.append("                        v0.1.0", style="dim")
    console.print(Panel(header, style="bold blue"))


def _render_summary(result: ScanResult) -> None:
    """Render the summary section."""
    # Capability counts
    cap_parts = []
    if result.outbound_count:
        cap_parts.append(f"{result.outbound_count} outbound")
    if result.data_access_count:
        cap_parts.append(f"{result.data_access_count} data access")
    if result.code_exec_count:
        cap_parts.append(f"{result.code_exec_count} code exec")
    if result.destructive_count:
        cap_parts.append(f"{result.destructive_count} destructive")
    if result.financial_count:
        cap_parts.append(f"{result.financial_count} financial")

    cap_str = ", ".join(cap_parts)
    console.print(f"  {result.total_capabilities} capabilities ({cap_str})")
    console.print(
        f"  {result.mcp_server_count} MCP servers \u00b7 "
        f"{result.guardrail_count} guardrails"
    )

    # Category breakdown
    all_findings = result.top_paths + result.signals
    security = sum(1 for f in all_findings if f.category == RiskCategory.SECURITY)
    business = sum(1 for f in all_findings if f.category == RiskCategory.BUSINESS)
    operational = sum(1 for f in all_findings if f.category == RiskCategory.OPERATIONAL)

    parts = []
    if security:
        parts.append(f"{security} security")
    if business:
        parts.append(f"{business} business")
    if operational:
        parts.append(f"{operational} operational")

    console.print(f"\n  \u25b8 {' \u00b7 '.join(parts)}")

    # Risk score
    score = result.risk_score
    bar_filled = score // 5
    bar_empty = 20 - bar_filled
    bar = "\u2588" * bar_filled + "\u2591" * bar_empty

    if score >= 80:
        level = "[bold red]CRITICAL[/bold red]"
    elif score >= 60:
        level = "[bold yellow]HIGH[/bold yellow]"
    elif score >= 40:
        level = "[yellow]MEDIUM[/yellow]"
    else:
        level = "[green]LOW[/green]"

    console.print(f"\n  RISK SCORE  {score}/100  {bar}  {level}")

    if result.diff:
        delta = result.diff.risk_score_delta
        arrow = "\u25b2" if delta > 0 else ("\u25bc" if delta < 0 else "\u25cf")
        sign = "+" if delta > 0 else ""
        new_count = len(result.diff.new_finding_ids)
        resolved_count = len(result.diff.resolved_finding_ids)
        console.print(
            f"  {arrow} {sign}{delta} since last scan \u00b7 "
            f"{new_count} new \u00b7 {resolved_count} resolved"
        )

    console.print()


def _render_top_paths(result: ScanResult) -> None:
    """Render the top risk paths section."""
    if not result.top_paths:
        return

    console.rule("[bold]TOP RISK PATHS[/bold]", style="bold")
    console.print()

    for finding in result.top_paths:
        _render_finding_full(finding)
        console.print("\u2500" * 60)
        console.print()


def _render_finding_full(finding: Finding) -> None:
    """Render a single finding in full detail."""
    sev = SEVERITY_DOTS.get(finding.severity, "")
    sev_label = SEVERITY_ICONS.get(finding.severity, "")

    console.print(
        f" {sev} {sev_label} \u00b7 {finding.confidence.value} \u00b7 "
        f"{finding.category.value}              {finding.id}"
    )
    console.print(f" [bold]{finding.title}[/bold]")
    console.print()
    console.print(f" {finding.path}")
    console.print()

    if finding.description:
        console.print(f" {finding.description}")
        console.print()

    if finding.evidence:
        evidence_str = " \u00b7 ".join(finding.evidence)
        console.print(f" [dim]\U0001f4cd {evidence_str}[/dim]")

    if finding.remediation:
        console.print(f" [green]\U0001f527 {finding.remediation}[/green]")

    refs = []
    if finding.owasp_id:
        refs.append(finding.owasp_id)
    for url in finding.references:
        # Shorten URLs for display
        short = url.replace("https://", "").replace("http://", "")
        refs.append(short)
    if refs:
        console.print(f" [dim]\U0001f4da {' \u00b7 '.join(refs)}[/dim]")

    console.print()


def _render_signals(result: ScanResult, verbose: bool) -> None:
    """Render the signals section."""
    if not result.signals:
        return

    console.rule(f"[bold]SIGNALS ({len(result.signals)} more)[/bold]", style="bold")
    console.print()

    if verbose:
        for finding in result.signals:
            _render_finding_full(finding)
            console.print("\u2500" * 60)
            console.print()
    else:
        for finding in result.signals:
            sev = SEVERITY_DOTS.get(finding.severity, "")
            sev_short = {
                Severity.CRITICAL: "[bold red]CRIT[/bold red]",
                Severity.HIGH: "[bold yellow]HIGH[/bold yellow]",
                Severity.MEDIUM: "[yellow]MED [/yellow]",
                Severity.LOW: "[dim]LOW [/dim]",
            }.get(finding.severity, "")

            console.print(
                f" {sev} {sev_short}  {finding.id}  {finding.title}   "
                f"{finding.category.value} \u00b7 {finding.confidence.value}"
            )

    console.print()
    if not verbose:
        console.print(" --verbose for details")
        console.print()


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


def _get_scan_count(result: ScanResult) -> int:
    """Get the total scan count from history for nudge display logic."""
    stratum_dir = os.path.join(result.directory, ".stratum")
    history_file = os.path.join(stratum_dir, "history.jsonl")
    try:
        if os.path.exists(history_file):
            with open(history_file, "r") as f:
                return sum(1 for _ in f)
    except OSError:
        pass
    return 1


def _load_project_config(result: ScanResult) -> dict:
    """Load .stratum/config.json for nudge suppression."""
    config_path = os.path.join(result.directory, ".stratum", "config.json")
    try:
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                return json.load(f)
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def _render_nudges(result: ScanResult, shared: bool = False) -> None:
    """Render share-telemetry nudge and benchmark teaser after scan output."""
    cfg = _load_project_config(result)
    scan_count = _get_scan_count(result)

    # Share prompt: shown on scans 1, 10, 20, 30...
    # NOT shown if --share-telemetry was used, or if suppressed
    show_share = (
        not shared
        and not cfg.get("suppress_share_prompt", False)
        and (scan_count == 1 or (scan_count >= 10 and scan_count % 10 == 0))
    )

    if show_share:
        cap_count = result.total_capabilities
        path_count = len(result.top_paths)
        console.print()
        console.rule(style="dim")
        console.print(
            f" [bold]Help build agent safety benchmarks[/bold]\n"
            f"    This scan found {cap_count} capabilities and {path_count} risk paths.\n"
            f"    Share anonymously to improve ecosystem intelligence.\n"
            f"    No source code. No identifiers. Counts and ratios only.\n"
            f"\n"
            f"    [cyan]stratum scan . --share-telemetry[/cyan]\n"
            f"    [dim]stratum config suppress-share-prompt    (to hide this)[/dim]"
        )

    # Benchmark teaser: shown on scans 1, 5, 10, 15, 20...
    # NOT shown if suppressed
    show_teaser = (
        not cfg.get("suppress_benchmark_teaser", False)
        and (scan_count == 1 or (scan_count >= 5 and scan_count % 5 == 0))
    )

    if show_teaser:
        console.print()
        console.rule(style="dim")
        console.print(BENCHMARK_TEASER)
