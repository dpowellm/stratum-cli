"""Action-oriented terminal output for Stratum scan results.

Structure:
1. Header (project info in bordered box)
2. Risk bar (visual score)
3. "Fix these first" (primary action groups with full treatment)
4. "What your agents look like" (flow maps for affected crews)
5. "Also worth fixing" (secondary actions as one-liners)
6. Footer (total counts, pointer to --verbose)
"""
from __future__ import annotations

import io
import os
import sys

from rich.console import Console

from stratum.models import ScanResult, Severity
from stratum.output.action_groups import group_findings_into_actions, split_primary_and_secondary
from stratum.output.code_block import render_code_block
from stratum.output.flow_map import render_all_crew_maps
from stratum.output.risk_bar import render_risk_bar

# Force UTF-8 output on Windows to support Unicode box-drawing characters
if sys.platform == "win32" and hasattr(sys.stdout, "buffer"):
    _stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
else:
    _stdout = sys.stdout

console = Console(file=_stdout, force_terminal=True, legacy_windows=False)

# Number circle characters for action numbering
_CIRCLES = {1: "\u2460", 2: "\u2461", 3: "\u2462", 4: "\u2463", 5: "\u2464",
             6: "\u2465", 7: "\u2466", 8: "\u2467", 9: "\u2468"}


def render(result: ScanResult, verbose: bool = False,
           security_mode: bool = False, quiet: bool = False) -> None:
    """Render the scan result to the terminal."""
    all_findings = result.top_paths + result.signals

    # Build action groups
    control_bypasses = getattr(result, "_control_bypasses", [])
    action_groups = group_findings_into_actions(
        findings=result.top_paths,
        signals=result.signals,
        incident_matches=getattr(result, "incident_matches", []),
        detected_frameworks=result.detected_frameworks,
        blast_radii=getattr(result, "blast_radii", []),
    )
    primary, secondary = split_primary_and_secondary(action_groups)

    # Quiet mode: minimal output for CI/scripts
    if quiet:
        _render_quiet(result, primary)
        return

    # Standard output
    _render_header(result)
    _render_risk_bar_section(result, all_findings)

    if primary:
        _render_section_header("FIX THESE FIRST")
        for i, group in enumerate(primary):
            _render_primary_action(group, i + 1, result)

    # Flow maps
    crews = getattr(result, "crew_definitions", [])
    graph = getattr(result, "graph", None)
    blast_radii = getattr(result, "blast_radii", [])
    incidents = getattr(result, "incident_matches", [])
    if crews and graph:
        maps = render_all_crew_maps(
            crews, graph, result.top_paths, blast_radii,
            control_bypasses, incidents,
        )
        if maps:
            _render_section_header("WHAT YOUR AGENTS LOOK LIKE")
            console.print(maps)

    if secondary:
        _render_section_header("ALSO WORTH FIXING")
        for group in secondary:
            _render_secondary_action(group)

    _render_footer(result, all_findings)

    # Verbose: append full details
    if verbose:
        from stratum.output.verbose import render_verbose_sections
        render_verbose_sections(result, console)


# ── Header ────────────────────────────────────────────────────────────────────

def _render_header(result: ScanResult) -> None:
    """Render the header in a double-line bordered box."""
    directory = result.directory
    project_name = directory.replace("\\", "/").rstrip("/").split("/")[-1]
    frameworks = ", ".join(result.detected_frameworks) if result.detected_frameworks else "Unknown"
    crews = len(getattr(result, "crew_definitions", []))
    agents = len(getattr(result, "agent_definitions", []))
    files = getattr(result, "files_scanned", 0)

    # Build info line
    info_parts: list[str] = []
    if files:
        info_parts.append(f"{files} files")
    if crews:
        info_parts.append(f"{crews} crews")
    if agents:
        info_parts.append(f"{agents} agents")
    info_str = " \u00b7 ".join(info_parts)

    box_width = 67
    inner = box_width - 4  # Account for "  " padding on each side

    line1 = "STRATUM SCAN"
    line2 = f"{project_name} \u00b7 {info_str}"
    line3 = f"Frameworks: {frameworks}"

    console.print()
    console.print(f" \u2554{'=' * (box_width - 2)}\u2557")
    console.print(f" \u2551  {line1:<{inner}}\u2551")
    console.print(f" \u2551  {line2:<{inner}}\u2551")
    console.print(f" \u2551  {line3:<{inner}}\u2551")
    console.print(f" \u255a{'=' * (box_width - 2)}\u255d")


# ── Risk Bar ──────────────────────────────────────────────────────────────────

def _render_risk_bar_section(result: ScanResult, all_findings: list) -> None:
    """Render the visual risk score bar."""
    lines = render_risk_bar(result.risk_score, all_findings)
    for line in lines:
        console.print(line)


# ── Section Headers ───────────────────────────────────────────────────────────

def _render_section_header(title: str) -> None:
    """Render a section divider."""
    console.print()
    console.print(f" \u2500\u2500\u2500 {title} {'\u2500' * max(0, 60 - len(title))}")
    console.print()


# ── Primary Actions ───────────────────────────────────────────────────────────

def _render_primary_action(group, number: int, result: ScanResult) -> None:
    """Render a primary action with full treatment."""
    num = _CIRCLES.get(number, f"({number})")

    # Title line with effort right-aligned
    title_part = f" {num} {group.title}"
    effort_part = f"\u2591 {group.effort}"
    gap = max(1, 66 - len(title_part) - len(effort_part))
    console.print(f"[bold]{title_part}[/bold]{' ' * gap}[dim]{effort_part}[/dim]")

    # Resolves line
    console.print(f"   Resolves {group.finding_count} findings ({group.severity_label})")
    console.print()

    # Narrative (word-wrapped)
    if group.narrative:
        wrapped = _wrap_text(group.narrative, 60, indent="   ")
        console.print(wrapped)

    # Code fix
    if group.code_fix:
        console.print()
        console.print("   Fix:")
        console.print(render_code_block(group.code_fix))

    # Apply to
    if group.apply_to:
        files_str = ", ".join(group.apply_to[:3])
        if len(group.apply_to) > 3:
            files_str += f" (+{len(group.apply_to) - 3} more)"
        console.print(f"   Apply to: [dim]{files_str}[/dim]")

    # Incident match
    if group.incident_match:
        console.print()
        m = group.incident_match
        console.print(f"   \U0001f4ce Matches real breach: [bold]{m['name']}[/bold]")
        if m.get("match_reason"):
            reason_wrapped = _wrap_text(m["match_reason"][:200], 58, indent="      ")
            console.print(f"[dim]{reason_wrapped}[/dim]")

    console.print()
    console.print()


# ── Secondary Actions ─────────────────────────────────────────────────────────

def _render_secondary_action(group) -> None:
    """Render a secondary action as a one-liner."""
    narrative = group.narrative.split(".")[0] if group.narrative else group.title
    console.print(f" \u00b7 {narrative}")


# ── Footer ────────────────────────────────────────────────────────────────────

def _render_footer(result: ScanResult, all_findings: list) -> None:
    """Render the footer with counts and pointer to --verbose."""
    finding_count = len(result.top_paths)
    signal_count = len(result.signals)
    console.print()
    console.print(
        f" \u2500\u2500\u2500 {finding_count} findings total \u00b7 "
        f"{signal_count} signals \u00b7 "
        f"Full details: [cyan]stratum scan . --verbose[/cyan]"
    )
    console.print()

    # History file reference
    stratum_dir = os.path.join(result.directory, ".stratum")
    history_file = os.path.join(stratum_dir, "history.jsonl")
    if os.path.exists(history_file):
        try:
            with open(history_file, "r") as f:
                count = sum(1 for _ in f)
            console.print(f" [dim].stratum/history.jsonl saved ({count} scans)[/dim]")
        except OSError:
            console.print(" [dim].stratum/history.jsonl saved[/dim]")
    else:
        console.print(" [dim].stratum/history.jsonl saved[/dim]")

    console.print()
    console.print(
        "[dim]                                     "
        "stratum v0.2 \u00b7 github.com/stratum-systems/stratum-cli[/dim]"
    )


# ── Quiet Mode ────────────────────────────────────────────────────────────────

def _render_quiet(result: ScanResult, primary_groups: list) -> None:
    """Render minimal output for CI/scripts (~6 lines)."""
    directory = result.directory
    project_name = directory.replace("\\", "/").rstrip("/").split("/")[-1]

    # Severity summary
    all_findings = result.top_paths + result.signals
    sev_counts: dict[str, int] = {}
    for f in all_findings:
        s = f.severity.value
        sev_counts[s] = sev_counts.get(s, 0) + 1
    parts: list[str] = []
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if sev_counts.get(s, 0) > 0:
            parts.append(f"{sev_counts[s]} {s.lower()}")
    sev_str = " \u00b7 ".join(parts)

    console.print(f" STRATUM  {project_name}  {result.risk_score}/100  {sev_str}")

    for i, group in enumerate(primary_groups[:3]):
        num = _CIRCLES.get(i + 1, f"({i + 1})")
        console.print(
            f" {num} {group.title} ({group.effort}, resolves {group.finding_count} findings)"
        )


# ── Utilities ─────────────────────────────────────────────────────────────────

def _wrap_text(text: str, width: int, indent: str = "") -> str:
    """Word-wrap text to width, with indent on each line."""
    words = text.split()
    lines: list[str] = []
    current = indent
    for word in words:
        if len(current) + len(word) + 1 > width + len(indent):
            lines.append(current)
            current = indent + word
        else:
            if current == indent:
                current += word
            else:
                current += " " + word
    if current.strip():
        lines.append(current)
    return "\n".join(lines)


# ── Preserved exports ─────────────────────────────────────────────────────────

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
