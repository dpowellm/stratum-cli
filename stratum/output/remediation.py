"""Generate copy-paste remediation diffs for findings.

Each finding type has a hardcoded template that uses scan evidence
(source_file, line_number, function_name, library) to produce a
concrete, file-specific fix the developer can apply immediately.

Templates are intentionally simple -- one fix per finding, always the
minimal viable fix, never architectural advice.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from stratum.models import Capability, Confidence, Finding, ScanResult, Severity
from stratum.knowledge.db import HTTP_LIBRARIES, KNOWN_CVES


@dataclass
class Remediation:
    finding_id: str
    title: str
    effort_label: str          # "~30 sec" | "~1 min" | "~2 min" | "~5 min"
    score_impact: int          # negative number (score reduction)
    file_path: str             # relative path to the file
    line_number: int | None    # line number if applicable
    diff_lines: list[str] = field(default_factory=list)
    command: str | None = None  # shell command if applicable


@dataclass
class QuickWin:
    """A grouped quick win for display -- may combine multiple Remediations."""
    rank: int
    title: str
    description: str
    effort_label: str
    score_impact: int
    remediations: list[Remediation] = field(default_factory=list)
    command: str | None = None


# ── Effort mapping ────────────────────────────────────────────────────────────

EFFORT_SECONDS = {
    "no_timeout": 30,
    "env_gitignore": 10,
    "pin_mcp_version": 60,
    "add_hitl": 120,
    "add_error_handling": 60,
    "add_financial_validation": 120,
    "mcp_remove_credentials": 300,
}

EFFORT_LABELS = {
    "no_timeout": "~30 sec",
    "env_gitignore": "~10 sec",
    "pin_mcp_version": "~1 min",
    "add_hitl": "~2 min",
    "add_error_handling": "~1 min",
    "add_financial_validation": "~2 min",
    "mcp_remove_credentials": "~5 min",
}

SCORE_IMPACTS = {
    "no_timeout": -8,
    "env_gitignore": -3,
    "pin_mcp_version": -5,
    "add_hitl": -15,
    "add_error_handling": -8,
    "add_financial_validation": -10,
    "mcp_remove_credentials": -15,
}


# ── Generator functions ───────────────────────────────────────────────────────

def _insert_kwarg(line: str, kwarg: str) -> str:
    """Insert a keyword argument before the closing paren of a function call.

    Simple string manipulation: find the last ')' and insert ', kwarg' before it.
    """
    idx = line.rfind(")")
    if idx == -1:
        return line
    return line[:idx] + f", {kwarg}" + line[idx:]


def _gen_timeout_fix(finding: Finding, result: ScanResult) -> list[Remediation]:
    """Generate timeout fixes for STRATUM-009."""
    remediations = []

    for cap in result.capabilities:
        if cap.kind != "outbound" or cap.confidence == Confidence.HEURISTIC:
            continue
        if cap.library not in HTTP_LIBRARIES:
            continue
        if cap.has_timeout:
            continue

        rel_path = cap.source_file  # already relative from scanner
        source_line = cap.call_text
        # Extract the method name from evidence (e.g. "import requests -> requests.post()")
        method_name = "get"
        if cap.evidence:
            for m in ("post", "put", "patch", "delete", "get", "send"):
                if f".{m}(" in cap.evidence or f".{m})" in cap.evidence:
                    method_name = m
                    break

        if source_line and "(" in source_line and ")" in source_line:
            fixed_line = _insert_kwarg(source_line, "timeout=30")
            remediations.append(Remediation(
                finding_id="STRATUM-009",
                title=f"Add timeout to {cap.function_name}()",
                effort_label="~30 sec",
                score_impact=-3,
                file_path=rel_path,
                line_number=cap.line_number,
                diff_lines=[f"- {source_line.strip()}", f"+ {fixed_line.strip()}"],
            ))
        else:
            remediations.append(Remediation(
                finding_id="STRATUM-009",
                title=f"Add timeout to {cap.function_name}()",
                effort_label="~30 sec",
                score_impact=-3,
                file_path=rel_path,
                line_number=cap.line_number,
                diff_lines=[
                    f"  # In {cap.function_name}(), add timeout to {cap.library} calls:",
                    f"+ {cap.library}.{method_name}(..., timeout=30)",
                ],
            ))
    return remediations


def _gen_gitignore_fix(finding: Finding, result: ScanResult) -> list[Remediation]:
    """Generate .gitignore fix for ENV-001."""
    return [Remediation(
        finding_id="ENV-001",
        title="Add .env to .gitignore",
        effort_label="~10 sec",
        score_impact=-3,
        file_path=".gitignore",
        line_number=None,
        command='echo ".env" >> .gitignore',
    )]


def _gen_pin_mcp_fix(finding: Finding, result: ScanResult) -> list[Remediation]:
    """Generate MCP version pinning fixes for STRATUM-006."""
    remediations = []

    for server in result.mcp_servers:
        if server.is_known_safe:
            continue
        if not server.npm_package or server.package_version:
            continue

        rel_path = server.source_file  # already relative from scanner
        pkg = server.npm_package

        # Check if we know a specific safe version from CVE data
        pin_version = "latest"
        if pkg in KNOWN_CVES:
            fixed = KNOWN_CVES[pkg].get("fixed", "")
            if fixed:
                pin_version = fixed

        remediations.append(Remediation(
            finding_id="STRATUM-006",
            title=f"Pin {pkg}",
            effort_label="~1 min",
            score_impact=-3,
            file_path=rel_path,
            line_number=None,
            diff_lines=[
                f"  {rel_path} -> {server.name}:",
                f'- "args": ["{pkg}", ...]',
                f'+ "args": ["{pkg}@{pin_version}", ...]',
            ],
        ))
    return remediations


def _gen_hitl_fix(finding: Finding, result: ScanResult) -> list[Remediation]:
    """Generate HITL fix for STRATUM-001 / STRATUM-002."""
    destructive_names = []
    for cap in result.capabilities:
        if cap.kind in ("destructive", "outbound") and cap.confidence != Confidence.HEURISTIC:
            if cap.function_name not in destructive_names:
                destructive_names.append(cap.function_name)

    names_str = ", ".join(f'"{n}"' for n in destructive_names[:5])
    return [Remediation(
        finding_id=finding.id,
        title="Add human-in-the-loop for dangerous operations",
        effort_label="~2 min",
        score_impact=-15,
        file_path="agent.py",
        line_number=None,
        diff_lines=[
            "  app = workflow.compile(",
            "      checkpointer=checkpointer,",
            f"+     interrupt_before=[{names_str}]",
            "  )",
        ],
    )]


def _gen_error_handling_fix(finding: Finding, result: ScanResult) -> list[Remediation]:
    """Generate error handling fix for STRATUM-008."""
    return [Remediation(
        finding_id="STRATUM-008",
        title="Add try/except to external calls",
        effort_label="~1 min",
        score_impact=-8,
        file_path="(multiple files)",
        line_number=None,
        diff_lines=[
            "  try:",
            "      result = requests.get(url, timeout=30)",
            "  except requests.RequestException as e:",
            '      return f"Service unavailable: {e}"',
        ],
    )]


def _gen_validation_fix(finding: Finding, result: ScanResult) -> list[Remediation]:
    """Generate input validation fix for STRATUM-007."""
    return [Remediation(
        finding_id="STRATUM-007",
        title="Add input validation to financial operations",
        effort_label="~2 min",
        score_impact=-10,
        file_path="(financial tool file)",
        line_number=None,
        diff_lines=[
            "+ if amount <= 0 or amount > MAX_AUTO_REFUND:",
            '+     raise ValueError("Amount out of bounds")',
        ],
    )]


def _gen_mcp_cred_fix(finding: Finding, result: ScanResult) -> list[Remediation]:
    """Generate MCP credential removal fix for STRATUM-005."""
    return [Remediation(
        finding_id="STRATUM-005",
        title="Remove credential passthrough from MCP config",
        effort_label="~5 min",
        score_impact=-15,
        file_path="MCP config",
        line_number=None,
        diff_lines=[
            '  "env": {',
            '-     "DATABASE_URL": "...",',
            '-     "AWS_SECRET_ACCESS_KEY": "..."',
            "  }",
            "  # Use scoped, read-only credentials instead",
        ],
    )]


# ── Template dispatch ─────────────────────────────────────────────────────────

GENERATORS = {
    "no_timeout": _gen_timeout_fix,
    "env_gitignore": _gen_gitignore_fix,
    "pin_mcp_version": _gen_pin_mcp_fix,
    "add_hitl": _gen_hitl_fix,
    "add_error_handling": _gen_error_handling_fix,
    "add_financial_validation": _gen_validation_fix,
    "mcp_remove_credentials": _gen_mcp_cred_fix,
}


# ── Quick wins selection ──────────────────────────────────────────────────────

def select_quick_wins(
    findings: list[Finding],
    result: ScanResult,
    max_wins: int = 3,
) -> list[QuickWin]:
    """Select the highest-impact, lowest-effort fixes.

    Algorithm:
    1. Generate all possible remediations from findings with quick_fix_type
    2. Group by quick_fix_type (one QuickWin per type)
    3. Score each by: abs(score_impact) / effort_seconds
    4. Sort descending by impact-per-second
    5. Take top max_wins
    """
    # Deduplicate by quick_fix_type
    seen_types: set[str] = set()
    candidates: list[tuple[str, Finding]] = []
    for f in findings:
        if f.quick_fix_type and f.quick_fix_type not in seen_types:
            seen_types.add(f.quick_fix_type)
            candidates.append((f.quick_fix_type, f))

    # Generate remediations and build QuickWins
    quick_wins: list[QuickWin] = []
    for fix_type, finding in candidates:
        gen = GENERATORS.get(fix_type)
        if not gen:
            continue

        remediations = gen(finding, result)
        if not remediations:
            continue

        score_impact = SCORE_IMPACTS.get(fix_type, -5)
        effort_seconds = EFFORT_SECONDS.get(fix_type, 60)
        effort_label = EFFORT_LABELS.get(fix_type, "~1 min")

        # Use first remediation's command if it has one
        cmd = None
        for r in remediations:
            if r.command:
                cmd = r.command
                break

        quick_wins.append(QuickWin(
            rank=0,
            title=remediations[0].title if len(remediations) == 1 else DESCRIPTIONS.get(fix_type, remediations[0].title),
            description=_quick_win_description(fix_type, remediations),
            effort_label=effort_label,
            score_impact=score_impact,
            remediations=remediations,
            command=cmd,
        ))

    # Sort by impact-per-second using theoretical impacts (highest first)
    quick_wins.sort(
        key=lambda qw: abs(qw.score_impact) / EFFORT_SECONDS.get(
            _type_from_id(qw), 60
        ),
        reverse=True,
    )

    selected = quick_wins[:max_wins]

    # Recalibrate score_impact values using actual simulation
    # so their sum matches the real estimated delta (accounts for cap + bonuses)
    fixed_ids: set[str] = set()
    for qw in selected:
        for rem in qw.remediations:
            fixed_ids.add(rem.finding_id)
    simulated = _simulate_risk_score(result, fixed_ids)
    actual_delta = simulated - result.risk_score  # e.g. 0 if still capped

    # Distribute actual_delta proportionally across selected quick wins
    theoretical_sum = sum(abs(qw.score_impact) for qw in selected)
    if theoretical_sum > 0 and actual_delta != 0:
        for qw in selected:
            weight = abs(qw.score_impact) / theoretical_sum
            qw.score_impact = round(actual_delta * weight)
        # Fix rounding so sum is exact
        rounding_err = actual_delta - sum(qw.score_impact for qw in selected)
        if selected and rounding_err != 0:
            selected[0].score_impact += rounding_err
    elif actual_delta == 0:
        for qw in selected:
            qw.score_impact = 0

    # Assign ranks
    for i, qw in enumerate(selected):
        qw.rank = i + 1

    return selected


def _type_from_id(qw: QuickWin) -> str:
    """Recover the fix_type from a QuickWin for sorting."""
    if qw.remediations:
        fid = qw.remediations[0].finding_id
        for fix_type, desc in DESCRIPTIONS.items():
            if desc == qw.title:
                return fix_type
    # Fall back to checking GENERATORS
    for fix_type, gen in GENERATORS.items():
        if DESCRIPTIONS.get(fix_type) == qw.title:
            return fix_type
    return "unknown"


DESCRIPTIONS = {
    "no_timeout": "Add timeouts to HTTP calls",
    "env_gitignore": "Add .env to .gitignore",
    "pin_mcp_version": "Pin MCP server versions",
    "add_hitl": "Add human-in-the-loop for dangerous operations",
    "add_error_handling": "Add try/except to external calls",
    "add_financial_validation": "Add input validation to financial operations",
    "mcp_remove_credentials": "Remove credential passthrough from MCP config",
}


def _quick_win_description(fix_type: str, remediations: list[Remediation]) -> str:
    """Generate a short description for a quick win."""
    if fix_type == "no_timeout":
        n = len(remediations)
        return f"{n} outbound call{'s' if n != 1 else ''} hang forever if an API is slow."
    elif fix_type == "env_gitignore":
        return "Your .env file contains secrets and isn't gitignored."
    elif fix_type == "pin_mcp_version":
        n = len(remediations)
        return f"{n} MCP server{'s' if n != 1 else ''} use unpinned packages."
    elif fix_type == "add_hitl":
        return "Destructive operations run without human approval."
    elif fix_type == "add_error_handling":
        return "External calls crash instead of degrading gracefully."
    elif fix_type == "add_financial_validation":
        return "Financial operations accept any input without validation."
    elif fix_type == "mcp_remove_credentials":
        return "Production credentials are passed to third-party MCP servers."
    return ""


def _simulate_risk_score(result: ScanResult, exclude_ids: set[str]) -> int:
    """Re-calculate the risk score with certain findings removed.

    Mirrors scanner._calculate_risk_score exactly, but excludes findings
    whose IDs are in exclude_ids. This accounts for the cap at 100 and
    all bonus adjustments.
    """
    all_findings = result.top_paths + result.signals
    remaining = [f for f in all_findings if f.id not in exclude_ids]

    score = 0
    for f in remaining:
        if f.severity == Severity.CRITICAL:
            score += 25
        elif f.severity == Severity.HIGH:
            score += 15
        elif f.severity == Severity.MEDIUM:
            score += 8
        elif f.severity == Severity.LOW:
            score += 3

    # Bonus: zero guardrails with >= 3 capabilities
    if not result.has_any_guardrails and len(result.capabilities) >= 3:
        score += 15

    # Bonus: Known CVE MCP (only if STRATUM-004 survives)
    if any(f.id == "STRATUM-004" for f in remaining):
        score += 20

    # Bonus: financial tools + no HITL + no validation
    # If STRATUM-007 is being fixed (add_financial_validation), skip this bonus
    financial_caps = [c for c in result.capabilities if c.kind == "financial"]
    if financial_caps and not any(c.has_input_validation for c in financial_caps):
        financial_names = {c.function_name for c in financial_caps}
        has_financial_hitl = any(
            g.kind == "hitl" and (
                not g.covers_tools or bool(set(g.covers_tools) & financial_names)
            )
            for g in result.guardrails
        )
        if not has_financial_hitl:
            if "STRATUM-007" not in exclude_ids:
                score += 10

    # Bonus: zero error handling across >= 3 external calls
    # If STRATUM-008 is being fixed, this bonus goes away
    if "STRATUM-008" not in exclude_ids:
        external_caps = [
            c for c in result.capabilities
            if c.kind in ("outbound", "data_access", "financial")
            and c.confidence != Confidence.HEURISTIC
        ]
        if len(external_caps) >= 3 and not any(c.has_error_handling for c in external_caps):
            score += 5

    return min(score, 100)


def compute_estimated_score(result: ScanResult, quick_wins: list[QuickWin]) -> int:
    """Estimate the score after applying all quick wins.

    Uses the real scoring algorithm (with cap and bonuses) to simulate
    what the score would be if the quick-win findings were resolved.
    """
    # Collect finding IDs addressed by quick wins
    fixed_ids: set[str] = set()
    for qw in quick_wins:
        for rem in qw.remediations:
            fixed_ids.add(rem.finding_id)

    return _simulate_risk_score(result, fixed_ids)
