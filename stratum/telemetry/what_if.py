"""What-if control computation for ScanProfile."""
from __future__ import annotations


def compute_what_if_controls(
    findings: list,
    capabilities: list,
    guardrails: list,
) -> list[dict]:
    """For each control that could be added, compute which findings it would suppress
    and the resulting risk score reduction.

    Returns list of dicts sorted by score_reduction descending:
    {
        "control": str,
        "description": str,
        "findings_suppressed": list[str],
        "severity_suppressed": dict[str, int],
        "score_reduction": int,
        "effort": str,
    }
    """
    what_ifs: list[dict] = []

    # What-if: Add HITL on all outbound paths
    hitl_suppresses = [
        f for f in findings
        if getattr(f, "quick_fix_type", "") == "add_hitl"
        or f.id in ("STRATUM-001", "STRATUM-BR01", "STRATUM-002")
    ]
    if hitl_suppresses:
        score_reduction = sum(
            25 if f.severity.value == "CRITICAL" else
            15 if f.severity.value == "HIGH" else
            8 if f.severity.value == "MEDIUM" else 3
            for f in hitl_suppresses
        )
        what_ifs.append({
            "control": "hitl_on_outbound",
            "description": "Add human_input=True on tasks with outbound external actions",
            "findings_suppressed": [f.id for f in hitl_suppresses],
            "severity_suppressed": _count_by_severity(hitl_suppresses),
            "score_reduction": score_reduction,
            "effort": "low",
        })

    # What-if: Add structured output validation between agent steps
    validation_suppresses = [
        f for f in findings
        if f.id in ("STRATUM-CR02", "STRATUM-BR04")
    ]
    if validation_suppresses:
        score_reduction = sum(
            25 if f.severity.value == "CRITICAL" else
            15 if f.severity.value == "HIGH" else
            8 if f.severity.value == "MEDIUM" else 3
            for f in validation_suppresses
        )
        what_ifs.append({
            "control": "structured_output_validation",
            "description": "Add output_pydantic validation on tasks in sequential chains",
            "findings_suppressed": [f.id for f in validation_suppresses],
            "severity_suppressed": _count_by_severity(validation_suppresses),
            "score_reduction": score_reduction,
            "effort": "low",
        })

    # What-if: Add error handling on all external calls
    error_suppresses = [f for f in findings if f.id in ("STRATUM-008",)]
    if error_suppresses:
        what_ifs.append({
            "control": "error_handling",
            "description": "Add try/except with graceful degradation on external calls",
            "findings_suppressed": [f.id for f in error_suppresses],
            "severity_suppressed": _count_by_severity(error_suppresses),
            "score_reduction": sum(8 for _ in error_suppresses),
            "effort": "med",
        })

    # What-if: Add input validation on shared tools
    shared_tool_suppresses = [
        f for f in findings
        if f.id.startswith("STRATUM-CR05") or f.id == "STRATUM-CR01"
    ]
    if shared_tool_suppresses:
        score_reduction = sum(
            25 if f.severity.value == "CRITICAL" else
            15 if f.severity.value == "HIGH" else 8
            for f in shared_tool_suppresses
        )
        what_ifs.append({
            "control": "shared_tool_validation",
            "description": "Add input validation on tools shared by 3+ agents",
            "findings_suppressed": [f.id for f in shared_tool_suppresses],
            "severity_suppressed": _count_by_severity(shared_tool_suppresses),
            "score_reduction": score_reduction,
            "effort": "med",
        })

    # What-if: Add observability
    obs_suppresses = [
        f for f in findings
        if f.id in ("TELEMETRY-003", "STRATUM-BR03")
    ]
    if obs_suppresses:
        what_ifs.append({
            "control": "observability",
            "description": "Add Langfuse, LangSmith, or OpenTelemetry tracing",
            "findings_suppressed": [f.id for f in obs_suppresses],
            "severity_suppressed": _count_by_severity(obs_suppresses),
            "score_reduction": sum(
                8 if f.severity.value == "MEDIUM" else 3
                for f in obs_suppresses
            ),
            "effort": "low",
        })

    # Sort by score_reduction descending
    what_ifs.sort(key=lambda x: -x["score_reduction"])

    return what_ifs


def _count_by_severity(findings: list) -> dict[str, int]:
    """Count findings by severity level."""
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.severity.value.lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts
