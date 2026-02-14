"""Shared ping validation and failure template for the Stratum pipeline."""

import hashlib
import time
from datetime import datetime, timezone


def generate_scan_id():
    """Generate a short hex scan ID."""
    raw = f"{time.time()}-{id(object())}".encode()
    return hashlib.sha256(raw).hexdigest()[:8]


def failure_ping(repo_record, reason, stderr=None):
    """Produce a minimal ping for a failed scan so the failure is tracked."""
    return {
        "scan_id": generate_scan_id(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scanner_version": "0.3.1",
        "repo_hash": None,
        "scan_status": "failed",
        "scan_duration_ms": 0,
        "files_scanned": 0,
        "files_total": 0,
        "parser_errors": 0,
        "schema_id": 5,
        "schema_version": "0.3.2",
        "failure_reason": reason,
        "failure_detail": str(stderr)[:500] if stderr else None,
        "risk_score": None,
        "finding_rule_count": 0,
        "agent_count": 0,
        "crew_count": 0,
        "frameworks": [],
        "selection_stratum": repo_record.get("selection_stratum"),
        "repo_full_name": repo_record.get("repo_full_name"),
    }


def validate_ping(ping):
    """Validate a successful scan ping against v7.2 schema invariants.

    Returns a list of error strings. Empty list = valid.
    """
    errors = []

    if ping.get("scan_status") in ("failed", "empty"):
        return errors  # minimal pings skip validation

    if ping.get("schema_id") != 5:
        errors.append(f"schema_id={ping.get('schema_id')}, expected 5")

    severities = ping.get("finding_severities", {})
    if ping.get("finding_rule_count") != sum(severities.values()):
        errors.append("finding_rule_count != sum(severities)")

    instance_counts = ping.get("finding_instance_counts", {})
    if ping.get("total_finding_instances") != sum(instance_counts.values()):
        errors.append("total_finding_instances != sum(instance_counts)")

    crew_dist = ping.get("crew_size_distribution", [])
    if len(crew_dist) != ping.get("crew_count", 0):
        errors.append("crew_size_distribution length != crew_count")

    agent_dist = ping.get("agent_tool_count_distribution", [])
    if len(agent_dist) != ping.get("agent_count", 0):
        errors.append("agent_tool_count_distribution length != agent_count")

    # --- v7.1 / v7.2 field checks ---

    # scanner_version: present and string
    sv = ping.get("scanner_version")
    if sv is None:
        errors.append("scanner_version is missing")
    elif not isinstance(sv, str):
        errors.append(f"scanner_version is {type(sv).__name__}, expected str")

    # schema_version must be '0.3.2'
    if ping.get("schema_version") != "0.3.2":
        errors.append(f"schema_version={ping.get('schema_version')!r}, expected '0.3.2'")

    # frameworks / framework_versions consistency
    frameworks = ping.get("frameworks")
    fw_versions = ping.get("framework_versions")
    if frameworks is not None:
        if not isinstance(frameworks, list):
            errors.append(f"frameworks is {type(frameworks).__name__}, expected list")
        elif fw_versions is not None:
            if set(frameworks) != set(fw_versions.keys()):
                errors.append(
                    f"frameworks keys mismatch: frameworks={sorted(frameworks)}, "
                    f"framework_versions keys={sorted(fw_versions.keys())}"
                )

    # deployment_signals.deployment_score == count of true booleans
    dep_signals = ping.get("deployment_signals")
    if isinstance(dep_signals, dict):
        score = dep_signals.get("deployment_score")
        if score is not None:
            true_count = sum(
                1 for k, v in dep_signals.items()
                if k != "deployment_score" and v is True
            )
            if score != true_count:
                errors.append(
                    f"deployment_signals.deployment_score={score}, "
                    f"but count of true booleans={true_count}"
                )

    # inter_crew_edges: int >= 0 and <= graph_edge_count
    ice = ping.get("inter_crew_edges")
    if ice is not None:
        if not isinstance(ice, int) or ice < 0:
            errors.append(f"inter_crew_edges={ice}, expected int >= 0")
        else:
            gec = ping.get("graph_edge_count")
            if gec is not None and ice > gec:
                errors.append(
                    f"inter_crew_edges={ice} > graph_edge_count={gec}"
                )

    # fix_impact_estimates: all values must be negative integers
    fie = ping.get("fix_impact_estimates")
    if isinstance(fie, dict):
        for key, val in fie.items():
            if not isinstance(val, int) or val >= 0:
                errors.append(
                    f"fix_impact_estimates[{key!r}]={val}, expected negative int"
                )

    return errors
