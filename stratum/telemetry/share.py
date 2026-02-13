"""One-way telemetry submission. POST only — no reads, no responses parsed.

This module is the ONLY network call in stratum-cli. It sends an anonymized
TelemetryProfile as JSON to the Stratum telemetry endpoint. The response
status is logged but never affects scan results or exit codes.
"""
from __future__ import annotations

import json
import logging
import platform
import sys
import time
import urllib.request
import urllib.error
from dataclasses import asdict, dataclass, field

logger = logging.getLogger(__name__)

TELEMETRY_ENDPOINT = "https://telemetry.stratum.dev/v1/profiles"
USAGE_ENDPOINT = "https://telemetry.stratum.dev/v1/usage"
TIMEOUT_SECONDS = 5


@dataclass
class UsagePing:
    """~250 bytes. Sent once per scan. Anonymous. Opt-in."""

    # Scanner identity
    v: str = ""
    os: str = ""
    py: str = ""

    # Project signal (anonymous, stable)
    project_hash: str = ""
    sig: str = ""                       # topology_signature

    # Framework signal
    fw: list[str] = field(default_factory=list)
    parse_quality: str = ""

    # Value signal
    agents: int = 0
    crews: int = 0
    findings: int = 0
    max_sev: str = "none"
    score: int = 0
    findings_by_cat: dict = field(default_factory=dict)

    # Adoption signal
    scan_source: str = "cli"
    duration_ms: int = 0
    files: int = 0

    # Feature engagement signal (v3)
    flags_used: list[str] = field(default_factory=list)
    fix_count: int = 0
    output_mode: str = "default"

    # v4 signals
    arch_findings: int = 0
    findings_by_class: dict = field(default_factory=dict)
    is_rescan: bool = False
    prev_score: int = 0
    score_delta: int = 0
    resolved_count: int = 0
    new_count: int = 0

    # Debug signal
    error: str = ""
    error_module: str = ""


def build_usage_ping(
    result,
    scan_profile=None,
    duration_ms: int = 0,
    flags_used: list[str] | None = None,
    fix_count: int = 0,
    output_mode: str = "default",
    error: str = "",
    error_module: str = "",
) -> UsagePing:
    """Build a UsagePing from a ScanResult and optional ScanProfile."""
    from stratum import __version__

    all_findings = result.top_paths + result.signals
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    max_sev = "none"
    for s in sev_order:
        if any(f.severity.value == s for f in all_findings):
            max_sev = s.lower()
            break

    # Findings by category
    findings_by_cat: dict[str, int] = {}
    for f in all_findings:
        cat = getattr(f, "category", "other")
        if hasattr(cat, "value"):
            cat = cat.value
        findings_by_cat[cat] = findings_by_cat.get(cat, 0) + 1

    # v4: findings by class
    findings_by_class: dict[str, int] = {}
    arch_findings = 0
    for f in all_findings:
        fc = getattr(f, "finding_class", "security")
        findings_by_class[fc] = findings_by_class.get(fc, 0) + 1
        if fc == "architecture":
            arch_findings += 1

    # v4: rescan delta
    diff = getattr(result, "diff", None)
    is_rescan = diff is not None
    prev_score = diff.previous_risk_score if diff else 0
    score_delta = diff.risk_score_delta if diff else 0
    resolved_count = len(diff.resolved_finding_ids) if diff else 0
    new_count = len(diff.new_finding_ids) if diff else 0

    ping = UsagePing(
        v=__version__,
        os=sys.platform,
        py=f"{sys.version_info.major}.{sys.version_info.minor}",
        project_hash=getattr(scan_profile, "project_hash", "") if scan_profile else "",
        sig=getattr(scan_profile, "topology_signature", "") if scan_profile else "",
        fw=list(result.detected_frameworks),
        parse_quality=getattr(result, "framework_parse_quality", "unknown"),
        agents=len(getattr(result, "agent_definitions", [])),
        crews=len(getattr(result, "crew_definitions", [])),
        findings=len(all_findings),
        max_sev=max_sev,
        score=result.risk_score,
        findings_by_cat=findings_by_cat,
        scan_source=getattr(scan_profile, "scan_source", "cli") if scan_profile else "cli",
        duration_ms=duration_ms,
        files=getattr(result, "files_scanned", 0),
        flags_used=flags_used or [],
        fix_count=fix_count,
        output_mode=output_mode,
        arch_findings=arch_findings,
        findings_by_class=findings_by_class,
        is_rescan=is_rescan,
        prev_score=prev_score,
        score_delta=score_delta,
        resolved_count=resolved_count,
        new_count=new_count,
        error=error,
        error_module=error_module,
    )
    return ping


def submit_profile(profile_dict: dict) -> bool:
    """Submit an anonymized telemetry profile via one-way POST.

    Returns True if the server responded with 2xx, False otherwise.
    Never raises — all errors are caught and logged.
    Does not affect scan results or exit codes.
    """
    return _post_json(TELEMETRY_ENDPOINT, profile_dict)


def submit_usage_ping(ping: UsagePing) -> bool:
    """Submit a lightweight usage ping via one-way POST.

    Returns True if the server responded with 2xx, False otherwise.
    Never raises.
    """
    return _post_json(USAGE_ENDPOINT, asdict(ping))


def _post_json(url: str, data_dict: dict) -> bool:
    """POST JSON to a URL. Returns True on 2xx, False otherwise."""
    try:
        data = json.dumps(data_dict).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            status = resp.status
            logger.debug("Telemetry POST %s: HTTP %d", url, status)
            return 200 <= status < 300
    except (urllib.error.URLError, OSError, ValueError) as e:
        logger.debug("Telemetry POST %s failed: %s", url, e)
        return False
