"""Anonymized telemetry profile builder.

No source code, secrets, paths, function names, or env values.
Just counts and ratios.
"""
from __future__ import annotations

from stratum.models import ScanResult, TelemetryProfile
from stratum.knowledge.db import HTTP_LIBRARIES


def build_profile(result: ScanResult) -> TelemetryProfile:
    """Build an anonymized telemetry profile from a ScanResult."""
    # Capability distribution
    cap_dist: dict[str, int] = {}
    trust_dist: dict[str, int] = {}
    for cap in result.capabilities:
        cap_dist[cap.kind] = cap_dist.get(cap.kind, 0) + 1
        tl = cap.trust_level.value
        trust_dist[tl] = trust_dist.get(tl, 0) + 1

    # Trust crossings
    trust_crossings: dict[str, int] = {}
    caps = result.capabilities
    seen_pairs: set[tuple[str, str]] = set()
    for i, c1 in enumerate(caps):
        for c2 in caps[i + 1:]:
            if c1.trust_level != c2.trust_level:
                pair = tuple(sorted([c1.trust_level.value, c2.trust_level.value]))
                pair_key = (pair[0], pair[1])
                if pair_key not in seen_pairs:
                    seen_pairs.add(pair_key)
                key = f"{pair[0]}\u2192{pair[1]}"
                trust_crossings[key] = trust_crossings.get(key, 0) + 1

    # MCP stats
    mcp_remote = sum(1 for s in result.mcp_servers if s.is_remote)
    mcp_auth = (
        sum(1 for s in result.mcp_servers if s.has_auth) / len(result.mcp_servers)
        if result.mcp_servers else 0.0
    )
    mcp_pinned = (
        sum(1 for s in result.mcp_servers if s.package_version) / len(result.mcp_servers)
        if result.mcp_servers else 0.0
    )

    # Guardrail types
    guard_types = list({g.kind for g in result.guardrails})

    # Finding severities and confidences
    all_findings = result.top_paths + result.signals
    sev_dist: dict[str, int] = {}
    conf_dist: dict[str, int] = {}
    for f in all_findings:
        sev_dist[f.severity.value] = sev_dist.get(f.severity.value, 0) + 1
        conf_dist[f.confidence.value] = conf_dist.get(f.confidence.value, 0) + 1

    # Error handling rate
    external_caps = [
        c for c in result.capabilities
        if c.kind in ("outbound", "data_access", "financial")
    ]
    error_rate = (
        sum(1 for c in external_caps if c.has_error_handling) / len(external_caps)
        if external_caps else 0.0
    )

    # Timeout rate
    http_caps = [
        c for c in result.capabilities
        if c.kind == "outbound" and c.library in HTTP_LIBRARIES
    ]
    timeout_rate = (
        sum(1 for c in http_caps if c.has_timeout) / len(http_caps)
        if http_caps else 0.0
    )

    # Financial validation rate
    fin_caps = [c for c in result.capabilities if c.kind == "financial"]
    fin_val_rate = (
        sum(1 for c in fin_caps if c.has_input_validation) / len(fin_caps)
        if fin_caps else 0.0
    )

    return TelemetryProfile(
        scan_id=result.scan_id,
        timestamp=result.timestamp,
        total_capabilities=result.total_capabilities,
        capability_distribution=cap_dist,
        trust_level_distribution=trust_dist,
        trust_crossings=trust_crossings,
        total_trust_crossings=sum(trust_crossings.values()),
        mcp_server_count=result.mcp_server_count,
        mcp_remote_count=mcp_remote,
        mcp_auth_ratio=round(mcp_auth, 2),
        mcp_pinned_ratio=round(mcp_pinned, 2),
        guardrail_count=result.guardrail_count,
        has_any_guardrails=result.has_any_guardrails,
        guardrail_types=guard_types,
        risk_score=result.risk_score,
        finding_severities=sev_dist,
        finding_confidences=conf_dist,
        env_var_count=len(result.env_vars),
        has_env_in_gitignore=False,  # Could be computed if needed
        error_handling_rate=round(error_rate, 2),
        timeout_rate=round(timeout_rate, 2),
        checkpoint_type=result.checkpoint_type,
        has_financial_tools=any(c.kind == "financial" for c in result.capabilities),
        financial_validation_rate=round(fin_val_rate, 2),
    )
