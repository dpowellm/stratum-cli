"""Aggregate statistics across scans."""
from __future__ import annotations

from risk_map.ingestion import ProfileStore
from risk_map.models import AggregateStats


def aggregate(store: ProfileStore) -> AggregateStats:
    """Compute aggregate statistics from all stored profiles."""
    profiles = store.load_all()
    stats = AggregateStats()

    if not profiles:
        return stats

    stats.total_scans = len(profiles)

    # Scans by week
    for p in profiles:
        ts = p.get("timestamp", "")
        week = ts[:10] if len(ts) >= 10 else "unknown"
        stats.scans_by_week[week] = stats.scans_by_week.get(week, 0) + 1

    # Capability prevalence
    cap_counts: dict[str, int] = {}
    for p in profiles:
        for cap_type, count in p.get("capability_distribution", {}).items():
            if count > 0:
                cap_counts[cap_type] = cap_counts.get(cap_type, 0) + 1
    for cap_type, count in cap_counts.items():
        stats.capability_prevalence[cap_type] = round(count / len(profiles), 2)

    # Trust crossing prevalence
    crossing_counts: dict[str, int] = {}
    for p in profiles:
        for crossing, count in p.get("trust_crossings", {}).items():
            if count > 0:
                crossing_counts[crossing] = crossing_counts.get(crossing, 0) + 1
    for crossing, count in crossing_counts.items():
        stats.trust_crossing_prevalence[crossing] = round(count / len(profiles), 2)

    # Guardrail adoption rate
    with_guards = sum(1 for p in profiles if p.get("has_any_guardrails", False))
    stats.guardrail_adoption_rate = round(with_guards / len(profiles), 2)

    # Guardrail type rates
    guard_type_counts: dict[str, int] = {}
    for p in profiles:
        for gt in p.get("guardrail_types", []):
            guard_type_counts[gt] = guard_type_counts.get(gt, 0) + 1
    for gt, count in guard_type_counts.items():
        stats.guardrail_type_rates[gt] = round(count / len(profiles), 2)

    # Risk score
    scores = [p.get("risk_score", 0) for p in profiles]
    stats.avg_risk_score = round(sum(scores) / len(scores), 1)

    # Risk score distribution
    for score in scores:
        if score >= 80:
            bucket = "critical"
        elif score >= 60:
            bucket = "high"
        elif score >= 40:
            bucket = "medium"
        else:
            bucket = "low"
        stats.risk_score_distribution[bucket] = (
            stats.risk_score_distribution.get(bucket, 0) + 1
        )

    # Finding prevalence
    finding_counts: dict[str, int] = {}
    for p in profiles:
        for sev, count in p.get("finding_severities", {}).items():
            if count > 0:
                finding_counts[sev] = finding_counts.get(sev, 0) + 1
    for sev, count in finding_counts.items():
        stats.finding_prevalence[sev] = round(count / len(profiles), 2)

    # MCP stats
    mcp_counts = [p.get("mcp_server_count", 0) for p in profiles]
    stats.avg_mcp_servers = round(sum(mcp_counts) / len(mcp_counts), 1)
    auth_ratios = [p.get("mcp_auth_ratio", 0.0) for p in profiles]
    stats.mcp_auth_rate = round(sum(auth_ratios) / len(auth_ratios), 2)
    pinned_ratios = [p.get("mcp_pinned_ratio", 0.0) for p in profiles]
    stats.mcp_pinned_rate = round(sum(pinned_ratios) / len(pinned_ratios), 2)

    return stats
