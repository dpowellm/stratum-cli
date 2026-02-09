"""Derive risk intelligence from aggregated data."""
from __future__ import annotations

from stratum.models import TelemetryProfile
from risk_map.ingestion import ProfileStore
from risk_map.models import AggregateStats, RiskIntelligence


def derive_intelligence(
    store: ProfileStore, stats: AggregateStats,
) -> RiskIntelligence:
    """Derive risk intelligence from stored profiles. Requires minimum 10 profiles."""
    profiles = store.load_all()
    intel = RiskIntelligence()

    if len(profiles) < 10:
        return intel

    # Capability combo risk: which combinations correlate with high scores
    combo_scores: dict[str, list[float]] = {}
    for p in profiles:
        caps = set(p.get("capability_distribution", {}).keys())
        score = p.get("risk_score", 0)
        for c1 in sorted(caps):
            for c2 in sorted(caps):
                if c1 < c2:
                    combo = f"{c1}+{c2}"
                    combo_scores.setdefault(combo, []).append(score)

    for combo, scores in combo_scores.items():
        if len(scores) >= 3:
            intel.capability_combo_risk[combo] = round(
                sum(scores) / len(scores), 1
            )

    # Guardrail benchmarks: avg score with vs without each guardrail type
    for gt in stats.guardrail_type_rates:
        with_gt = [
            p.get("risk_score", 0) for p in profiles
            if gt in p.get("guardrail_types", [])
        ]
        without_gt = [
            p.get("risk_score", 0) for p in profiles
            if gt not in p.get("guardrail_types", [])
        ]
        if with_gt and without_gt:
            intel.guardrail_benchmarks[gt] = round(
                sum(without_gt) / len(without_gt) - sum(with_gt) / len(with_gt), 1
            )

    # Crossing risk correlation
    for crossing in stats.trust_crossing_prevalence:
        with_crossing = [
            p for p in profiles
            if crossing in p.get("trust_crossings", {})
        ]
        if len(with_crossing) >= 3:
            avg_score = sum(p.get("risk_score", 0) for p in with_crossing) / len(with_crossing)
            intel.crossing_risk_correlation[crossing] = {
                "avg_score": round(avg_score, 1),
                "count": len(with_crossing),
            }

    return intel


def generate_contextual_insights(
    profile: TelemetryProfile,
    intel: RiskIntelligence,
) -> list[str]:
    """Generate insight strings for a specific scan vs ecosystem."""
    insights: list[str] = []

    # Compare risk score to combo averages
    for combo, avg_score in intel.capability_combo_risk.items():
        caps = combo.split("+")
        if all(c in profile.capability_distribution for c in caps):
            if profile.risk_score > avg_score * 1.2:
                insights.append(
                    f"Your risk score ({profile.risk_score}) is above average "
                    f"({avg_score:.0f}) for projects with {combo}."
                )

    # Guardrail benchmarks
    for gt, reduction in intel.guardrail_benchmarks.items():
        if gt not in profile.guardrail_types and reduction > 5:
            insights.append(
                f"Adding {gt} guardrails typically reduces risk score by {reduction:.0f} points."
            )

    return insights
