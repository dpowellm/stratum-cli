"""Generate "State of AI Agent Security" ecosystem report from batch scan data.

Aggregates statistics across thousands of scanned agent projects to produce
a publishable report with key insights about the AI agent security landscape.

Usage:
    python -m stratum.batch.ecosystem_report --profiles-dir ./scans/ --output ecosystem-2026.json
"""
from __future__ import annotations

import argparse
import json
import logging
import os
from collections import Counter
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def generate_ecosystem_report(profiles_dir: str) -> dict:
    """Generate ecosystem statistics from batch scan profiles.

    Returns a dict with all statistics suitable for publishing.
    """
    profiles = _load_all_profiles(profiles_dir)
    if not profiles:
        return {"error": "No profiles found"}

    n = len(profiles)
    logger.info("Analyzing %d profiles", n)

    # --- Framework distribution ---
    fw_counter: Counter = Counter()
    for p in profiles:
        for fw in p.get("frameworks", []):
            fw_counter[fw] += 1

    # --- Parse quality distribution ---
    quality_counter: Counter = Counter()
    for p in profiles:
        quality_counter[p.get("framework_parse_quality", "unknown")] += 1

    # --- Risk score distribution ---
    risk_scores = [p.get("risk_score", 0) for p in profiles]
    risk_scores.sort()
    risk_percentiles = _compute_percentiles(risk_scores)

    # --- Maturity distribution ---
    maturity_counter: Counter = Counter()
    for p in profiles:
        maturity_counter[p.get("maturity_level", "unknown")] += 1

    maturity_scores = [p.get("maturity_score", 0) for p in profiles]
    maturity_scores.sort()

    # --- HITL adoption ---
    hitl_count = sum(1 for p in profiles if p.get("has_hitl"))
    no_hitl_count = n - hitl_count

    # --- Breach pattern prevalence ---
    breach_count = sum(1 for p in profiles if p.get("matches_any_breach"))
    echoleak_count = sum(1 for p in profiles if p.get("matches_echoleak"))

    # --- Finding category distribution ---
    category_totals: Counter = Counter()
    for p in profiles:
        for cat, count in p.get("findings_by_category", {}).items():
            category_totals[cat] += count

    # --- Most common finding IDs ---
    finding_counter: Counter = Counter()
    for p in profiles:
        for fid in p.get("finding_ids", []):
            finding_counter[fid] += 1

    # --- Model dependency ---
    model_counter: Counter = Counter()
    provider_counter: Counter = Counter()
    for p in profiles:
        for m in p.get("llm_models", []):
            if isinstance(m, dict):
                model_counter[m.get("model", "unknown")] += 1
                provider_counter[m.get("provider", "unknown")] += 1

    single_provider = sum(1 for p in profiles if not p.get("has_multiple_providers"))

    # --- Blast radius stats ---
    blast_radii = [p.get("max_blast_radius", 0) for p in profiles]
    avg_blast = round(sum(blast_radii) / n, 2) if n else 0

    # --- Agent/crew sizes ---
    agent_counts = [p.get("agent_count", 0) for p in profiles if p.get("agent_count", 0) > 0]
    crew_counts = [p.get("crew_count", 0) for p in profiles if p.get("crew_count", 0) > 0]

    # --- Guardrail adoption ---
    no_guardrails = sum(1 for p in profiles if p.get("guardrail_count", 0) == 0)
    has_observability = sum(1 for p in profiles if p.get("has_observability"))
    has_rate_limiting = sum(1 for p in profiles if p.get("has_rate_limiting"))
    has_error_handling = sum(1 for p in profiles if p.get("has_error_handling"))

    report = {
        "title": "State of AI Agent Security",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_projects": n,

        # Framework distribution
        "framework_distribution": dict(fw_counter.most_common()),
        "parse_quality_distribution": dict(quality_counter),

        # Risk scores
        "risk_score_percentiles": risk_percentiles,
        "risk_score_avg": round(sum(risk_scores) / n, 1),
        "risk_score_median": risk_scores[n // 2] if risk_scores else 0,
        "projects_above_70": sum(1 for s in risk_scores if s >= 70),
        "projects_above_70_pct": round(sum(1 for s in risk_scores if s >= 70) * 100 / n, 1),

        # Maturity
        "maturity_distribution": dict(maturity_counter),
        "maturity_avg": round(sum(maturity_scores) / n, 1) if maturity_scores else 0,

        # HITL
        "hitl_adoption_pct": round(hitl_count * 100 / n, 1),
        "no_hitl_pct": round(no_hitl_count * 100 / n, 1),
        "no_hitl_count": no_hitl_count,

        # Breach patterns
        "breach_match_pct": round(breach_count * 100 / n, 1),
        "echoleak_match_pct": round(echoleak_count * 100 / n, 1),

        # Finding categories
        "finding_category_totals": dict(category_totals),
        "top_10_findings": dict(finding_counter.most_common(10)),
        "avg_findings_per_project": round(
            sum(p.get("finding_count", 0) for p in profiles) / n, 1
        ),

        # Model dependency
        "top_models": dict(model_counter.most_common(10)),
        "top_providers": dict(provider_counter.most_common()),
        "single_provider_pct": round(single_provider * 100 / n, 1),

        # Blast radius
        "avg_max_blast_radius": avg_blast,

        # Project sizes
        "avg_agents": round(sum(agent_counts) / len(agent_counts), 1) if agent_counts else 0,
        "avg_crews": round(sum(crew_counts) / len(crew_counts), 1) if crew_counts else 0,

        # Guardrail adoption
        "no_guardrails_pct": round(no_guardrails * 100 / n, 1),
        "observability_pct": round(has_observability * 100 / n, 1),
        "rate_limiting_pct": round(has_rate_limiting * 100 / n, 1),
        "error_handling_pct": round(has_error_handling * 100 / n, 1),

        # Key takeaways (auto-generated)
        "key_findings": _generate_key_findings(
            n, hitl_count, breach_count, no_guardrails,
            risk_percentiles, single_provider, provider_counter,
        ),
    }

    return report


def build_percentile_lookup(profiles_dir: str) -> dict[int, float]:
    """Build a risk score -> percentile lookup table from batch data.

    Returns dict mapping risk_score -> percentile (0-100).
    Used by the terminal output to show "73rd percentile" next to risk score.
    """
    profiles = _load_all_profiles(profiles_dir)
    scores = sorted(p.get("risk_score", 0) for p in profiles)
    if not scores:
        return {}

    n = len(scores)
    lookup: dict[int, float] = {}
    for score in range(0, 101):
        # Count how many scores are below this score
        below = sum(1 for s in scores if s < score)
        lookup[score] = round(below * 100 / n, 1)

    return lookup


def _load_all_profiles(profiles_dir: str) -> list[dict]:
    """Load all profiles from a directory."""
    profiles = []
    for fname in os.listdir(profiles_dir):
        if not fname.endswith(".json"):
            continue
        try:
            with open(os.path.join(profiles_dir, fname), "r", encoding="utf-8") as f:
                data = json.load(f)
            profile = data.get("scan_profile", data)
            if profile.get("framework_parse_quality") != "empty":
                profiles.append(profile)
        except (OSError, json.JSONDecodeError):
            continue
    return profiles


def _compute_percentiles(sorted_scores: list[int]) -> dict:
    """Compute percentile values from sorted scores."""
    n = len(sorted_scores)
    if n == 0:
        return {}
    return {
        "p10": sorted_scores[int(n * 0.1)],
        "p25": sorted_scores[int(n * 0.25)],
        "p50": sorted_scores[int(n * 0.5)],
        "p75": sorted_scores[int(n * 0.75)],
        "p90": sorted_scores[int(n * 0.9)],
        "p95": sorted_scores[min(int(n * 0.95), n - 1)],
    }


def _generate_key_findings(
    n: int, hitl_count: int, breach_count: int, no_guardrails: int,
    percentiles: dict, single_provider: int, provider_counter: Counter,
) -> list[str]:
    """Auto-generate key finding statements for the report."""
    findings = []

    hitl_pct = round(hitl_count * 100 / n, 1) if n else 0
    if hitl_pct < 30:
        findings.append(
            f"Only {hitl_pct}% of agent projects implement human-in-the-loop review. "
            f"{n - hitl_count} projects let agents take actions without human approval."
        )

    breach_pct = round(breach_count * 100 / n, 1) if n else 0
    if breach_pct > 10:
        findings.append(
            f"{breach_pct}% of projects match known breach patterns. "
            f"The most common match is the EchoLeak pattern (unguarded inbox-to-outbound flow)."
        )

    if provider_counter:
        top_provider = provider_counter.most_common(1)[0]
        sp_pct = round(single_provider * 100 / n, 1) if n else 0
        if sp_pct > 60:
            findings.append(
                f"{sp_pct}% of projects depend on a single LLM provider ({top_provider[0]}). "
                f"A single-provider outage would affect the majority of the ecosystem."
            )

    no_guard_pct = round(no_guardrails * 100 / n, 1) if n else 0
    if no_guard_pct > 40:
        findings.append(
            f"{no_guard_pct}% of projects have zero guardrails. "
            f"No input validation, no output filtering, no human review."
        )

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate ecosystem report")
    parser.add_argument("--profiles-dir", type=str, required=True)
    parser.add_argument("--output", type=str, help="Output JSON file")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(message)s",
    )

    report = generate_ecosystem_report(args.profiles_dir)
    output = json.dumps(report, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Report written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
