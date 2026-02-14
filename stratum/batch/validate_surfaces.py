"""Validate cross-project connectable surface quality on real batch data.

This is a hypothesis test: can static analysis infer multi-project topology?
Run after batch scan to test whether env vars, LLM models, and vector stores
produce meaningful cross-project connections for orgs with 3+ repos.

Usage:
    python -m stratum.batch.validate_surfaces --profiles-dir ./scans/
"""
from __future__ import annotations

import argparse
import json
import logging
import os

logger = logging.getLogger(__name__)


def validate_connections(profiles_dir: str) -> dict:
    """Test cross-project connection quality on batch scan profiles.

    Groups profiles by org_id, then analyzes orgs with 3+ projects.
    Returns stats dict with overlap counts and percentages.
    """
    # Load all profiles
    profiles_by_org: dict[str, list[dict]] = {}
    total = 0

    for fname in os.listdir(profiles_dir):
        if not fname.endswith(".json"):
            continue
        try:
            with open(os.path.join(profiles_dir, fname), "r", encoding="utf-8") as f:
                data = json.load(f)
            # Support both flat profiles and nested (scan_profile + repo_context)
            profile = data.get("scan_profile", data)
            org = profile.get("org_id") or profile.get("_batch", {}).get("org", "unknown")
            if not org or org == "unknown":
                continue
            profiles_by_org.setdefault(org, []).append(profile)
            total += 1
        except (OSError, json.JSONDecodeError, KeyError):
            continue

    # Filter to orgs with 3+ projects
    multi_orgs = {k: v for k, v in profiles_by_org.items() if len(v) >= 3}

    results = {
        "total_profiles": total,
        "total_orgs": len(profiles_by_org),
        "multi_project_orgs": len(multi_orgs),
        "model_overlap": 0,
        "specific_env_overlap": 0,
        "vector_overlap": 0,
        "any_connection": 0,
        "universal_only": 0,
    }

    for org, projects in multi_orgs.items():
        models = [
            set(m["model"] for m in p.get("llm_models", []) if isinstance(m, dict))
            for p in projects
        ]
        specific_envs = [
            set(e["name"] for e in p.get("env_var_names_specific", []) if isinstance(e, dict))
            for p in projects
        ]
        vectors = [
            set(p.get("vector_stores", []))
            for p in projects
        ]
        universal_envs = [
            set(
                e["name"] for e in p.get("env_var_names", [])
                if isinstance(e, dict) and e.get("specificity") == "universal"
            )
            for p in projects
        ]

        has_model = _sets_overlap(models)
        has_specific_env = _sets_overlap(specific_envs)
        has_vector = _sets_overlap(vectors)
        has_universal = _sets_overlap(universal_envs)

        if has_model:
            results["model_overlap"] += 1
        if has_specific_env:
            results["specific_env_overlap"] += 1
        if has_vector:
            results["vector_overlap"] += 1
        if has_model or has_specific_env or has_vector:
            results["any_connection"] += 1
        if has_universal and not has_specific_env and not has_vector:
            results["universal_only"] += 1

    # Calculate percentages
    n = results["multi_project_orgs"]
    if n > 0:
        results["model_overlap_pct"] = round(results["model_overlap"] * 100 / n, 1)
        results["specific_env_overlap_pct"] = round(results["specific_env_overlap"] * 100 / n, 1)
        results["vector_overlap_pct"] = round(results["vector_overlap"] * 100 / n, 1)
        results["any_connection_pct"] = round(results["any_connection"] * 100 / n, 1)
        results["universal_only_pct"] = round(results["universal_only"] * 100 / n, 1)

    # Decision thresholds
    results["decision"] = _make_decision(results)
    return results


def _sets_overlap(sets: list[set]) -> bool:
    """Check if any two sets share at least one element."""
    for i, a in enumerate(sets):
        for b in sets[i + 1:]:
            if a & b:
                return True
    return False


def _make_decision(results: dict) -> str:
    """Determine whether connectable surfaces are viable for Phase 3."""
    pct = results.get("any_connection_pct", 0)
    if pct > 40:
        return "PROCEED: Connectable surfaces work — invest in Phase 3 visualization"
    elif pct > 20:
        return "MIXED: Some signal — tune env var classification before Phase 3"
    else:
        return "RETHINK: Static analysis alone may not infer topology — consider alternative"


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate connectable surfaces")
    parser.add_argument("--profiles-dir", type=str, required=True,
                        help="Directory with batch scan profile JSONs")
    parser.add_argument("--output", type=str, help="Write results to JSON file")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(message)s",
    )

    results = validate_connections(args.profiles_dir)

    print(json.dumps(results, indent=2))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    main()
