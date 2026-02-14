#!/usr/bin/env python
"""Phase 4: Post-collection dataset audit for the Stratum 50k pipeline.

Reads scan_results.jsonl, assesses dataset quality against 8 gates,
and produces a markdown audit report with ASCII histograms.

Usage:
    python pipeline/audit.py                                          # full audit
    python pipeline/audit.py --input pipeline/data/scan_results.jsonl # custom input
    python pipeline/audit.py --split                                  # also train/test split
    python pipeline/audit.py --section duplicates                     # single section
"""

import argparse
import hashlib
import json
import math
import os
import random
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from statistics import median

# Allow running from repo root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_pings(path):
    """Load all pings from a JSONL file."""
    pings = []
    if not os.path.exists(path):
        return pings
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    pings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return pings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BAR_WIDTH = 40  # max bar chart width in characters


def ascii_bar(value, max_value):
    """Return an ASCII bar scaled to BAR_WIDTH."""
    if max_value <= 0:
        return ""
    width = int((value / max_value) * BAR_WIDTH)
    return "#" * max(width, 1) if value > 0 else ""


def fmt_pct(num, den):
    """Format a percentage string."""
    if den == 0:
        return "0.0%"
    return f"{(num / den) * 100:.1f}%"


def quartiles(values):
    """Return (min, q1, median, q3, max) for a list of numbers."""
    if not values:
        return (0, 0, 0, 0, 0)
    s = sorted(values)
    n = len(s)
    q1_idx = n // 4
    q3_idx = (3 * n) // 4
    return (s[0], s[q1_idx], median(s), s[q3_idx], s[-1])


# ---------------------------------------------------------------------------
# Quality gates
# ---------------------------------------------------------------------------

TOP_5_FRAMEWORKS = ["LangChain", "CrewAI", "LangGraph", "AutoGen", "LlamaIndex"]


def evaluate_gates(pings):
    """Evaluate all 8 quality gates. Returns list of (id, name, passed, evidence)."""
    total = len(pings)

    status_counts = Counter(p.get("scan_status", "unknown") for p in pings)
    success_count = status_counts.get("success", 0)
    partial_count = status_counts.get("partial", 0)
    failed_count = status_counts.get("failed", 0)
    empty_count = status_counts.get("empty", 0)

    effective = success_count + partial_count

    # Framework counts (from successful/partial pings only)
    fw_repo_counts = Counter()
    for p in pings:
        if p.get("scan_status") in ("success", "partial"):
            for fw in p.get("frameworks", []):
                fw_repo_counts[fw] += 1

    # Deployment scores
    dep_scores = []
    for p in pings:
        if p.get("scan_status") in ("success", "partial"):
            ds = p.get("deployment_signals")
            if isinstance(ds, dict):
                score = ds.get("deployment_score")
                if isinstance(score, int):
                    dep_scores.append(score)

    mature_count = sum(1 for s in dep_scores if s >= 3)

    # Finding rule prevalence
    rule_repo_counts = Counter()
    for p in pings:
        if p.get("scan_status") in ("success", "partial"):
            instance_counts = p.get("finding_instance_counts", {})
            for rule in instance_counts:
                rule_repo_counts[rule] += 1

    rules_over_100 = sum(1 for c in rule_repo_counts.values() if c >= 100)

    # Duplicate analysis
    topo_clusters = Counter()
    for p in pings:
        tsh = p.get("topology_signature_hash")
        if tsh:
            topo_clusters[tsh] += 1

    dup_repos = sum(c for h, c in topo_clusters.items() if c >= 10)
    dup_rate = (dup_repos / total * 100) if total > 0 else 0

    # Coverage
    coverage_ratios = []
    for p in pings:
        if p.get("scan_status") in ("success", "partial"):
            scanned = p.get("files_scanned", 0)
            total_f = p.get("files_total", 0)
            if total_f > 0:
                coverage_ratios.append(scanned / total_f)

    med_coverage = median(coverage_ratios) if coverage_ratios else 0

    gates = [
        (
            "G1", "Volume",
            effective >= 40000,
            f"success+partial={effective:,} (need >=40,000)",
        ),
        (
            "G2", "Framework coverage",
            all(fw_repo_counts.get(fw, 0) >= 1000 for fw in TOP_5_FRAMEWORKS),
            "; ".join(f"{fw}={fw_repo_counts.get(fw, 0):,}" for fw in TOP_5_FRAMEWORKS),
        ),
        (
            "G3", "Maturity spread",
            mature_count >= 2000,
            f"repos with deployment_score>=3: {mature_count:,} (need >=2,000)",
        ),
        (
            "G4", "Finding coverage",
            rules_over_100 >= 15,
            f"rules in 100+ repos: {rules_over_100} (need >=15)",
        ),
        (
            "G5", "Duplicate rate",
            dup_rate <= 5.0,
            f"dup_rate={dup_rate:.1f}% (need <=5%); {dup_repos:,} repos in clusters of 10+",
        ),
        (
            "G6", "Empty rate",
            (empty_count / total * 100 if total else 0) <= 20.0,
            f"empty={empty_count:,}/{total:,} ({fmt_pct(empty_count, total)}; need <=20%)",
        ),
        (
            "G7", "Failure rate",
            (failed_count / total * 100 if total else 0) <= 10.0,
            f"failed={failed_count:,}/{total:,} ({fmt_pct(failed_count, total)}; need <=10%)",
        ),
        (
            "G8", "Coverage",
            med_coverage >= 0.8,
            f"median(files_scanned/files_total)={med_coverage:.3f} (need >=0.80)",
        ),
    ]

    return gates


# ---------------------------------------------------------------------------
# Report sections
# ---------------------------------------------------------------------------

def section_volume(pings):
    """Section 1: Volume summary."""
    total = len(pings)
    status_counts = Counter(p.get("scan_status", "unknown") for p in pings)
    effective = status_counts.get("success", 0) + status_counts.get("partial", 0)

    lines = [
        "## 1. Volume Summary",
        "",
        f"| Status | Count | % |",
        f"|--------|------:|---:|",
    ]
    for status in ["success", "partial", "failed", "empty", "unknown"]:
        c = status_counts.get(status, 0)
        if c > 0 or status in ("success", "partial", "failed", "empty"):
            lines.append(f"| {status} | {c:,} | {fmt_pct(c, total)} |")
    lines.append(f"| **Total** | **{total:,}** | |")
    lines.append("")
    lines.append(f"Effective dataset size (success + partial): **{effective:,}**")
    lines.append("")
    return "\n".join(lines)


def section_frameworks(pings):
    """Section 2: Framework distribution."""
    fw_counts = Counter()
    for p in pings:
        if p.get("scan_status") in ("success", "partial"):
            for fw in p.get("frameworks", []):
                fw_counts[fw] += 1

    max_count = max(fw_counts.values()) if fw_counts else 1
    target_map = {
        "LangChain": 8000, "CrewAI": 6000, "LangGraph": 5000,
        "AutoGen": 3000, "LlamaIndex": 3000,
    }

    lines = [
        "## 2. Framework Distribution",
        "",
        "```",
    ]

    for fw, count in fw_counts.most_common(15):
        bar = ascii_bar(count, max_count)
        target = target_map.get(fw)
        gap = f"  (target: {target:,}, gap: {target - count:+,})" if target else ""
        lines.append(f"  {fw:<20} {count:>6,}  {bar}{gap}")

    lines.append("```")
    lines.append("")

    # Gap analysis
    gaps = []
    for fw in TOP_5_FRAMEWORKS:
        actual = fw_counts.get(fw, 0)
        if actual < 1000:
            gaps.append(f"- **{fw}**: {actual:,} repos (need 1,000+)")
    if gaps:
        lines.append("### Gap Analysis")
        lines.append("")
        lines.extend(gaps)
        lines.append("")

    return "\n".join(lines)


def section_scores(pings):
    """Section 3: Score distribution."""
    buckets = defaultdict(int)
    for p in pings:
        if p.get("scan_status") in ("success", "partial"):
            score = p.get("risk_score")
            if isinstance(score, (int, float)) and score is not None:
                bucket_start = min(int(score) // 10 * 10, 90)
                label = f"{bucket_start + 1}-{bucket_start + 10}" if bucket_start > 0 else "0-10"
                buckets[label] += 1

    # Ensure all buckets exist
    labels = ["0-10", "11-20", "21-30", "31-40", "41-50",
              "51-60", "61-70", "71-80", "81-90", "91-100"]
    max_count = max((buckets.get(l, 0) for l in labels), default=1)

    lines = [
        "## 3. Score Distribution",
        "",
        "```",
    ]
    for label in labels:
        count = buckets.get(label, 0)
        bar = ascii_bar(count, max_count)
        lines.append(f"  {label:>6}: {count:>6,}  {bar}")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def section_findings(pings):
    """Section 4: Finding prevalence."""
    rule_repo_counts = Counter()
    rule_impacts = defaultdict(list)

    for p in pings:
        if p.get("scan_status") in ("success", "partial"):
            instance_counts = p.get("finding_instance_counts", {})
            for rule in instance_counts:
                rule_repo_counts[rule] += 1

            fie = p.get("fix_impact_estimates", {})
            for rule, impact in fie.items():
                if isinstance(impact, (int, float)):
                    rule_impacts[rule].append(impact)

    lines = [
        "## 4. Finding Prevalence",
        "",
        "| Rule | Repos | Median Impact | Flag |",
        "|------|------:|--------------:|------|",
    ]

    for rule, count in rule_repo_counts.most_common():
        impacts = rule_impacts.get(rule, [])
        med_impact = f"{median(impacts):.0f}" if impacts else "n/a"
        flag = "" if count >= 100 else "< 100 repos"
        lines.append(f"| {rule} | {count:,} | {med_impact} | {flag} |")

    lines.append("")
    return "\n".join(lines)


def section_maturity(pings):
    """Section 5: Maturity distribution."""
    dep_histogram = Counter()
    for p in pings:
        if p.get("scan_status") in ("success", "partial"):
            ds = p.get("deployment_signals")
            if isinstance(ds, dict):
                score = ds.get("deployment_score")
                if isinstance(score, int) and 0 <= score <= 5:
                    dep_histogram[score] += 1

    max_count = max(dep_histogram.values()) if dep_histogram else 1

    lines = [
        "## 5. Maturity Distribution",
        "",
        "deployment_score histogram:",
        "",
        "```",
    ]
    for score in range(6):
        count = dep_histogram.get(score, 0)
        bar = ascii_bar(count, max_count)
        lines.append(f"  {score}: {count:>6,}  {bar}")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def section_duplicates(pings):
    """Section 6: Duplicate analysis."""
    topo_clusters = defaultdict(list)
    for p in pings:
        tsh = p.get("topology_signature_hash")
        if tsh:
            topo_clusters[tsh].append(p.get("repo_full_name", "?"))

    total = len(pings)
    big_clusters = {h: repos for h, repos in topo_clusters.items() if len(repos) >= 10}
    dup_repos = sum(len(repos) for repos in big_clusters.values())
    dup_rate = (dup_repos / total * 100) if total > 0 else 0

    lines = [
        "## 6. Duplicate Analysis",
        "",
        f"Unique topology_signature_hash values: {len(topo_clusters):,}",
        f"Clusters with 10+ members: {len(big_clusters)}",
        f"Repos in large clusters: {dup_repos:,}",
        f"Contamination rate: {dup_rate:.1f}%",
        "",
    ]

    if big_clusters:
        lines.append("### Large Clusters")
        lines.append("")
        lines.append("| Hash | Members | Sample Repos |")
        lines.append("|------|--------:|-------------|")
        for h, repos in sorted(big_clusters.items(), key=lambda x: -len(x[1])):
            sample = ", ".join(repos[:3])
            if len(repos) > 3:
                sample += f" (+{len(repos) - 3} more)"
            lines.append(f"| `{h[:12]}...` | {len(repos)} | {sample} |")
        lines.append("")

    return "\n".join(lines)


def section_coverage(pings):
    """Section 7: Coverage analysis."""
    ratios = []
    for p in pings:
        if p.get("scan_status") in ("success", "partial"):
            scanned = p.get("files_scanned", 0)
            total_f = p.get("files_total", 0)
            if total_f > 0:
                ratios.append(scanned / total_f)

    if ratios:
        mn, q1, med, q3, mx = quartiles(ratios)
    else:
        mn = q1 = med = q3 = mx = 0

    lines = [
        "## 7. Coverage Analysis",
        "",
        "files_scanned / files_total distribution:",
        "",
        f"| Stat | Value |",
        f"|------|------:|",
        f"| Min | {mn:.3f} |",
        f"| Q1 | {q1:.3f} |",
        f"| Median | {med:.3f} |",
        f"| Q3 | {q3:.3f} |",
        f"| Max | {mx:.3f} |",
        f"| N | {len(ratios):,} |",
        "",
    ]
    return "\n".join(lines)


def section_strata_fill(pings):
    """Section 8: Strata fill rates."""
    strata_targets = {s["name"]: s["target"] for s in config.STRATA}
    strata_actual = Counter()
    for p in pings:
        stratum = p.get("selection_stratum")
        if stratum:
            strata_actual[stratum] += 1

    lines = [
        "## 8. Strata Fill Rates",
        "",
        "| Stratum | Target | Actual | Fill % |",
        "|---------|-------:|-------:|-------:|",
    ]

    for name, target in strata_targets.items():
        actual = strata_actual.get(name, 0)
        pct = fmt_pct(actual, target)
        lines.append(f"| {name} | {target:,} | {actual:,} | {pct} |")

    # Any strata in data but not in config
    for name, actual in strata_actual.items():
        if name not in strata_targets:
            lines.append(f"| {name} | (unknown) | {actual:,} | - |")

    lines.append("")
    return "\n".join(lines)


def section_gates(gates):
    """Section 9: Quality gate results."""
    lines = [
        "## 9. Quality Gate Results",
        "",
        "| Gate | Name | Result | Evidence |",
        "|------|------|--------|----------|",
    ]

    for gid, name, passed, evidence in gates:
        result = "PASS" if passed else "**FAIL**"
        lines.append(f"| {gid} | {name} | {result} | {evidence} |")

    passed = sum(1 for _, _, p, _ in gates if p)
    total = len(gates)
    lines.append("")
    lines.append(f"**{passed}/{total} gates passed.**")
    lines.append("")
    return "\n".join(lines)


def section_recommendations(gates, pings):
    """Section 10: Recommendations based on gate failures."""
    failed_gates = [(gid, name, ev) for gid, name, passed, ev in gates if not passed]

    lines = [
        "## 10. Recommendations",
        "",
    ]

    if not failed_gates:
        lines.append("All quality gates passed. Dataset is ready for use.")
        lines.append("")
        return "\n".join(lines)

    for gid, name, evidence in failed_gates:
        lines.append(f"### {gid}: {name}")
        lines.append("")
        lines.append(f"Evidence: {evidence}")
        lines.append("")

        if gid == "G1":
            lines.append("- Run additional discovery queries targeting under-represented strata")
            lines.append("- Broaden date ranges or lower star thresholds in search queries")
        elif gid == "G2":
            lines.append("- Add targeted queries for under-represented frameworks")
            lines.append("- Check that framework detection covers all naming variants")
        elif gid == "G3":
            lines.append("- Add queries targeting production repos (CI/CD, Docker, deployment configs)")
            lines.append("- Lower the star threshold for high_maturity stratum")
        elif gid == "G4":
            lines.append("- Review finding rule definitions for false negatives")
            lines.append("- Ensure parser covers all framework patterns")
        elif gid == "G5":
            lines.append("- Investigate large topology clusters for template repos or forks")
            lines.append("- Consider deduplicating by topology_signature_hash")
        elif gid == "G6":
            lines.append("- Review empty scan repos for non-Python projects mis-tagged")
            lines.append("- Add language filters to discovery queries")
        elif gid == "G7":
            lines.append("- Investigate common failure reasons (clone errors, parse crashes)")
            lines.append("- Retry failed repos with increased timeouts")
        elif gid == "G8":
            lines.append("- Review parser for file types being skipped")
            lines.append("- Check for repos with many non-Python files inflating files_total")

        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Train/test split
# ---------------------------------------------------------------------------

def stratified_split(pings, train_ratio=0.8, min_test_stratum=40):
    """Split pings into train/test sets, stratified by framework x deployment_score."""
    # Only split success/partial pings
    splittable = [p for p in pings if p.get("scan_status") in ("success", "partial")]
    non_splittable = [p for p in pings if p.get("scan_status") not in ("success", "partial")]

    # Build strata keys
    def stratum_key(p):
        fws = p.get("frameworks", [])
        primary_fw = fws[0] if fws else "none"
        ds = p.get("deployment_signals")
        if isinstance(ds, dict):
            score = ds.get("deployment_score", 0)
        else:
            score = 0
        dep_bucket = "high" if score >= 3 else "low"
        return f"{primary_fw}_{dep_bucket}"

    # Group by stratum
    strata_groups = defaultdict(list)
    for p in splittable:
        strata_groups[stratum_key(p)].append(p)

    # Merge small strata into 'other'
    final_groups = defaultdict(list)
    for key, group in strata_groups.items():
        test_size = max(1, int(len(group) * (1 - train_ratio)))
        if test_size < min_test_stratum and len(group) < min_test_stratum * 2:
            final_groups["other"].extend(group)
        else:
            final_groups[key] = group

    train = []
    test = []

    for key, group in final_groups.items():
        random.shuffle(group)
        split_idx = int(len(group) * train_ratio)
        for p in group[:split_idx]:
            p["dataset_split"] = "train"
            train.append(p)
        for p in group[split_idx:]:
            p["dataset_split"] = "test"
            test.append(p)

    # Non-splittable go to train
    for p in non_splittable:
        p["dataset_split"] = "train"
        train.append(p)

    return train, test, final_groups


def write_split(train, test, train_path, test_path):
    """Write train/test splits to JSONL files."""
    os.makedirs(os.path.dirname(train_path), exist_ok=True)
    with open(train_path, "w") as f:
        for p in train:
            f.write(json.dumps(p) + "\n")
    with open(test_path, "w") as f:
        for p in test:
            f.write(json.dumps(p) + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

SECTION_MAP = {
    "volume": section_volume,
    "frameworks": section_frameworks,
    "scores": section_scores,
    "findings": section_findings,
    "maturity": section_maturity,
    "duplicates": section_duplicates,
    "coverage": section_coverage,
    "strata": section_strata_fill,
}


def run_audit(input_path, report_path, do_split=False, section_filter=None):
    """Run the full audit and write the report."""
    pings = load_pings(input_path)

    if not pings:
        print(f"No pings found in {input_path}")
        return

    print(f"Loaded {len(pings):,} pings from {input_path}")

    gates = evaluate_gates(pings)

    # Build report
    report_lines = [
        "# Stratum Dataset Audit Report",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"Input: `{input_path}`",
        f"Total pings: {len(pings):,}",
        "",
    ]

    sections = [
        ("volume", lambda: section_volume(pings)),
        ("frameworks", lambda: section_frameworks(pings)),
        ("scores", lambda: section_scores(pings)),
        ("findings", lambda: section_findings(pings)),
        ("maturity", lambda: section_maturity(pings)),
        ("duplicates", lambda: section_duplicates(pings)),
        ("coverage", lambda: section_coverage(pings)),
        ("strata", lambda: section_strata_fill(pings)),
        ("gates", lambda: section_gates(gates)),
        ("recommendations", lambda: section_recommendations(gates, pings)),
    ]

    for name, builder in sections:
        if section_filter is None or name == section_filter:
            report_lines.append(builder())

    report = "\n".join(report_lines)

    # Write report
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w") as f:
        f.write(report)

    print(f"Audit report written: {report_path}")

    # Print gate summary
    passed = sum(1 for _, _, p, _ in gates if p)
    print(f"\nQuality gates: {passed}/{len(gates)} passed")
    for gid, name, p, evidence in gates:
        status = "PASS" if p else "FAIL"
        print(f"  {gid} {name}: {status} — {evidence}")

    # Train/test split
    if do_split:
        print("\nGenerating train/test split...")
        random.seed(42)
        train, test, strata_groups = stratified_split(pings)
        write_split(train, test, config.DEFAULT_TRAIN_PATH, config.DEFAULT_TEST_PATH)
        print(f"  Train: {len(train):,} pings -> {config.DEFAULT_TRAIN_PATH}")
        print(f"  Test:  {len(test):,} pings -> {config.DEFAULT_TEST_PATH}")
        print(f"  Strata used: {len(strata_groups)}")
        for key in sorted(strata_groups):
            group = strata_groups[key]
            train_count = sum(1 for p in group if p.get("dataset_split") == "train")
            test_count = len(group) - train_count
            print(f"    {key}: {len(group)} total ({train_count} train / {test_count} test)")

    return report


def main():
    parser = argparse.ArgumentParser(
        description="Stratum Pipeline Phase 4: Dataset Audit",
    )
    parser.add_argument(
        "--input", "-i",
        help=f"Path to scan_results.jsonl (default: {config.DEFAULT_SCAN_RESULTS_PATH})",
    )
    parser.add_argument(
        "--output", "-o",
        help=f"Path for audit report (default: {config.DEFAULT_AUDIT_REPORT_PATH})",
    )
    parser.add_argument(
        "--split",
        action="store_true",
        help="Generate stratified train/test split",
    )
    parser.add_argument(
        "--section", "-s",
        choices=list(SECTION_MAP.keys()) + ["gates", "recommendations"],
        help="Run only one section",
    )

    args = parser.parse_args()

    input_path = args.input or config.DEFAULT_SCAN_RESULTS_PATH
    report_path = args.output or config.DEFAULT_AUDIT_REPORT_PATH

    if not os.path.exists(input_path):
        print(f"ERROR: Input file not found: {input_path}", file=sys.stderr)
        print("Run pipeline/scan_runner.py first.", file=sys.stderr)
        sys.exit(1)

    print("Stratum Pipeline — Phase 4: Dataset Audit")
    print(f"  Input:  {input_path}")
    print(f"  Report: {report_path}")
    if args.section:
        print(f"  Section: {args.section}")
    if args.split:
        print(f"  Split: enabled")
    print()

    run_audit(input_path, report_path, do_split=args.split, section_filter=args.section)


if __name__ == "__main__":
    main()
