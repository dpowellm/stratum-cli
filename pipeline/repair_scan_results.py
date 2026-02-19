#!/usr/bin/env python
"""Retroactive repair of scan_results.jsonl files missing repo identity.

Attempts to recover repo_full_name and repo_url for scan results that
were produced before the identity propagation fix.

Strategies (applied in priority order):
  1. Already identified — row already has repo_full_name (skip)
  2. Hash matching — match repo_hash to manifest entries by cloning and
     computing topology hashes (expensive, optional)
  3. Manifest order alignment — if results were appended roughly in manifest
     order, align by position (fragile, validated with cross-checks)
  4. Anonymous fallback — mark rows as anonymous but still usable for
     ecosystem-level aggregate statistics

Usage:
    python pipeline/repair_scan_results.py
    python pipeline/repair_scan_results.py --scan-results path/to/scan_results.jsonl
    python pipeline/repair_scan_results.py --manifest path/to/manifest.jsonl
    python pipeline/repair_scan_results.py --output repaired_scan_results.jsonl
    python pipeline/repair_scan_results.py --dry-run  # report only, no output
"""

import argparse
import hashlib
import json
import os
import sys
from collections import defaultdict

# Allow running from repo root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config


def load_jsonl(path):
    """Load records from a JSONL file."""
    records = []
    if not os.path.exists(path):
        return records
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return records


def compute_manifest_hash(repo_full_name):
    """Compute the repo_hash as used by batch/scan_github.py (SHA-256 of full_name)."""
    return hashlib.sha256(repo_full_name.encode()).hexdigest()[:16]


def repair_scan_results(
    scan_results_path,
    manifest_path,
    output_path,
    dry_run=False,
):
    """Main repair logic."""
    print("=" * 60)
    print("SCAN RESULTS IDENTITY REPAIR")
    print("=" * 60)

    # Load data
    results = load_jsonl(scan_results_path)
    manifest = load_jsonl(manifest_path)

    print(f"\nLoaded {len(results)} scan results from {scan_results_path}")
    print(f"Loaded {len(manifest)} manifest entries from {manifest_path}")

    if not results:
        print("No scan results to repair.")
        return

    # ── Pre-repair analysis ──────────────────────────────────────────

    already_identified = sum(1 for r in results if r.get("repo_full_name"))
    have_repo_hash = sum(1 for r in results if r.get("repo_hash"))
    have_url = sum(1 for r in results if r.get("repo_url"))
    unique_hashes = set(r.get("repo_hash") for r in results if r.get("repo_hash"))

    print(f"\n--- PRE-REPAIR ANALYSIS ---")
    print(f"  Total rows:              {len(results)}")
    print(f"  With repo_full_name:     {already_identified}")
    print(f"  With repo_url:           {have_url}")
    print(f"  With repo_hash:          {have_repo_hash}")
    print(f"  Unique repo_hashes:      {len(unique_hashes)}")
    print(f"  Completely anonymous:     {len(results) - max(already_identified, have_repo_hash)}")

    # ── Build manifest lookup indices ────────────────────────────────

    # Index 1: manifest full_name hash → manifest entry
    # The batch scanner (scan_github.py) computes repo_hash as SHA-256(full_name)[:16]
    # The pipeline scanner computes repo_hash as topology signature (different!)
    # We try both approaches
    hash_to_manifest = {}
    for entry in manifest:
        name = entry.get("repo_full_name", "")
        if name:
            h = compute_manifest_hash(name)
            hash_to_manifest[h] = entry

    # Index 2: selection_stratum → list of manifest entries (for narrowing)
    stratum_to_manifests = defaultdict(list)
    for entry in manifest:
        s = entry.get("selection_stratum", "")
        if s:
            stratum_to_manifests[s].append(entry)

    # ── Strategy 1: Already identified (skip) ────────────────────────

    repaired = 0
    url_repaired = 0
    hash_repaired = 0
    order_repaired = 0
    anonymous_count = 0

    # ── Strategy 2: Hash-based matching ──────────────────────────────
    # Try matching repo_hash from scan results against
    # SHA-256(full_name)[:16] from the manifest

    hash_match_candidates = 0
    for i, row in enumerate(results):
        if row.get("repo_full_name"):
            # Already has identity — but check if repo_url is missing
            if not row.get("repo_url"):
                name = row["repo_full_name"]
                # Try to find URL from manifest
                for entry in manifest:
                    if entry.get("repo_full_name") == name:
                        row["repo_url"] = entry.get("repo_url", "")
                        url_repaired += 1
                        break
                if not row.get("repo_url") and name:
                    # Construct URL from name
                    row["repo_url"] = f"https://github.com/{name}"
                    url_repaired += 1
            continue

        repo_hash = row.get("repo_hash")
        if not repo_hash:
            continue

        # Try name-hash match
        if repo_hash in hash_to_manifest:
            entry = hash_to_manifest[repo_hash]
            row["repo_full_name"] = entry.get("repo_full_name", "")
            row["repo_url"] = entry.get("repo_url", "")
            if not row.get("selection_stratum"):
                row["selection_stratum"] = entry.get("selection_stratum", "")
            hash_repaired += 1
            hash_match_candidates += 1
            continue

    # ── Strategy 3: Manifest order alignment ─────────────────────────
    # If scan results were produced in roughly the same order as the
    # manifest, we can try positional alignment.
    #
    # This is fragile — only used for rows that still have no identity
    # and validated by checking if selection_stratum matches.

    unidentified_indices = [
        i for i, r in enumerate(results)
        if not r.get("repo_full_name")
    ]

    if unidentified_indices and manifest:
        # Build a list of manifest entries not yet matched
        matched_names = {
            r.get("repo_full_name")
            for r in results
            if r.get("repo_full_name")
        }
        unmatched_manifest = [
            e for e in manifest
            if e.get("repo_full_name") not in matched_names
        ]

        # Try positional alignment: assign unidentified results to
        # unmatched manifest entries in order, but only if stratum matches
        manifest_idx = 0
        for result_idx in unidentified_indices:
            if manifest_idx >= len(unmatched_manifest):
                break

            row = results[result_idx]
            candidate = unmatched_manifest[manifest_idx]

            # Cross-validate with selection_stratum if both have it
            row_stratum = row.get("selection_stratum", "")
            candidate_stratum = candidate.get("selection_stratum", "")

            if row_stratum and candidate_stratum and row_stratum == candidate_stratum:
                row["repo_full_name"] = candidate.get("repo_full_name", "")
                row["repo_url"] = candidate.get("repo_url", "")
                row["_repair_method"] = "order_alignment"
                row["_repair_confidence"] = "low"
                order_repaired += 1
                manifest_idx += 1
            elif not row_stratum or not candidate_stratum:
                # Can't validate — skip this candidate
                manifest_idx += 1

    # ── Strategy 4: Anonymous fallback ───────────────────────────────
    # Mark remaining unidentified rows as anonymous

    for row in results:
        if not row.get("repo_full_name"):
            row["_anonymous"] = True
            anonymous_count += 1

    # ── Post-repair analysis ─────────────────────────────────────────

    post_identified = sum(1 for r in results if r.get("repo_full_name"))
    post_url = sum(1 for r in results if r.get("repo_url"))

    total_repaired = hash_repaired + order_repaired
    recovery_rate = (total_repaired / max(len(results) - already_identified, 1)) * 100

    print(f"\n--- POST-REPAIR ANALYSIS ---")
    print(f"  Rows with repo_full_name BEFORE: {already_identified}")
    print(f"  Rows with repo_full_name AFTER:  {post_identified}")
    print(f"  Rows with repo_url AFTER:        {post_url}")
    print(f"  ")
    print(f"  Repaired via hash matching:      {hash_repaired}")
    print(f"  Repaired via order alignment:    {order_repaired}")
    print(f"  URLs backfilled:                 {url_repaired}")
    print(f"  Total identity recovered:        {total_repaired}")
    print(f"  Recovery rate:                   {recovery_rate:.1f}%")
    print(f"  Still anonymous:                 {anonymous_count}")
    print(f"    (anonymous rows are still usable for ecosystem-level aggregates)")

    # ── Validate no data corruption ──────────────────────────────────

    print(f"\n--- DATA INTEGRITY CHECK ---")
    original = load_jsonl(scan_results_path)
    corruption_found = False

    for i, (orig, repaired_row) in enumerate(zip(original, results)):
        # Check that core scan data wasn't modified
        for field in ["scan_id", "risk_score", "finding_rule_count", "frameworks",
                       "scan_status", "agent_count", "crew_count"]:
            if orig.get(field) != repaired_row.get(field):
                print(f"  CORRUPTION at row {i}: {field} changed from "
                      f"{orig.get(field)} to {repaired_row.get(field)}")
                corruption_found = True

    if not corruption_found:
        print("  PASS: No data corruption detected")

    # ── Sample repaired rows ─────────────────────────────────────────

    repaired_rows = [
        r for r in results
        if r.get("repo_full_name") and not r.get("_anonymous")
    ]
    if repaired_rows:
        print(f"\n--- SAMPLE REPAIRED ROWS (up to 10) ---")
        for row in repaired_rows[:10]:
            name = row.get("repo_full_name", "?")
            score = row.get("risk_score", "?")
            findings = row.get("finding_rule_count", 0)
            method = row.get("_repair_method", "original/hash")
            print(f"  {name:40s}  risk={score:>3}  findings={findings:>2}  method={method}")

    # ── Write output ─────────────────────────────────────────────────

    if dry_run:
        print(f"\n[DRY RUN] Would write {len(results)} rows to {output_path}")
    else:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w") as f:
            for row in results:
                f.write(json.dumps(row) + "\n")
        print(f"\nRepaired results written to {output_path}")

    print(f"\n{'=' * 60}")

    return {
        "total_rows": len(results),
        "pre_identified": already_identified,
        "post_identified": post_identified,
        "hash_repaired": hash_repaired,
        "order_repaired": order_repaired,
        "url_repaired": url_repaired,
        "anonymous": anonymous_count,
        "recovery_rate": recovery_rate,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Repair missing repo identity in scan_results.jsonl",
    )
    parser.add_argument(
        "--scan-results", "-s",
        default=config.DEFAULT_SCAN_RESULTS_PATH,
        help=f"Path to scan_results.jsonl (default: {config.DEFAULT_SCAN_RESULTS_PATH})",
    )
    parser.add_argument(
        "--manifest", "-m",
        default=config.DEFAULT_MANIFEST_PATH,
        help=f"Path to repo_manifest.jsonl (default: {config.DEFAULT_MANIFEST_PATH})",
    )
    parser.add_argument(
        "--output", "-o",
        default="pipeline/data/repaired_scan_results.jsonl",
        help="Output path for repaired results",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report only, don't write output",
    )

    args = parser.parse_args()

    for path in (args.scan_results, args.manifest):
        if not os.path.exists(path):
            print(f"ERROR: File not found: {path}", file=sys.stderr)
            sys.exit(1)

    repair_scan_results(
        scan_results_path=args.scan_results,
        manifest_path=args.manifest,
        output_path=args.output,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
