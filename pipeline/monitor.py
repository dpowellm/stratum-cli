#!/usr/bin/env python
"""Phase 3: Real-time scan monitor for the Stratum 50k pipeline.

Tails scan_results.jsonl and prints a dashboard every 30 seconds.
Run in a separate terminal while scan_runner.py is active.

Usage:
    python pipeline/monitor.py           # live watch (refreshes every 30s)
    python pipeline/monitor.py --once    # one-shot snapshot
"""

import argparse
import json
import os
import sys
import time
from collections import Counter
from datetime import datetime, timezone

# Allow running from repo root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config

REFRESH_INTERVAL = 30  # seconds


def load_results(path):
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


def load_run_log(path):
    """Load the pipeline run log."""
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def render_dashboard(results_path, quarantine_path, log_path):
    """Build and print the dashboard."""
    pings = load_results(results_path)
    quarantine = load_results(quarantine_path)
    run_log = load_run_log(log_path)

    total = len(pings)
    q_count = len(quarantine)

    # Status breakdown
    status_counts = Counter()
    framework_counts = Counter()
    score_buckets = {"0-20": 0, "21-40": 0, "41-60": 0, "61-80": 0, "81-100": 0}
    durations = []
    last_error = None

    for ping in pings:
        status = ping.get("scan_status", "unknown")
        status_counts[status] += 1

        # Frameworks
        for fw in ping.get("frameworks", []):
            framework_counts[fw] += 1

        # Score buckets
        score = ping.get("risk_score")
        if score is not None and isinstance(score, (int, float)):
            if score <= 20:
                score_buckets["0-20"] += 1
            elif score <= 40:
                score_buckets["21-40"] += 1
            elif score <= 60:
                score_buckets["41-60"] += 1
            elif score <= 80:
                score_buckets["61-80"] += 1
            else:
                score_buckets["81-100"] += 1

        # Duration
        dur = ping.get("scan_duration_ms")
        if dur and isinstance(dur, (int, float)) and dur > 0:
            durations.append(dur)

        # Track last error
        if status == "failed":
            reason = ping.get("failure_reason", "unknown")
            name = ping.get("repo_full_name", "?")
            last_error = f"{name}: {reason}"

    # Compute averages and ETA
    avg_duration_ms = sum(durations) / len(durations) if durations else 0
    avg_duration_s = avg_duration_ms / 1000

    manifest_total = run_log.get("manifest_repo_count", "?") if run_log else "?"
    remaining = 0
    eta_str = "?"
    if run_log and isinstance(manifest_total, int):
        scanned = total + q_count
        remaining = max(manifest_total - scanned, 0)
        if avg_duration_s > 0 and scanned > 0:
            # Factor in parallelism from run log
            elapsed = None
            if run_log.get("started_at"):
                try:
                    start = datetime.fromisoformat(run_log["started_at"])
                    elapsed_s = (datetime.now(timezone.utc) - start).total_seconds()
                    throughput = scanned / elapsed_s if elapsed_s > 0 else 0
                    if throughput > 0:
                        eta_seconds = remaining / throughput
                        eta_h = int(eta_seconds // 3600)
                        eta_m = int((eta_seconds % 3600) // 60)
                        eta_str = f"{eta_h}h {eta_m}m"
                except (ValueError, TypeError):
                    pass

    # Progress
    if isinstance(manifest_total, int) and manifest_total > 0:
        pct = ((total + q_count) / manifest_total) * 100
        progress_str = f"{total + q_count} / {manifest_total} ({pct:.1f}%)"
    else:
        progress_str = f"{total + q_count}"

    # Render
    now = datetime.now().strftime("%H:%M:%S")
    lines = [
        "",
        f"{'='*60}",
        f"  STRATUM SCAN MONITOR  [{now}]",
        f"{'='*60}",
        "",
        f"  Progress:    {progress_str}",
        f"  Remaining:   {remaining}    ETA: {eta_str}",
        "",
        f"  --- Status Breakdown ---",
        f"  Success:     {status_counts.get('success', 0)}",
        f"  Partial:     {status_counts.get('partial', 0)}",
        f"  Failed:      {status_counts.get('failed', 0)}",
        f"  Empty:       {status_counts.get('empty', 0)}",
        f"  Quarantined: {q_count}",
        "",
        f"  --- Score Distribution ---",
    ]
    for bucket, count in score_buckets.items():
        bar = "#" * min(count, 40)
        lines.append(f"  {bucket:>6}: {count:>5}  {bar}")

    lines.append("")
    lines.append(f"  --- Frameworks (top 10) ---")
    for fw, count in framework_counts.most_common(10):
        lines.append(f"  {fw:<20} {count:>5}")

    lines.append("")
    lines.append(f"  Avg scan duration: {avg_duration_s:.1f}s")

    if last_error:
        lines.append(f"  Last error: {last_error}")

    lines.append(f"{'='*60}")
    lines.append("")

    print("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(
        description="Stratum Pipeline Phase 3: Scan Monitor",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Print dashboard once and exit (no live watch)",
    )

    args = parser.parse_args()

    results_path = config.DEFAULT_SCAN_RESULTS_PATH
    quarantine_path = config.DEFAULT_QUARANTINE_PATH
    log_path = config.DEFAULT_PIPELINE_LOG_PATH

    if args.once:
        render_dashboard(results_path, quarantine_path, log_path)
        return

    print("Stratum scan monitor — Ctrl+C to stop")
    print(f"Watching: {results_path}")
    print()

    try:
        while True:
            # Clear screen (works on both Windows and Unix)
            os.system("cls" if os.name == "nt" else "clear")
            render_dashboard(results_path, quarantine_path, log_path)
            time.sleep(REFRESH_INTERVAL)
    except KeyboardInterrupt:
        print("\nMonitor stopped.")


if __name__ == "__main__":
    main()
