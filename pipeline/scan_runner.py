#!/usr/bin/env python
"""Phase 2: Parallel scan runner for the Stratum 50k pipeline.

Reads a repo manifest, clones each repo, runs 'stratum scan', validates the
resulting ping, and writes results to scan_results.jsonl (or quarantine.jsonl
for invalid pings). Uses multiprocessing for parallel workers.

Usage:
    python pipeline/scan_runner.py                          # full run
    python pipeline/scan_runner.py --limit 16               # first N repos
    python pipeline/scan_runner.py --resume                 # skip already-scanned
    python pipeline/scan_runner.py --workers 5              # override worker count
    python pipeline/scan_runner.py --manifest path/to.jsonl # override manifest
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone

# Allow running from repo root (python pipeline/scan_runner.py)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config
from validation import failure_ping, validate_ping


def scan_single_repo(repo_record):
    """Clone, scan, and return a ping dict for one repo.

    This function runs in a worker process. It must be self-contained —
    no shared mutable state.
    """
    repo_name = repo_record.get("repo_full_name", "unknown")
    clone_url = repo_record.get("repo_url") or f"https://github.com/{repo_name}.git"

    # Build a per-worker temp directory
    worker_dir = os.path.join(
        tempfile.gettempdir(),
        f"stratum-worker-{os.getpid()}",
        repo_name.replace("/", "_"),
    )

    try:
        # --- Clone ---
        ping = _clone_repo(repo_record, clone_url, worker_dir)
        if ping is not None:
            return ping  # clone failed, return failure ping

        # --- Scan ---
        ping = _run_scan(repo_record, worker_dir)
        return ping

    finally:
        # Always clean up the clone directory
        if os.path.exists(worker_dir):
            shutil.rmtree(worker_dir, ignore_errors=True)


def _clone_repo(repo_record, clone_url, dest_dir):
    """Attempt git clone with retries. Returns failure_ping on error, None on success."""
    os.makedirs(os.path.dirname(dest_dir), exist_ok=True)

    for attempt in range(config.CLONE_MAX_RETRIES):
        # Clean up any partial clone from a previous attempt
        if os.path.exists(dest_dir):
            shutil.rmtree(dest_dir, ignore_errors=True)

        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", "--quiet", clone_url, dest_dir],
                capture_output=True,
                text=True,
                timeout=config.CLONE_TIMEOUT_SECONDS,
            )

            if result.returncode == 0:
                return None  # success

            stderr = result.stderr.strip()

            # Check for rate limiting (HTTP 429)
            if "429" in stderr or "rate limit" in stderr.lower():
                if attempt < config.CLONE_MAX_RETRIES - 1:
                    backoff = config.CLONE_RETRY_BACKOFF[attempt]
                    time.sleep(backoff)
                    continue
                return failure_ping(repo_record, "clone_rate_limited", stderr)

            # Any other clone error (404, auth, etc.)
            return failure_ping(repo_record, "clone_error", stderr)

        except subprocess.TimeoutExpired:
            return failure_ping(repo_record, "clone_timeout")

        except Exception as e:
            return failure_ping(repo_record, "clone_error", str(e))

    return failure_ping(repo_record, "clone_rate_limited")


def _run_scan(repo_record, clone_dir):
    """Run stratum scan on a cloned repo. Returns a ping dict."""
    repo_name = repo_record.get("repo_full_name", "")
    repo_url = repo_record.get("repo_url", "")

    try:
        cmd = ["stratum", "scan", clone_dir, "--json", "--no-telemetry"]
        # Pass identity flags so the scanner embeds them in the JSON output
        if repo_name:
            cmd.extend(["--repo-name", repo_name])
        if repo_url:
            cmd.extend(["--repo-url", repo_url])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.SCAN_TIMEOUT_SECONDS,
        )

        if result.returncode != 0:
            return failure_ping(repo_record, "parse_crash", result.stderr)

        # Parse JSON output
        stdout = result.stdout.strip()
        if not stdout:
            return failure_ping(repo_record, "invalid_json", "empty stdout")

        try:
            ping = json.loads(stdout)
        except json.JSONDecodeError as e:
            return failure_ping(repo_record, "invalid_json", str(e))

        # Belt-and-suspenders: backfill identity from manifest metadata.
        # For selection_stratum: prefer scanner's computed value (from framework
        # detection), fall back to manifest if scanner didn't set one.
        manifest_stratum = repo_record.get("selection_stratum")
        if not ping.get("selection_stratum") and manifest_stratum:
            ping["selection_stratum"] = manifest_stratum
        if repo_name:
            ping["repo_full_name"] = repo_name
        elif not ping.get("repo_full_name"):
            ping["repo_full_name"] = repo_record.get("repo_full_name")
        if repo_url:
            ping["repo_url"] = repo_url
        elif not ping.get("repo_url"):
            ping["repo_url"] = repo_record.get("repo_url")

        return ping

    except subprocess.TimeoutExpired:
        return failure_ping(repo_record, "parse_timeout")

    except FileNotFoundError:
        return failure_ping(
            repo_record, "parse_crash",
            "stratum command not found — is stratum-cli installed?",
        )

    except Exception as e:
        return failure_ping(repo_record, "parse_crash", str(e))


# ---------------------------------------------------------------------------
# Coordinator (main process)
# ---------------------------------------------------------------------------

def load_manifest(path):
    """Load repo records from a JSONL manifest."""
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return records


def load_skip_set(results_path, quarantine_path):
    """Load repo_full_name values from existing results and quarantine files."""
    skip = set()
    for path in (results_path, quarantine_path):
        if not os.path.exists(path):
            continue
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        record = json.loads(line)
                        name = record.get("repo_full_name")
                        if name:
                            skip.add(name)
                    except json.JSONDecodeError:
                        continue
    return skip


def write_pipeline_log(log_path, log_data):
    """Write/update the pipeline run log."""
    log_data["last_updated"] = datetime.now(timezone.utc).isoformat()
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, "w") as f:
        json.dump(log_data, f, indent=2)


def run_scan_pipeline(manifest_path, results_path, quarantine_path,
                      log_path, workers, limit=None, resume=False):
    """Main coordinator: dispatch repos to workers, collect and write results."""
    # Load manifest
    all_records = load_manifest(manifest_path)
    print(f"Manifest loaded: {len(all_records)} repos from {manifest_path}")

    # Resume support: skip already-scanned repos
    skip_set = set()
    if resume:
        skip_set = load_skip_set(results_path, quarantine_path)
        if skip_set:
            print(f"Resume: skipping {len(skip_set)} already-scanned repos")

    # Filter to work queue
    work_queue = [r for r in all_records if r.get("repo_full_name") not in skip_set]

    if limit is not None:
        work_queue = work_queue[:limit]

    if not work_queue:
        print("Nothing to scan — work queue is empty.")
        return

    print(f"Work queue: {len(work_queue)} repos, {workers} workers")
    print()

    # Initialize run log
    started_at = datetime.now(timezone.utc).isoformat()
    run_log = {
        "run_id": f"scan_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
        "started_at": started_at,
        "completed_at": None,
        "manifest_repo_count": len(all_records),
        "work_queue_size": len(work_queue),
        "success": 0,
        "partial": 0,
        "failed": 0,
        "empty": 0,
        "quarantined": 0,
        "rate_limit_hits": 0,
        "last_updated": started_at,
    }

    # Ensure output directory exists
    os.makedirs(os.path.dirname(results_path), exist_ok=True)

    # Open output files in append mode
    results_file = open(results_path, "a")
    quarantine_file = open(quarantine_path, "a")

    completed = 0

    try:
        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(scan_single_repo, record): record
                for record in work_queue
            }

            for future in as_completed(futures):
                repo_record = futures[future]
                repo_name = repo_record.get("repo_full_name", "unknown")

                try:
                    ping = future.result()
                except Exception as e:
                    ping = failure_ping(repo_record, "worker_exception", str(e))

                # Classify result
                status = ping.get("scan_status", "unknown")
                failure_reason = ping.get("failure_reason")

                if failure_reason and "rate_limit" in failure_reason:
                    run_log["rate_limit_hits"] += 1

                if status == "failed":
                    run_log["failed"] += 1
                    status_tag = f"FAILED ({failure_reason})"
                elif status == "empty":
                    run_log["empty"] += 1
                    status_tag = "EMPTY"
                elif status == "partial":
                    run_log["partial"] += 1
                    status_tag = "PARTIAL"
                else:
                    run_log["success"] += 1
                    status_tag = "OK"

                # Validate non-failure pings
                if status not in ("failed", "empty"):
                    errors = validate_ping(ping)
                    if errors:
                        run_log["quarantined"] += 1
                        run_log["success"] -= 1  # undo the success count
                        quarantine_record = {
                            "ping": ping,
                            "validation_errors": errors,
                            "quarantined_at": datetime.now(timezone.utc).isoformat(),
                        }
                        quarantine_file.write(json.dumps(quarantine_record) + "\n")
                        quarantine_file.flush()
                        status_tag = f"QUARANTINED ({len(errors)} errors)"
                    else:
                        results_file.write(json.dumps(ping) + "\n")
                        results_file.flush()
                else:
                    # Failed/empty pings go to results (they're valid failure records)
                    results_file.write(json.dumps(ping) + "\n")
                    results_file.flush()

                completed += 1
                pct = (completed / len(work_queue)) * 100
                print(f"  [{completed}/{len(work_queue)} {pct:.0f}%] {repo_name} — {status_tag}")

                # Update run log periodically
                if completed % config.LOG_INTERVAL == 0 or completed == len(work_queue):
                    write_pipeline_log(log_path, run_log)

    finally:
        results_file.close()
        quarantine_file.close()

    # Final log update
    run_log["completed_at"] = datetime.now(timezone.utc).isoformat()
    write_pipeline_log(log_path, run_log)

    # Summary
    total = run_log["success"] + run_log["partial"] + run_log["failed"] + run_log["empty"]
    print(f"\n{'='*60}")
    print("SCAN COMPLETE")
    print(f"{'='*60}")
    print(f"  Total scanned: {total}")
    print(f"  Success:       {run_log['success']}")
    print(f"  Partial:       {run_log['partial']}")
    print(f"  Failed:        {run_log['failed']}")
    print(f"  Empty:         {run_log['empty']}")
    print(f"  Quarantined:   {run_log['quarantined']}")
    print(f"  Rate limits:   {run_log['rate_limit_hits']}")
    print(f"\nResults:    {results_path}")
    print(f"Quarantine: {quarantine_path}")
    print(f"Run log:    {log_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Stratum Pipeline Phase 2: Scan Runner",
    )
    parser.add_argument(
        "--manifest", "-m",
        help=f"Path to repo manifest (default: {config.DEFAULT_MANIFEST_PATH})",
    )
    parser.add_argument(
        "--limit", "-l",
        type=int,
        help="Scan only the first N repos (for testing)",
    )
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=config.DEFAULT_WORKERS,
        help=f"Number of parallel workers (default: {config.DEFAULT_WORKERS})",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Skip repos already in scan_results.jsonl or quarantine.jsonl",
    )

    args = parser.parse_args()

    manifest_path = args.manifest or config.DEFAULT_MANIFEST_PATH
    if not os.path.exists(manifest_path):
        print(f"ERROR: Manifest not found: {manifest_path}", file=sys.stderr)
        print("Run pipeline/discover.py first to generate the manifest.", file=sys.stderr)
        sys.exit(1)

    print("Stratum Pipeline — Phase 2: Scan Runner")
    print(f"  Manifest: {manifest_path}")
    print(f"  Workers:  {args.workers}")
    if args.limit:
        print(f"  Limit:    {args.limit}")
    if args.resume:
        print(f"  Mode:     RESUME")
    print()

    run_scan_pipeline(
        manifest_path=manifest_path,
        results_path=config.DEFAULT_SCAN_RESULTS_PATH,
        quarantine_path=config.DEFAULT_QUARANTINE_PATH,
        log_path=config.DEFAULT_PIPELINE_LOG_PATH,
        workers=args.workers,
        limit=args.limit,
        resume=args.resume,
    )


if __name__ == "__main__":
    main()
