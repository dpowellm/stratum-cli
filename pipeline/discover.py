#!/usr/bin/env python
"""Phase 1: Stratified GitHub repo discovery for the Stratum 50k pipeline.

Queries the GitHub Search API across 8 strata, enriches repos with metadata,
filters forks, deduplicates, and produces a frozen manifest.

Usage:
    python pipeline/discover.py --dry-run
    python pipeline/discover.py --stratum crewai --output pipeline/data/test_manifest.jsonl
    python pipeline/discover.py --output pipeline/data/repo_manifest.jsonl
    python pipeline/discover.py --resume --output pipeline/data/repo_manifest.jsonl
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

import requests

# Allow running from repo root (python pipeline/discover.py)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config


def check_rate_limit(response, is_search=False):
    """Check rate limit headers and sleep if necessary."""
    remaining = response.headers.get("X-RateLimit-Remaining")
    reset_at = response.headers.get("X-RateLimit-Reset")

    if remaining is None:
        return 0

    remaining = int(remaining)
    floor = config.SEARCH_RATE_LIMIT_FLOOR if is_search else config.RATE_LIMIT_FLOOR

    if remaining < floor and reset_at:
        reset_time = int(reset_at)
        now = int(time.time())
        sleep_seconds = max(reset_time - now + 1, 1)
        print(f"  Rate limit: {remaining} remaining, sleeping {sleep_seconds}s until reset")
        time.sleep(sleep_seconds)
        return 1

    return 0


def api_request(url, params=None, is_search=False):
    """Make a GitHub API request with retry and rate limit handling."""
    _, headers = config.require_token()

    for attempt in range(config.MAX_RETRIES):
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=30)
            check_rate_limit(resp, is_search=is_search)

            if resp.status_code == 403 and "rate limit" in resp.text.lower():
                reset_at = resp.headers.get("X-RateLimit-Reset")
                if reset_at:
                    sleep_seconds = max(int(reset_at) - int(time.time()) + 1, 1)
                    print(f"  Rate limited (403), sleeping {sleep_seconds}s")
                    time.sleep(sleep_seconds)
                    continue

            if resp.status_code == 422:
                print(f"  Validation error (422): {resp.text[:200]}")
                return None

            resp.raise_for_status()
            return resp

        except requests.exceptions.RequestException as e:
            backoff = config.RETRY_BACKOFF[min(attempt, len(config.RETRY_BACKOFF) - 1)]
            print(f"  Request error (attempt {attempt + 1}/{config.MAX_RETRIES}): {e}")
            if attempt < config.MAX_RETRIES - 1:
                print(f"  Retrying in {backoff}s...")
                time.sleep(backoff)
            else:
                print(f"  Max retries exceeded for {url}")
                return None

    return None


def search_repos(query):
    """Search GitHub for repos matching query. Returns list of search result items."""
    url = f"{config.GITHUB_API}/search/repositories"
    all_items = []
    page = 1

    while True:
        params = {
            "q": query,
            "sort": "updated",
            "per_page": config.SEARCH_PER_PAGE,
            "page": page,
        }

        resp = api_request(url, params=params, is_search=True)
        if resp is None:
            break

        data = resp.json()
        total_count = data.get("total_count", 0)
        items = data.get("items", [])

        if not items:
            break

        all_items.extend(items)

        # Check if we've hit the 1000-result cap
        if total_count > config.SEARCH_MAX_RESULTS and page == 1:
            print(f"    Query has {total_count} results (>{config.SEARCH_MAX_RESULTS} cap), will partition by date")

        # Stop at 1000 results (10 pages of 100)
        if page * config.SEARCH_PER_PAGE >= config.SEARCH_MAX_RESULTS:
            break

        if page * config.SEARCH_PER_PAGE >= total_count:
            break

        page += 1

    return all_items, total_count if all_items else 0


def search_with_partitioning(query):
    """Search with automatic date partitioning if results exceed 1000."""
    # First, try the query as-is
    items, total_count = search_repos(query)

    if total_count <= config.SEARCH_MAX_RESULTS:
        return items

    # Results exceed cap — partition by created: date ranges
    print(f"    Partitioning query into {len(config.DATE_PARTITIONS)} date ranges...")
    all_items = []

    for start_date, end_date in config.DATE_PARTITIONS:
        partitioned_query = f"{query} created:{start_date}..{end_date}"
        print(f"    Partition: created:{start_date}..{end_date}")
        partition_items, _ = search_repos(partitioned_query)
        all_items.extend(partition_items)
        print(f"      Found {len(partition_items)} repos")

    return all_items


def enrich_repo(repo_item):
    """Fetch full repo details from GET /repos/{owner}/{repo}."""
    full_name = repo_item["full_name"]
    url = f"{config.GITHUB_API}/repos/{full_name}"

    resp = api_request(url)
    if resp is None:
        # Fall back to search result data
        return {
            "full_name": full_name,
            "fork": repo_item.get("fork", False),
            "parent": None,
            "stargazers_count": repo_item.get("stargazers_count", 0),
            "forks_count": repo_item.get("forks_count", 0),
            "size": repo_item.get("size", 0),
            "pushed_at": repo_item.get("pushed_at"),
            "created_at": repo_item.get("created_at"),
            "license": repo_item.get("license"),
            "topics": repo_item.get("topics", []),
            "language": repo_item.get("language"),
            "default_branch": repo_item.get("default_branch", "main"),
            "clone_url": repo_item.get("clone_url"),
        }

    data = resp.json()
    return {
        "full_name": data["full_name"],
        "fork": data.get("fork", False),
        "parent": data.get("parent"),
        "stargazers_count": data.get("stargazers_count", 0),
        "forks_count": data.get("forks_count", 0),
        "size": data.get("size", 0),
        "pushed_at": data.get("pushed_at"),
        "created_at": data.get("created_at"),
        "license": data.get("license"),
        "topics": data.get("topics", []),
        "language": data.get("language"),
        "default_branch": data.get("default_branch", "main"),
        "clone_url": data.get("clone_url"),
    }


def filter_forks(repos):
    """Filter forks: keep the best fork per parent (most stars, most recent push)."""
    seen_parents = {}  # parent_full_name -> best repo record
    non_forks = []
    fork_repos = []

    for repo in repos:
        if not repo["fork"]:
            non_forks.append(repo)
            continue

        parent = repo.get("parent")
        if parent is None:
            non_forks.append(repo)  # can't determine parent, keep it
            continue

        parent_name = parent.get("full_name", parent) if isinstance(parent, dict) else parent

        if parent_name not in seen_parents:
            seen_parents[parent_name] = repo
        elif repo["stargazers_count"] > seen_parents[parent_name]["stargazers_count"]:
            seen_parents[parent_name] = repo
        elif (repo["stargazers_count"] == seen_parents[parent_name]["stargazers_count"]
              and repo.get("pushed_at", "") > seen_parents[parent_name].get("pushed_at", "")):
            seen_parents[parent_name] = repo

    # Combine non-forks with best-fork-per-parent
    result = non_forks + list(seen_parents.values())
    removed = len(repos) - len(result)
    return result, removed


def build_manifest_record(enriched_repo, query, stratum_name, discovered_at):
    """Build a manifest record from an enriched repo."""
    license_info = enriched_repo.get("license")
    license_id = None
    if isinstance(license_info, dict):
        license_id = license_info.get("spdx_id")

    parent = enriched_repo.get("parent")
    fork_parent = None
    if isinstance(parent, dict):
        fork_parent = parent.get("full_name")

    full_name = enriched_repo["full_name"]
    org = full_name.split("/")[0] if "/" in full_name else full_name

    return {
        "repo_full_name": full_name,
        "repo_url": enriched_repo.get("clone_url") or f"https://github.com/{full_name}.git",
        "repo_hash": None,
        "org": org,
        "github_stars": enriched_repo.get("stargazers_count", 0),
        "github_forks": enriched_repo.get("forks_count", 0),
        "github_size_kb": enriched_repo.get("size", 0),
        "last_commit_date": enriched_repo.get("pushed_at"),
        "repo_created_date": enriched_repo.get("created_at"),
        "is_fork": enriched_repo.get("fork", False),
        "fork_parent": fork_parent,
        "license": license_id,
        "github_topics": enriched_repo.get("topics", []),
        "primary_language": enriched_repo.get("language"),
        "default_branch": enriched_repo.get("default_branch", "main"),
        "discovery_query": query,
        "selection_stratum": stratum_name,
        "matched_strata": [stratum_name],
        "discovered_at": discovered_at,
        "scan_status": "pending",
    }


def deduplicate(all_records):
    """Deduplicate by repo_full_name. First stratum wins, track all in matched_strata."""
    seen = {}  # repo_full_name -> record
    dedup_count = 0

    for record in all_records:
        name = record["repo_full_name"]
        if name not in seen:
            seen[name] = record
        else:
            # Add this stratum to matched_strata
            existing = seen[name]
            if record["selection_stratum"] not in existing["matched_strata"]:
                existing["matched_strata"].append(record["selection_stratum"])
            dedup_count += 1

    return list(seen.values()), dedup_count


def load_existing_manifest(path):
    """Load repo_full_names from an existing manifest for resume support."""
    existing = set()
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        record = json.loads(line)
                        existing.add(record.get("repo_full_name"))
                    except json.JSONDecodeError:
                        continue
    return existing


def load_existing_strata(path):
    """Load strata names from discovery_log.json for resume support."""
    log_path = os.path.splitext(path)[0].replace("repo_manifest", "discovery_log") + ".json"
    if not os.path.exists(log_path):
        # Check default location
        log_path = os.path.join(os.path.dirname(path), "discovery_log.json")
    if not os.path.exists(log_path):
        return set()

    try:
        with open(log_path) as f:
            log = json.load(f)
        return set(log.get("strata_distribution", {}).keys())
    except (json.JSONDecodeError, OSError):
        return set()


def dry_run(strata):
    """Show queries and targets without making API calls."""
    print("\n=== DRY RUN — Queries to execute ===\n")
    total_target = 0

    for stratum in strata:
        print(f"Stratum: {stratum['name']} (target: {stratum['target']:,})")
        for q in stratum["queries"]:
            print(f"  Query: {q}")
        total_target += stratum["target"]
        print()

    print(f"Total strata: {len(strata)}")
    print(f"Total queries: {sum(len(s['queries']) for s in strata)}")
    print(f"Total target repos: {total_target:,}")
    print(f"Expected unique after dedup: ~{int(total_target * 0.75):,}")
    print("\nNo API calls made. Run without --dry-run to execute.")


def run_discovery(strata, output_path, resume=False):
    """Execute full discovery pipeline."""
    config.require_token()
    started_at = datetime.now(timezone.utc).isoformat()
    rate_limit_sleeps = 0
    errors = []
    strata_counts = {}
    total_search_results = 0
    total_fork_filtered = 0

    # Resume support
    completed_strata = set()
    existing_records = []
    if resume:
        completed_strata = load_existing_strata(output_path)
        if completed_strata:
            print(f"Resuming: skipping {len(completed_strata)} completed strata: {completed_strata}")
        # Load existing records for dedup
        existing_names = load_existing_manifest(output_path)
        if existing_names:
            print(f"Resuming: {len(existing_names)} repos already in manifest")

    all_records = list(existing_records)

    for stratum in strata:
        if stratum["name"] in completed_strata:
            print(f"\nSkipping completed stratum: {stratum['name']}")
            continue

        print(f"\n{'='*60}")
        print(f"Stratum: {stratum['name']} (target: {stratum['target']:,})")
        print(f"{'='*60}")

        stratum_repos = []

        for query in stratum["queries"]:
            print(f"\n  Query: {query}")
            items = search_with_partitioning(query)
            print(f"  Found {len(items)} search results")
            total_search_results += len(items)

            # Enrich each repo
            print(f"  Enriching {len(items)} repos...")
            enriched = []
            for i, item in enumerate(items):
                if (i + 1) % 50 == 0:
                    print(f"    Enriched {i + 1}/{len(items)}...")
                repo_data = enrich_repo(item)
                enriched.append(repo_data)

            stratum_repos.extend(enriched)

        # Deduplicate within stratum by full_name
        seen_in_stratum = {}
        unique_repos = []
        for repo in stratum_repos:
            name = repo["full_name"]
            if name not in seen_in_stratum:
                seen_in_stratum[name] = repo
                unique_repos.append(repo)
        print(f"\n  Unique repos in stratum (pre-fork-filter): {len(unique_repos)}")

        # Fork filter
        filtered, fork_removed = filter_forks(unique_repos)
        total_fork_filtered += fork_removed
        print(f"  After fork filter: {len(filtered)} (removed {fork_removed} forks)")

        # Build manifest records
        discovered_at = datetime.now(timezone.utc).isoformat()
        for repo in filtered:
            # Find which query discovered this repo (use first matching)
            record = build_manifest_record(
                repo,
                query=stratum["queries"][0],  # attribute to first query
                stratum_name=stratum["name"],
                discovered_at=discovered_at,
            )
            all_records.append(record)

        strata_counts[stratum["name"]] = len(filtered)
        print(f"  Stratum '{stratum['name']}' complete: {len(filtered)} repos")

    # Cross-strata deduplication
    print(f"\n{'='*60}")
    print("Cross-strata deduplication...")
    final_records, dedup_removed = deduplicate(all_records)
    print(f"  Before dedup: {len(all_records)}")
    print(f"  After dedup: {len(final_records)} (removed {dedup_removed} duplicates)")

    # Write manifest
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        for record in final_records:
            f.write(json.dumps(record) + "\n")
    print(f"\nManifest written: {output_path} ({len(final_records)} repos)")

    # Write discovery log
    completed_at = datetime.now(timezone.utc).isoformat()
    log = {
        "run_id": f"discovery_{datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
        "started_at": started_at,
        "completed_at": completed_at,
        "total_search_results": total_search_results,
        "after_fork_filter": total_search_results - total_fork_filtered,
        "after_dedup": len(final_records),
        "strata_distribution": strata_counts,
        "fork_filter_removed": total_fork_filtered,
        "dedup_removed": dedup_removed,
        "rate_limit_sleeps": rate_limit_sleeps,
        "errors": errors,
    }

    log_path = os.path.join(os.path.dirname(output_path), "discovery_log.json")
    with open(log_path, "w") as f:
        json.dump(log, f, indent=2)
    print(f"Discovery log written: {log_path}")

    return final_records, log


def main():
    parser = argparse.ArgumentParser(
        description="Stratum Pipeline Phase 1: Repo Discovery",
        epilog="Requires GITHUB_TOKEN environment variable.",
    )
    parser.add_argument(
        "--output", "-o",
        help="Output path for repo_manifest.jsonl",
    )
    parser.add_argument(
        "--stratum", "-s",
        help="Run a single stratum only (for testing)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show queries and targets without making API calls",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Skip already-discovered strata (reads existing discovery_log.json)",
    )

    args = parser.parse_args()

    strata = list(config.STRATA)

    if args.stratum:
        strata = [s for s in strata if s["name"] == args.stratum]
        if not strata:
            valid = [s["name"] for s in config.STRATA]
            print(f"Unknown stratum '{args.stratum}'. Valid: {valid}")
            sys.exit(1)

    if args.dry_run:
        dry_run(strata)
        return

    # Real run — require token before any API calls
    config.require_token()
    output_path = args.output or config.DEFAULT_MANIFEST_PATH

    print(f"Stratum Pipeline — Phase 1: Discovery")
    print(f"Strata: {len(strata)}")
    print(f"Output: {output_path}")
    if args.resume:
        print("Mode: RESUME")
    print()

    records, log = run_discovery(strata, output_path, resume=args.resume)

    print(f"\n{'='*60}")
    print(f"DISCOVERY COMPLETE")
    print(f"{'='*60}")
    print(f"  Total repos: {len(records):,}")
    print(f"  Search results: {log['total_search_results']:,}")
    print(f"  Fork filtered: {log['fork_filter_removed']:,}")
    print(f"  Dedup removed: {log['dedup_removed']:,}")
    print(f"  Rate limit sleeps: {log['rate_limit_sleeps']}")
    print(f"\nStrata distribution:")
    for name, count in log["strata_distribution"].items():
        print(f"  {name}: {count:,}")


if __name__ == "__main__":
    main()
