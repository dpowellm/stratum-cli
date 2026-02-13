"""GitHub batch scan pipeline.

Scans public agent projects from GitHub, builds ScanProfiles and RepoContexts,
and stores them as JSON for the intelligence database.

Usage:
    python -m stratum.batch.scan_github --query "crewai" --max-repos 100 --output ./scans/
    python -m stratum.batch.scan_github --all --max-repos 10000 --output ./scans/
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile

logger = logging.getLogger(__name__)

SEED_ORGS = [
    "crewAIInc",
    "langchain-ai",
    "microsoft",  # autogen
    "run-llama",
]

EXAMPLE_KEYWORDS = {
    "example", "demo", "tutorial", "starter", "template",
    "quickstart", "sample", "boilerplate", "playground",
}

SEARCH_QUERIES = [
    # Framework-specific
    "crewai",
    "crewai crew",
    "langchain agent tool",
    "langgraph",
    "autogen agent",
    "langchain ReAct agent",
    # Pattern-specific
    "AI agent tool use",
    "multi agent system python",
    "agent orchestration",
    "agentic workflow",
    # Tool-specific (high-risk patterns)
    "GmailToolkit langchain",
    "slack agent tool",
    "agent file management",
    "agent web scraper",
]


def scan_github(
    output_dir: str,
    max_repos: int = 100,
    queries: list[str] | None = None,
) -> None:
    """Main batch scan loop.

    Clones repos, scans with stratum, builds profiles, saves to output_dir.
    """
    from stratum.scanner import scan
    from stratum.telemetry.profile import build_scan_profile
    from stratum.batch.repo_context import build_repo_context

    os.makedirs(output_dir, exist_ok=True)
    scanned_hashes: set[str] = _load_scanned_hashes(output_dir)
    queries = queries or SEARCH_QUERIES
    total_scanned = 0

    for query in queries:
        if total_scanned >= max_repos:
            break

        logger.info("Searching: %s", query)
        repos = _github_search(query, language="Python", max_results=min(100, max_repos - total_scanned))

        for repo in repos:
            if total_scanned >= max_repos:
                break

            repo_hash = hashlib.sha256(
                repo.get("full_name", "").encode()
            ).hexdigest()[:16]

            if repo_hash in scanned_hashes:
                logger.debug("Skipping (already scanned): %s", repo.get("full_name"))
                continue

            clone_dir = None
            try:
                # Clone
                clone_dir = _clone_repo(repo)
                if clone_dir is None:
                    continue

                # Scan
                logger.info("Scanning: %s", repo.get("full_name"))
                result = scan(clone_dir)

                # Build profiles
                scan_profile = build_scan_profile(result)
                repo_context = build_repo_context(repo, clone_dir)

                # Save
                entry = {
                    "scan_profile": dataclasses.asdict(scan_profile),
                    "repo_context": dataclasses.asdict(repo_context),
                    "is_example": _is_example_repo(repo, result),
                }
                entry_path = os.path.join(output_dir, f"{repo_hash}.json")
                with open(entry_path, "w", encoding="utf-8") as f:
                    json.dump(entry, f, indent=2)

                scanned_hashes.add(repo_hash)
                total_scanned += 1
                logger.info(
                    "Scanned %d/%d: %s (risk=%d)",
                    total_scanned, max_repos,
                    repo.get("full_name"), result.risk_score,
                )

            except Exception as e:
                logger.warning("Failed to scan %s: %s", repo.get("full_name"), e)
            finally:
                if clone_dir and os.path.exists(clone_dir):
                    shutil.rmtree(clone_dir, ignore_errors=True)

    logger.info("Batch scan complete: %d repos scanned", total_scanned)


def _github_search(
    query: str, language: str = "Python", max_results: int = 100
) -> list[dict]:
    """Search GitHub for repositories matching a query.

    Requires `gh` CLI to be installed and authenticated.
    """
    try:
        cmd = [
            "gh", "api", "search/repositories",
            "--method", "GET",
            "-f", f"q={query} language:{language}",
            "-f", "sort=stars",
            "-f", "order=desc",
            "-f", f"per_page={min(max_results, 100)}",
        ]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            logger.warning("GitHub search failed: %s", result.stderr)
            return []
        data = json.loads(result.stdout)
        return data.get("items", [])
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        logger.warning("GitHub search error: %s", e)
        return []


def _clone_repo(repo: dict) -> str | None:
    """Clone a repository to a temp directory. Returns path or None."""
    clone_url = repo.get("clone_url", "")
    if not clone_url:
        return None

    clone_dir = tempfile.mkdtemp(prefix="stratum_batch_")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", clone_url, clone_dir],
            capture_output=True, timeout=120,
        )
        return clone_dir
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        logger.warning("Clone failed for %s: %s", repo.get("full_name"), e)
        shutil.rmtree(clone_dir, ignore_errors=True)
        return None


def _is_example_repo(repo: dict, result=None) -> bool:
    """Detect if a repo is an example/demo project.

    Checks repo name/description for example keywords,
    and optionally checks scan results for anomalous framework/finding counts.
    """
    name = (repo.get("name") or "").lower()
    desc = (repo.get("description") or "").lower()
    combined = f"{name} {desc}"

    # Keyword match in name or description
    if any(kw in combined for kw in EXAMPLE_KEYWORDS):
        return True

    if result is not None:
        # 4+ frameworks detected suggests a kitchen-sink demo
        if len(getattr(result, "detected_frameworks", [])) >= 4:
            return True
        # 80+ findings suggests an intentionally insecure example
        all_findings = getattr(result, "top_paths", []) + getattr(result, "signals", [])
        if len(all_findings) >= 80:
            return True

    return False


def discover_clustered(
    output_dir: str,
    max_repos: int = 500,
) -> None:
    """Two-phase discovery: broad search then expand multi-repo orgs + seed orgs.

    Phase 1: Standard broad search using SEARCH_QUERIES.
    Phase 2: For orgs that appear 2+ times, fetch all their agent repos.
             Also scan SEED_ORGS repos.
    """
    from stratum.scanner import scan as stratum_scan
    from stratum.telemetry.profile import build_scan_profile
    from stratum.batch.repo_context import build_repo_context

    os.makedirs(output_dir, exist_ok=True)
    scanned_hashes: set[str] = _load_scanned_hashes(output_dir)
    total_scanned = 0
    org_counts: dict[str, int] = {}

    # Phase 1: Broad search
    logger.info("Phase 1: Broad search")
    for query in SEARCH_QUERIES:
        if total_scanned >= max_repos // 2:
            break
        repos = _github_search(query, max_results=50)
        for repo in repos:
            if total_scanned >= max_repos // 2:
                break
            repo_hash = hashlib.sha256(
                repo.get("full_name", "").encode()
            ).hexdigest()[:16]
            if repo_hash in scanned_hashes:
                continue

            # Track org
            owner = repo.get("owner", {}).get("login", "")
            if owner:
                org_counts[owner] = org_counts.get(owner, 0) + 1

            scanned_hashes.add(repo_hash)
            total_scanned += 1

    # Phase 2: Expand multi-repo orgs + seed orgs
    expand_orgs = {org for org, count in org_counts.items() if count >= 2}
    expand_orgs.update(SEED_ORGS)
    logger.info("Phase 2: Expanding %d orgs", len(expand_orgs))

    for org in expand_orgs:
        if total_scanned >= max_repos:
            break
        repos = _github_search(f"org:{org} agent", max_results=20)
        for repo in repos:
            if total_scanned >= max_repos:
                break
            repo_hash = hashlib.sha256(
                repo.get("full_name", "").encode()
            ).hexdigest()[:16]
            if repo_hash in scanned_hashes:
                continue
            scanned_hashes.add(repo_hash)
            total_scanned += 1

    logger.info("Discovery complete: %d repos identified", total_scanned)


def _load_scanned_hashes(output_dir: str) -> set[str]:
    """Load set of already-scanned repo hashes from output directory."""
    hashes: set[str] = set()
    if os.path.isdir(output_dir):
        for fname in os.listdir(output_dir):
            if fname.endswith(".json"):
                hashes.add(fname.replace(".json", ""))
    return hashes


def main() -> None:
    parser = argparse.ArgumentParser(description="Batch scan GitHub agent projects")
    parser.add_argument("--query", type=str, help="Single search query")
    parser.add_argument("--all", action="store_true", help="Use all default queries")
    parser.add_argument("--max-repos", type=int, default=100, help="Max repos to scan")
    parser.add_argument("--output", type=str, default="./scans", help="Output directory")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(message)s",
    )

    queries = None
    if args.query:
        queries = [args.query]
    elif not args.all:
        parser.error("Specify --query or --all")

    scan_github(args.output, max_repos=args.max_repos, queries=queries)


if __name__ == "__main__":
    main()
