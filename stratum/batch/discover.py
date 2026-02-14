"""Discover companies with AI agent repositories on GitHub.

Uses GitHub Code Search API to find repos with agent framework imports.
Output: repos.jsonl — one line per repo with org, stars, framework signal.

Usage:
    python -m stratum.batch.discover --output repos.jsonl --token ghp_...
    python -m stratum.batch.discover --output repos.jsonl --max-pages 5
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import time
import urllib.request
import urllib.error

logger = logging.getLogger(__name__)

# Code search queries that identify agent framework usage
CODE_QUERIES = [
    'from crewai import Crew',
    'from crewai import Agent',
    'from langgraph.graph import StateGraph',
    'from langchain.agents import AgentExecutor',
    'from langchain.agents import create_react_agent',
    'from langchain.agents import create_openai_functions_agent',
    'from autogen import AssistantAgent',
    'from autogen import ConversableAgent',
]

# Repo search queries (topic-based, broader)
REPO_QUERIES = [
    "crewai agent",
    "langgraph agent",
    "langchain agent tool",
    "multi agent system python",
    "agentic workflow python",
    "AI agent orchestration",
]


def discover_repos(
    output_path: str,
    github_token: str,
    max_pages: int = 10,
    use_code_search: bool = True,
) -> int:
    """Find repos with agent framework imports via GitHub API.

    Args:
        output_path: Path to write repos.jsonl (one JSON object per line).
        github_token: GitHub personal access token for API auth.
        max_pages: Max pages per query (100 results per page).
        use_code_search: If True, use code search; else use repo search.

    Returns:
        Number of unique repos discovered.
    """
    seen: set[str] = set()

    # Load existing repos if file exists (resume support)
    if os.path.exists(output_path):
        try:
            with open(output_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        obj = json.loads(line)
                        seen.add(obj.get("repo", ""))
        except (OSError, json.JSONDecodeError):
            pass
    logger.info("Starting with %d existing repos", len(seen))

    queries = CODE_QUERIES if use_code_search else REPO_QUERIES
    new_count = 0

    with open(output_path, "a", encoding="utf-8") as f:
        for query in queries:
            logger.info("Searching: %s", query)
            for page in range(1, max_pages + 1):
                items = _search_github(
                    query, page, github_token,
                    search_type="code" if use_code_search else "repositories",
                )
                if items is None:
                    # Rate limited or error — wait and skip
                    logger.warning("Rate limited on page %d, waiting 60s", page)
                    time.sleep(60)
                    continue

                for item in items:
                    if use_code_search:
                        repo_data = item.get("repository", {})
                    else:
                        repo_data = item

                    full_name = repo_data.get("full_name", "")
                    if not full_name or full_name in seen:
                        continue

                    seen.add(full_name)
                    org = full_name.split("/")[0]
                    entry = {
                        "repo": full_name,
                        "org": org,
                        "stars": repo_data.get("stargazers_count", 0),
                        "forks": repo_data.get("forks_count", 0),
                        "language": repo_data.get("language", ""),
                        "description": (repo_data.get("description") or "")[:200],
                        "query": query,
                    }
                    f.write(json.dumps(entry) + "\n")
                    new_count += 1

                if len(items) < 100:
                    break  # No more results for this query

                # Rate limiting: GitHub allows 10 code searches/min for authenticated
                time.sleep(2)

    logger.info("Discovered %d new repos (total: %d)", new_count, len(seen))
    return new_count


def _search_github(
    query: str, page: int, token: str, search_type: str = "code",
) -> list[dict] | None:
    """Execute a single GitHub search API request.

    Returns list of items, or None if rate limited / error.
    """
    url = f"https://api.github.com/search/{search_type}"
    params = f"q={urllib.parse.quote(query)}&per_page=100&page={page}"
    if search_type == "repositories":
        params += "&sort=stars&order=desc"

    full_url = f"{url}?{params}"
    req = urllib.request.Request(
        full_url,
        headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "stratum-batch-scanner",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("items", [])
    except urllib.error.HTTPError as e:
        if e.code == 403:
            return None  # Rate limited
        logger.warning("GitHub search failed: HTTP %d", e.code)
        return []
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
        logger.warning("GitHub search error: %s", e)
        return []


import urllib.parse  # noqa: E402 (needed for quote in _search_github)


def main() -> None:
    parser = argparse.ArgumentParser(description="Discover AI agent repos on GitHub")
    parser.add_argument("--output", type=str, default="repos.jsonl",
                        help="Output JSONL file path")
    parser.add_argument("--token", type=str,
                        default=os.environ.get("GITHUB_TOKEN", ""),
                        help="GitHub token (or set GITHUB_TOKEN env var)")
    parser.add_argument("--max-pages", type=int, default=10,
                        help="Max pages per query")
    parser.add_argument("--repo-search", action="store_true",
                        help="Use repo search instead of code search")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(message)s",
    )

    if not args.token:
        parser.error("GitHub token required: --token or GITHUB_TOKEN env var")

    discover_repos(
        args.output, args.token,
        max_pages=args.max_pages,
        use_code_search=not args.repo_search,
    )


if __name__ == "__main__":
    main()
