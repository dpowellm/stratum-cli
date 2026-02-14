"""Shared configuration for the Stratum 50k pipeline."""

import os
import sys

GITHUB_API = "https://api.github.com"

# Token and headers are None at module level — call require_token() before API use.
GITHUB_TOKEN = None
GITHUB_HEADERS = None


def require_token():
    """Validate GITHUB_TOKEN and return (token, headers). Exits if missing."""
    global GITHUB_TOKEN, GITHUB_HEADERS
    if GITHUB_TOKEN is not None:
        return GITHUB_TOKEN, GITHUB_HEADERS

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("ERROR: GITHUB_TOKEN environment variable is required.", file=sys.stderr)
        print("  export GITHUB_TOKEN=ghp_...", file=sys.stderr)
        sys.exit(1)

    GITHUB_TOKEN = token
    GITHUB_HEADERS = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    return GITHUB_TOKEN, GITHUB_HEADERS

# Rate limit thresholds
RATE_LIMIT_FLOOR = 5          # sleep when remaining < this
SEARCH_RATE_LIMIT_FLOOR = 2   # search API is stricter (30/min)
MAX_RETRIES = 3
RETRY_BACKOFF = [2, 10, 30]   # seconds

# GitHub Search API limits
SEARCH_PER_PAGE = 100
SEARCH_MAX_RESULTS = 1000     # GitHub caps at 1000 per query

# Date partitions for queries that hit the 1000-result cap
DATE_PARTITIONS = [
    ("2024-01-01", "2024-04-01"),
    ("2024-04-01", "2024-07-01"),
    ("2024-07-01", "2024-10-01"),
    ("2024-10-01", "2025-01-01"),
    ("2025-01-01", "2025-04-01"),
    ("2025-04-01", "2025-07-01"),
    ("2025-07-01", "2025-10-01"),
    ("2025-10-01", "2026-01-01"),
    ("2026-01-01", "2026-04-01"),
]

# Default output paths
DEFAULT_MANIFEST_PATH = "pipeline/data/repo_manifest.jsonl"
DEFAULT_DISCOVERY_LOG_PATH = "pipeline/data/discovery_log.json"
DEFAULT_SCAN_RESULTS_PATH = "pipeline/data/scan_results.jsonl"
DEFAULT_QUARANTINE_PATH = "pipeline/data/quarantine.jsonl"
DEFAULT_PIPELINE_LOG_PATH = "pipeline/data/pipeline_run_log.json"

# Scan runner settings
SCAN_TIMEOUT_SECONDS = 300       # 5-minute timeout for stratum scan
CLONE_TIMEOUT_SECONDS = 300      # 5-minute timeout for git clone
DEFAULT_WORKERS = 10
CLONE_RETRY_BACKOFF = [5, 30, 120]  # seconds between clone retries
CLONE_MAX_RETRIES = 3
LOG_INTERVAL = 100               # update pipeline_run_log every N scans

STRATA = [
    {
        "name": "langchain_active",
        "queries": [
            "langchain agent language:python pushed:>2025-06-01",
            "langchain tool language:python pushed:>2025-06-01",
            "langchain graph language:python pushed:>2025-06-01",
        ],
        "target": 8000,
    },
    {
        "name": "crewai",
        "queries": [
            "crewai language:python pushed:>2025-06-01",
            "crewai crew language:python pushed:>2025-06-01",
        ],
        "target": 6000,
    },
    {
        "name": "langgraph",
        "queries": [
            "langgraph language:python pushed:>2025-06-01",
            "langgraph agent language:python pushed:>2025-06-01",
        ],
        "target": 5000,
    },
    {
        "name": "autogen",
        "queries": [
            "autogen agent language:python pushed:>2025-01-01",
            "autogen multi-agent language:python pushed:>2025-01-01",
        ],
        "target": 3000,
    },
    {
        "name": "llamaindex",
        "queries": [
            "llamaindex agent language:python pushed:>2025-01-01",
            "llama-index agent language:python pushed:>2025-01-01",
        ],
        "target": 3000,
    },
    {
        "name": "agno_smolagents_other",
        "queries": [
            "agno agent language:python pushed:>2025-06-01",
            "smolagents language:python pushed:>2025-06-01",
            "ai agent framework language:python pushed:>2025-06-01",
        ],
        "target": 3000,
    },
    {
        "name": "high_maturity",
        "queries": [
            "ai agent language:python stars:>100",
            "llm agent language:python stars:>50 pushed:>2024-06-01",
        ],
        "target": 5000,
    },
    {
        "name": "discovery_pool",
        "queries": [
            "ai agent python language:python pushed:>2025-06-01",
            "llm agent language:python pushed:>2025-06-01",
            "autonomous agent language:python pushed:>2025-01-01",
        ],
        "target": 10000,
    },
]
