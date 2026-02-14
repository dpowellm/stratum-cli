# Stratum 50k Pipeline

Orchestrates the discovery, scanning, and quality audit of ~50k public GitHub repos to produce the Stratum benchmarking dataset.

## Setup

```bash
# 1. Set your GitHub token (requires public_repo scope)
export GITHUB_TOKEN=ghp_your_token_here

# 2. Install dependencies
pip install -r pipeline/requirements.txt
```

## Phase 1: Repo Discovery

Queries the GitHub Search API across 8 strata, enriches repos with metadata, filters forks, deduplicates, and produces a frozen manifest.

### Usage

```bash
# Dry run — show queries and targets, no API calls
python pipeline/discover.py --dry-run

# Single stratum test
python pipeline/discover.py --stratum crewai --output pipeline/data/test_manifest.jsonl

# Full discovery run
python pipeline/discover.py --output pipeline/data/repo_manifest.jsonl

# Resume after interruption
python pipeline/discover.py --resume --output pipeline/data/repo_manifest.jsonl
```

### Output

- `pipeline/data/repo_manifest.jsonl` — one JSON record per unique repo
- `pipeline/data/discovery_log.json` — run summary with strata distribution

### Strata

| Stratum | Target | Queries |
|---------|--------|---------|
| langchain_active | 8,000 | langchain agent/tool/graph |
| crewai | 6,000 | crewai / crewai crew |
| langgraph | 5,000 | langgraph / langgraph agent |
| autogen | 3,000 | autogen agent / multi-agent |
| llamaindex | 3,000 | llamaindex / llama-index agent |
| agno_smolagents_other | 3,000 | agno / smolagents / ai agent framework |
| high_maturity | 5,000 | stars:>100 / stars:>50 |
| discovery_pool | 10,000 | ai/llm/autonomous agent |

Total target: ~43,000. After dedup, expect ~50-60k unique repos.

## Schema

All outputs conform to Stratum telemetry schema v0.3.2 (schema_id=5). See `spec/telemetry/SCHEMA.md` for the full data dictionary.
