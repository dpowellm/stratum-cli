# Stratum 50k Pipeline

Orchestrates the discovery, scanning, and quality audit of ~50k public GitHub repos to produce the Stratum benchmarking dataset.

## Setup

```bash
# 1. Set your GitHub token (requires public_repo scope)
export GITHUB_TOKEN=ghp_your_token_here

# 2. Install dependencies
pip install -r pipeline/requirements.txt

# 3. Ensure stratum-cli is installed (needed for Phase 2)
pip install -e .
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

## Phase 2: Scan Runner

Parallel scan runner that clones repos, runs `stratum scan`, validates pings, and writes results to `scan_results.jsonl`. Invalid pings go to `quarantine.jsonl`.

### Quick test (first 16 repos)

```bash
python pipeline/scan_runner.py --manifest pipeline/data/test_manifest.jsonl --limit 16 --workers 2
```

### Full 50k scan

```bash
# Start the scan (default 10 workers)
python pipeline/scan_runner.py

# Or with custom settings
python pipeline/scan_runner.py --workers 20 --manifest pipeline/data/repo_manifest.jsonl
```

### Resume after crash

```bash
# Automatically skips repos already in scan_results.jsonl and quarantine.jsonl
python pipeline/scan_runner.py --resume
```

### Output

- `pipeline/data/scan_results.jsonl` — validated scan pings (success, partial, failed, empty)
- `pipeline/data/quarantine.jsonl` — pings that failed schema validation
- `pipeline/data/pipeline_run_log.json` — run progress (updated every 100 scans)

### CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `--manifest`, `-m` | `pipeline/data/repo_manifest.jsonl` | Path to repo manifest |
| `--limit`, `-l` | (all) | Scan only the first N repos |
| `--workers`, `-w` | 10 | Number of parallel workers |
| `--resume` | off | Skip already-scanned repos |

## Phase 3: Monitor

Real-time dashboard that tails `scan_results.jsonl` and displays progress, status breakdown, score distribution, and framework stats.

### Run in a separate terminal while scanning

```bash
# Live watch (refreshes every 30 seconds)
python pipeline/monitor.py

# One-shot snapshot
python pipeline/monitor.py --once
```

### Dashboard shows

- Progress count and percentage
- Status breakdown (success / partial / failed / empty / quarantined)
- Score distribution buckets (0-20, 21-40, 41-60, 61-80, 81-100)
- Framework distribution (top 10)
- Average scan duration
- ETA based on throughput
- Last error

## Phase 4: Dataset Audit

Post-collection quality audit that reads `scan_results.jsonl`, evaluates 8 quality gates, and produces a markdown report with ASCII histograms.

### Full audit

```bash
python pipeline/audit.py
python pipeline/audit.py --input pipeline/data/scan_results.jsonl
```

### Generate train/test split

```bash
# Stratified 80/20 split by framework x deployment_score
python pipeline/audit.py --split
```

### Run a single section

```bash
python pipeline/audit.py --section duplicates
python pipeline/audit.py --section frameworks
```

Available sections: `volume`, `frameworks`, `scores`, `findings`, `maturity`, `duplicates`, `coverage`, `strata`, `gates`, `recommendations`

### Quality Gates

| Gate | Name | Threshold |
|------|------|-----------|
| G1 | Volume | success + partial >= 40,000 |
| G2 | Framework coverage | each top-5 framework >= 1,000 repos |
| G3 | Maturity spread | >= 2,000 repos with deployment_score >= 3 |
| G4 | Finding coverage | >= 15 rules appear in 100+ repos |
| G5 | Duplicate rate | <= 5% repos share topology_signature_hash with 10+ others |
| G6 | Empty rate | empty scans <= 20% |
| G7 | Failure rate | failed scans <= 10% |
| G8 | Coverage | median files_scanned/files_total >= 0.80 |

### Output

- `pipeline/data/dataset_audit_report.md` — full audit report with ASCII charts
- `pipeline/data/scan_results_train.jsonl` — training split (80%, with `--split`)
- `pipeline/data/scan_results_test.jsonl` — test split (20%, with `--split`)

### Testing with synthetic data

```bash
# Generate 200 synthetic pings
python pipeline/generate_test_data.py

# Run audit on synthetic data
python pipeline/audit.py --input pipeline/data/test_scan_results.jsonl
```

## Schema

All outputs conform to Stratum telemetry schema v0.3.2 (schema_id=5). See `spec/telemetry/SCHEMA.md` for the full data dictionary.
