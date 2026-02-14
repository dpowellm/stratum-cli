# Stratum 50k Scan — Dataset Strategy

The schema (v7 + v7.1) defines what you collect per scan. This document covers the two things that determine whether the dataset is actually useful: which repos you scan, and how you run the pipeline.

---

## Part 1: Repo Selection

The 50k scan is a one-shot. The selection methodology IS the dataset. Get it wrong and you have 50k rows of noise.

### The Fork Problem

crewAI-examples has ~2,000 forks on GitHub. If you discover repos by searching "crewai" and clone what comes back, your dataset has 2,000 near-identical rows. Any model trained on this overfits to one architecture pattern. Worse, forks cluster around popular tutorials — simple architectures, no production complexity. Your model learns to predict risk for toy projects.

**Fix:** During discovery (before scanning), call the GitHub API's `/repos/{owner}/{repo}` endpoint. If `fork: true`, record `fork_parent` and skip by default. Maintain a fork index: for each parent repo, allow at most 1 fork into the dataset (the most-starred or most-recently-updated fork). This turns 2,000 crewAI-examples clones into 1 data point.

### Stratified Sampling

A naive GitHub search returns whatever has the most SEO. The framework distribution will be ~70% LangChain, ~15% CrewAI, ~5% AutoGen, ~10% everything else. That makes benchmarking useless for non-LangChain users — and CrewAI developers are your early adopters.

**Fix:** Define target strata before selection:

| Stratum | Target N | Discovery query pattern |
|---------|----------|------------------------|
| LangChain (active) | 8,000 | `langchain agent` pushed:>2025-06-01 NOT fork |
| LangChain (mature) | 4,000 | `langchain` stars:>50 pushed:>2025-01-01 |
| CrewAI | 6,000 | `crewai` pushed:>2025-06-01 NOT fork |
| LangGraph | 5,000 | `langgraph` pushed:>2025-06-01 |
| AutoGen | 3,000 | `autogen agent` pushed:>2025-01-01 |
| LlamaIndex | 3,000 | `llamaindex agent` pushed:>2025-01-01 |
| Agno / SmolAgents / Other | 3,000 | Various |
| Multi-framework | 3,000 | Repos detected with 2+ frameworks |
| High-maturity | 5,000 | Stars:>100 OR has Dockerfile + CI + tests |
| Discovery pool | 10,000 | Broad "ai agent python" for long-tail |

Totals to ~50k. Strata overlap (a CrewAI repo with 200 stars appears in both "CrewAI" and "high-maturity"), so deduplicate after discovery. The point is: you control the distribution rather than letting GitHub's search ranking control it.

The "high-maturity" stratum is critical. Enterprise benchmarks are only credible if calibrated against production-grade repos. Without deliberate oversampling, the dataset will be 90%+ experimental code.

### Recency Filter

A repo last updated in 2023 using LangChain 0.1 tells you nothing about current risk patterns. The agent framework landscape changes quarterly. Abandoned repos outnumber active ones 10:1 on GitHub.

**Fix:** Hard floor of `pushed:>2025-01-01` for most strata. For the "high-maturity" stratum, relax to `pushed:>2024-06-01` (mature repos update less frequently). Record `last_commit_date` in selection metadata for filtering at analysis time.

### Selection Metadata

Every repo gets a selection record BEFORE scanning, from the GitHub API:

```json
"repo_source_metadata": {
  "github_stars": 342,
  "github_forks": 45,
  "last_commit_date": "2026-01-15",
  "repo_created_date": "2025-03-22",
  "is_fork": false,
  "fork_parent": null,
  "license": "MIT",
  "github_topics": ["langchain", "agents", "rag"],
  "primary_language": "Python",
  "language_bytes": {"Python": 45000, "JavaScript": 12000},
  "has_readme": true,
  "discovery_query": "langchain agent pushed:>2025-06-01",
  "selection_stratum": "langchain_active",
  "collected_at": "2026-02-14T10:00:00Z"
}
```

This lives in a separate `repo_manifest.jsonl` alongside the pings. Not in the ping itself — it's GitHub metadata, not scan telemetry. Joined to pings via `repo_hash`.

Key fields:
- `is_fork` + `fork_parent` — deduplication during analysis and training weight
- `github_stars` — maturity/popularity proxy, weighting signal
- `last_commit_date` — recency filter
- `selection_stratum` — know which bucket this repo was drawn from
- `discovery_query` — reproducibility (someone can re-run the exact query)
- `language_bytes` — know what fraction of the repo is Python (the scanner's coverage)

### Minimum Viable Counts

Work backward from product features to the data needed:

**"Repos like yours score X"** (benchmarking percentiles)
- Stable percentile estimates require ~200 repos per bucket
- Buckets: {framework} × {agent_count: 1, 2-5, 6-20, 21+} × {maturity: low/high}
- That's ~7 frameworks × 4 size buckets × 2 maturity = 56 buckets
- At 200 per bucket = 11,200 minimum useful repos
- 50k gives ~4x headroom after deduplication and filtering

**"Fixing CR05 drops score by 8 points"** (fix impact medians)
- Stable median requires ~100 repos per finding rule
- ~20 finding rules → need 100+ repos with each common rule
- Most rules fire in >10% of repos → 5,000+ instances at 50k

**"Your fleet vs industry"** (enterprise benchmarks)
- CISO's fleet is production-grade. Benchmark must compare like-to-like.
- Need ≥2,000 repos with `deployment_score >= 3` to form a "production" baseline
- The "high-maturity" stratum targets this directly

---

## Part 2: Execution Pipeline

### Pipeline Architecture

```
Discovery → Manifest → Clone → Scan → Validate → Store
```

**Discovery:** GitHub Search API queries, one per stratum. Collect `repo_source_metadata`. Deduplicate by `full_name`. Filter forks. Output: `repo_manifest.jsonl` (~60-70k candidates for 50k target).

**Manifest:** The frozen list of repos to scan. Version-controlled. Never modified after pipeline starts. Every scan references a manifest row by `repo_hash`.

**Clone:** `git clone --depth 1` (shallow, saves bandwidth). 5-minute timeout per clone. Failed clones → retry queue (3 attempts, exponential backoff). After 3 failures → emit `scan_status: "failed"` ping with `failure_reason: "clone_timeout"` or `"clone_404"`.

**Scan:** Run `stratum scan .` on each cloned repo. 5-minute hard timeout. If timeout → emit `scan_status: "partial"` ping. If no agents found → emit `scan_status: "empty"` ping. Always emit a ping. Zero silent drops.

**Validate:** Per-ping validation before storage:
- `schema_id == 3` (or current)
- `repo_hash` matches manifest
- `finding_count == sum(finding_severities.values())`
- `len(crew_size_distribution) == crew_count`
- All required fields present

Invalid pings → quarantine queue for manual review. Never silently dropped.

**Store:** Append to `scan_results.jsonl` (one line per ping). Alongside `repo_manifest.jsonl`.

### Failure Handling

Add to ping schema (part of v7 `scan_status` but needs a companion field):

```json
"failure_reason": null
```

Values when `scan_status != "success"`:
- `"clone_timeout"` — git clone exceeded 5 minutes
- `"clone_404"` — repo not found (deleted or private)
- `"clone_rate_limited"` — GitHub rate limit after retries
- `"parse_timeout"` — scanner exceeded 5 minutes
- `"parse_crash"` — scanner threw unhandled exception
- `"no_python"` — no Python files found
- `"no_agents"` — Python files found but no agents detected

For `"failed"` and some `"partial"` pings, most telemetry fields will be null/zero. That's fine — the ping's value is knowing that this repo EXISTS and FAILED, not its risk score.

### Rate Limiting Strategy

GitHub authenticated API: 5,000 requests/hour. Discovery phase needs ~500 API calls (paginated search results). Clone phase doesn't use the API. Scan phase doesn't use the API.

The bottleneck is clone bandwidth. At ~50MB average repo (shallow clone), 50k repos = ~2.5TB of data. Sequential cloning at ~10 repos/minute = ~83 hours.

**Parallelism:** 10 concurrent clone+scan workers. Each worker: clone → scan → emit ping → delete clone → next. Storage footprint: 10 × 50MB = 500MB peak. Runtime: ~8 hours.

### Pipeline Run Log

Separate from pings. One record per pipeline execution:

```json
{
  "run_id": "run_2026-02-14_001",
  "started_at": "2026-02-14T10:00:00Z",
  "completed_at": "2026-02-14T18:23:00Z",
  "manifest_version": "v1",
  "manifest_repo_count": 52000,
  "scans_attempted": 52000,
  "scans_success": 44500,
  "scans_partial": 2100,
  "scans_failed": 1900,
  "scans_empty": 3500,
  "framework_distribution": {
    "LangChain": 18000,
    "CrewAI": 8500,
    "LangGraph": 7200,
    ...
  },
  "rate_limit_hits": 12,
  "total_duration_hours": 8.4,
  "avg_scan_duration_ms": 890
}
```

---

## Part 3: Post-Collection, Pre-Training

### Dataset Audit (before any modeling)

**Distribution analysis:**
- Score distribution: histogram of `risk_score`. Is it bimodal? Heavy-tailed? Uniform? This determines whether percentile-based thresholds make sense.
- Finding prevalence: for each finding rule, what % of repos trigger it? Rules that fire in <1% of repos can't support a prediction model.
- Framework distribution: actual vs target strata. If CrewAI is underrepresented, consider a targeted supplemental scan.
- Maturity distribution: histogram of `deployment_score`. What fraction of the dataset is "production-grade" (score ≥ 3)?

**Fork/duplicate audit:**
- Group by `topology_signature_hash`. Any hash with >10 repos is suspicious — likely forks or copy-paste clones.
- Group by `fork_parent` from manifest. Confirm dedup policy was applied.
- Measure effective dataset size after dedup.

**Coverage audit:**
- Distribution of `files_scanned / files_total`. Repos where coverage <50% may have unreliable results.
- Distribution of `language_bytes.Python / sum(language_bytes)` from manifest. Repos that are <20% Python are barely covered.
- Count of `scan_status: "empty"`. If >20%, the agent detection heuristics need tuning before using the data.

### Label Audit

risk_score is computed by the scoring formula. Training a model to predict your own score is circular. The model learns `raw/(raw+50)*100`, not actual risk.

**Fix:** Manual review of 100 repos stratified by score bucket (20 repos from each quintile). For each repo, a human answers: "Is this repo riskier than one with a lower score?" Binary agreement rate should be ≥80%. If it's lower, the scoring formula needs recalibration before training.

This is 1-2 days of work. It's the difference between "our benchmarks are statistically rigorous" and "our benchmarks are vibes."

### Train/Test Split

Stratified by {framework × deployment_score_bucket}, not random. Each test stratum needs ≥40 repos for reliable evaluation. At 50k repos with 80/20 split, the test set is ~10k — more than enough if the selection strata were adequate.

Freeze the split before any modeling. Store the split assignment (`train` or `test`) in the manifest so it's never accidentally contaminated.

### Feature/Label Separation

Define before training begins:

**Architecture features** (inputs to models):
- `graph_topology_metrics.*`
- `crew_size_distribution`
- `agent_tool_count_distribution`
- `capability_distribution`
- `trust_level_distribution`
- `agent_count`, `crew_count`, `total_tool_count`
- `deployment_signals.*`
- `repo_metadata.*`

**Risk features** (labels / prediction targets):
- `risk_score`
- `finding_rules` (binary vector)
- `finding_severities`
- `finding_instance_counts`
- `fix_impact_estimates`

**Metadata features** (for bucketing / stratification, not model input):
- `repo_source_metadata.*`
- `framework_versions`
- `llm_providers`

Never use risk features to predict risk features. The model must learn architecture → risk, not formula → score.

---

## Part 4: What This Means for the Ping Schema

Two additions to the v7.1 schema:

### Add: `failure_reason` (string, nullable)

```json
"failure_reason": null
```

Companion to `scan_status`. Null when status is `"success"`. Enum string otherwise. Required for understanding WHY 5-10% of scans fail — which is the most actionable data for improving the scanner before enterprise deployment.

### Add: `repo_source_metadata` as a separate file, not in the ping

This is GitHub API data, not scan telemetry. It lives in `repo_manifest.jsonl`, joined to pings via `repo_hash`. Keeping it out of the ping maintains the telemetry contract ("no source code, file paths, or secrets are collected") and avoids bloating every ping with static metadata.

**Final ping field count:** ~98 (v7 base of ~90, plus v7.1's 7 fields, plus `failure_reason`).

**Companion files:**
- `scan_results.jsonl` — one ping per scan (50k+ rows)
- `repo_manifest.jsonl` — one row per repo with GitHub metadata (50k+ rows)  
- `pipeline_run_log.json` — one record per pipeline execution

---

## Summary: The Full Stack

| Layer | What | Status |
|-------|------|--------|
| Schema — pipeline integrity | repo_hash, scan_status, duration, files, parser_errors, schema_id | v7 ✅ |
| Schema — ML features | normalized_features, graph_topology, distributions, co-occurrence | v7 ✅ |
| Schema — product features | finding_instance_counts, fix_impact_estimates, llm_providers, framework_versions, deployment_signals, inter_crew_edges | v7.1 spec |
| Schema — failure handling | failure_reason | This doc |
| Repo selection | Stratified sampling, fork filtering, recency floor, manifest | This doc |
| Execution pipeline | Clone/scan/validate/store with failure handling and monitoring | This doc |
| Post-collection | Distribution audit, label audit, train/test split, feature/label separation | This doc |

The schema is necessary but not sufficient. The dataset is the schema × selection × pipeline × audit.
