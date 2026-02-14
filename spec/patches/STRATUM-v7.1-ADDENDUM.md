# Stratum v7.1 Addendum — Collect-Now-or-Never Fields

**Context:** v7 hardened the schema for pipeline integrity and ML readiness. This addendum adds 6 fields that require data available during the scan but unrecoverable from the ping afterward. Skipping any of these means rescanning 50k repos to get the data.

**Test:** For each proposed field, ask: "Can I compute this from the existing ping fields alone?" If yes, skip it — compute at analysis time. If no, it must be collected.

---

## 1. `finding_instance_counts` — Per-rule instance count

```json
"finding_instance_counts": {
  "STRATUM-001": 20,
  "STRATUM-CR05": 3,
  "STRATUM-CR05.1": 1,
  "STRATUM-CR05.2": 1,
  "STRATUM-009": 29,
  "STRATUM-008": 8,
  "CONTEXT-001": 1,
  ...
}
```

**Why it can't be reconstructed:** `finding_rules` is a deduplicated list (18 unique rules). `finding_count` is the total (also 18 in current data — because we currently count unique rules, not instances). The actual number of *places in code* where each rule fires requires the finding engine's raw output, which is discarded after the ping.

**What it powers:**
- **Indie:** "You have 20 crews without human review. Fix the 9 YAML-configured ones to close this finding entirely." Instance count is the denominator for the partial credit progress bar.
- **Enterprise:** "STRATUM-CR05 fires an average of 4.2 times per repo. Your fleet has 12.7 instances per repo — 3x above median."
- **Model 2 (finding prediction):** Instance count is a stronger feature than binary presence. A repo with 20 instances of STRATUM-001 has a fundamentally different risk profile than one with 2.

**Implication for existing fields:** `finding_count` should become `sum(finding_instance_counts.values())` (total instances), which may be > `finding_rule_count` (unique rules). This redefines finding_count from "unique rules that fired" to "total finding instances." The initial ping would change from finding_count=18 to finding_count=~80+ (since STRATUM-001 alone fires 20 times). This is a breaking semantic change that needs careful handling.

**Recommendation:** Add `finding_instance_counts` AND add a separate `total_finding_instances` field. Keep `finding_count` as-is (unique rule count) to avoid breaking the existing score math. Make the distinction explicit:
- `finding_rule_count`: 18 (unique rules, same as len(finding_rules))
- `total_finding_instances`: 83 (sum of all instances across all rules)
- `finding_instance_counts`: {rule → instance_count} (the detail)

---

## 2. `fix_impact_estimates` — Per-rule score delta if fixed

```json
"fix_impact_estimates": {
  "STRATUM-001": -8,
  "STRATUM-CR05": -12,
  "STRATUM-CR05.1": -3,
  "STRATUM-009": -2,
  "STRATUM-008": -1,
  ...
}
```

Negative values = score decreases (improvement). Each value is the estimated score change if ALL instances of that rule are resolved.

**Why it can't be reconstructed:** The scoring formula uses intermediate values — blast radius multipliers, crew-level aggregation weights, partial credit adjustments — that aren't in the ping. Simulating "remove finding X and recalculate" requires the full scoring engine state, which only exists during the scan.

**What it powers:**
- **Indie (killer feature):** "Fix STRATUM-CR05 first — it drops your score by 12 points. STRATUM-001 only drops it by 8." This is the line that converts a curious developer into a repeat user.
- **Terminal enhancement:** Finding ① can show "Score impact: -12 points" alongside "Resolves 3 findings."
- **Model (fix prioritization):** Train on {finding_rule, architecture_features} → actual_score_delta. At 50k repos, this becomes: "Fixing shared tool blast radius in hub-spoke architectures gives a median 15-point improvement, vs 6 points in pipeline architectures."

**Computation:** For each finding rule, clone the scoring state, remove all instances of that rule, recalculate. O(n) where n = number of rules. Trivial.

---

## 3. `llm_providers` + `llm_models` — Provider and model lists

```json
"llm_providers": ["openai", "anthropic"],
"llm_models": ["gpt-4o", "claude-sonnet-4-5-20250929"]
```

**Why it can't be reconstructed:** `provider_confidence` tells us HOW we inferred (detected/env_var/framework) but not WHICH providers or models. These lists are in batch-results but not in the ping. To do fleet analysis from pings alone (which is what the enterprise product does), you need them here.

**What it powers:**
- **Enterprise:** "78% of repos in your fleet depend on OpenAI. If OpenAI has a 4-hour outage, here are the 156 affected repos." Computable from pings without joining to batch-results.
- **Model 4 (provider concentration):** Per-repo provider diversity as a feature. Single-provider repos have correlated failure risk.
- **Benchmarking:** "Repos using Claude have 23% fewer findings than repos using GPT-4o for the same architecture pattern." Only possible if models are in the ping alongside findings.

---

## 4. `framework_versions` — Detected version strings

```json
"framework_versions": {
  "CrewAI": "0.80.0",
  "LangChain": "0.3.7",
  "LangGraph": "0.2.44"
}
```

**Why it can't be reconstructed:** Requires parsing `requirements.txt`, `pyproject.toml`, or import version strings at scan time. The ping only has framework names (from `frameworks` list in batch-results, and `repo_metadata.primary_framework`).

**What it powers:**
- **Enterprise:** "Your LangChain 0.1 repos have 3.2x the finding density of your LangChain 0.3 repos. Upgrade priority: these 12 repos." Version-aware benchmarking is table stakes.
- **Indie:** "You're on CrewAI 0.50. Version 0.80 fixed the YAML config pattern that causes STRATUM-001. Consider upgrading."
- **Model 1 (benchmarking):** Version is a critical bucketing dimension. Without it, you're averaging across incompatible framework generations.

**Detection approach:** Parse `requirements.txt` / `pyproject.toml` / `setup.py` for pinned versions. If no pinned version, check `importlib.metadata` patterns in code. If neither, emit `null` for that framework. Partial data is better than no data.

---

## 5. `deployment_signals` — Production vs toy project markers

```json
"deployment_signals": {
  "has_dockerfile": true,
  "has_ci_config": true,
  "has_tests": true,
  "has_lockfile": true,
  "has_env_example": true,
  "deployment_score": 5
}
```

`deployment_score` = count of true signals (0-5). Higher = more likely production.

**Why it can't be reconstructed:** Requires checking for specific files during the directory walk. The ping has `files_scanned` and `files_total` but no information about which types of files exist.

**What it powers:**
- **Enterprise (critical):** Benchmarking against "repos like yours" is meaningless if "yours" is a production fleet and the benchmark includes 80% toy projects. `deployment_score >= 3` filters to production-like repos.
- **Model 1 (benchmarking):** "Among production-grade LangChain repos with 3-5 agents, your risk score of 72 is in the 89th percentile." Without deployment signals, this percentile includes student projects and hello-world repos.
- **Dataset quality:** At 50k public GitHub repos, the majority will be experimental. This field lets you weight or filter for the subset that's informative about real-world risk.

**Detection approach:** During the initial file-walk phase (which already runs), check for the existence of 5 specific file patterns. Zero additional parsing needed — just `os.path.exists()` calls.

---

## 6. `inter_crew_edges` — Cross-crew data flow count

```json
"inter_crew_edges": 3
```

Number of edges in the topology graph that connect nodes in different crews.

**Why it can't be reconstructed:** `graph_edge_count` is the total. `connected_components` tells you how many isolated subgraphs exist. But neither tells you how many edges cross crew boundaries. A graph with 93 edges and 20 components could have 0 inter-crew edges (fully isolated crews) or 20 inter-crew edges (heavily interconnected). These are completely different risk profiles.

**What it powers:**
- **Core thesis:** "Network topology for agents" means detecting risks that compound across crews. `inter_crew_edges > 0` means the system has cross-crew coupling. This is literally Stratum's differentiator.
- **Enterprise:** "Your fleet has 47 repos with cross-crew data flows. These are your highest systemic risk."
- **Model 3 (architecture classification):** Inter-crew coupling is the signal that separates "collection of independent crews" from "integrated multi-crew system." These are different architecture archetypes with different risk profiles.

**Computation:** For each edge in the topology graph, check if source and target belong to different crews. Count. One loop, O(edges).

---

## Field Summary

| # | Field | Type | Bytes | Powers |
|---|-------|------|-------|--------|
| 1 | `finding_instance_counts` | {str: int} | ~200 | Indie progress, enterprise benchmark, Model 2 |
| 2 | `fix_impact_estimates` | {str: int} | ~200 | **Indie killer feature**, fix prioritization model |
| 3 | `llm_providers` | [str] | ~50 | Enterprise fleet, Model 4 |
| 4 | `framework_versions` | {str: str} | ~80 | Enterprise benchmark, Model 1 bucketing |
| 5 | `deployment_signals` | object | ~100 | **Dataset quality**, benchmark filtering |
| 6 | `inter_crew_edges` | int | ~5 | **Core thesis**, Model 3, enterprise systemic risk |

**Also add:** `total_finding_instances` (int) alongside existing `finding_rule_count`.

**Total: 7 new fields, ~635 bytes per ping, ~30 lines of scanner code.**

**Net schema: ~97 fields per ping (was ~90 in v7).**

---

## What Changes in Existing Artifacts

### sample-usage-ping.json (initial scan)
Add all 7 fields with pre-fix values.

### sample-rescan-ping.json (rescan)  
Add all 7 fields with post-fix values. `fix_impact_estimates` changes because partial credit alters the impact of remaining findings. `finding_instance_counts` drops instances for resolved findings.

### batch-results.json
No changes — batch records are fleet metadata, not per-scan telemetry. The new fields only exist in pings.

### evaluation-summary.json
Add v7.1 section documenting the new fields and their verification checks.

### Terminals
No changes to terminal output for this patch. `fix_impact_estimates` WILL appear in the terminal in a future version (showing "Score impact: -12 points" next to each finding), but that's a display feature, not a telemetry requirement.

---

## Verification Checks for v7.1

| # | Check |
|---|-------|
| S19 | Both pings have `finding_instance_counts` as object with string keys and int values |
| S20 | `total_finding_instances == sum(finding_instance_counts.values())` |
| S21 | All keys in `finding_instance_counts` exist in `finding_rules` |
| S22 | Both pings have `fix_impact_estimates` as object with string keys and negative int values |
| S23 | All keys in `fix_impact_estimates` exist in `finding_rules` |
| S24 | Both pings have `llm_providers` as list of strings |
| S25 | Both pings have `llm_models` as list of strings |
| S26 | Both pings have `framework_versions` as object with string keys and string/null values |
| S27 | Framework names in `framework_versions` exist in batch-results `frameworks` for this repo |
| S28 | Both pings have `deployment_signals` with 5 boolean fields and deployment_score int |
| S29 | `deployment_signals.deployment_score == count of true booleans` |
| S30 | Both pings have `inter_crew_edges` as integer >= 0 |
| S31 | `inter_crew_edges <= graph_edge_count` |
| S32 | Both pings have `total_finding_instances` >= `finding_rule_count` |
