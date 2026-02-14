# Stratum v7 Patch — Telemetry Schema Hardening for 50k-Repo Scan

**Purpose:** The v6.1 schema was designed around 1 repo and validated against 16. Before scanning 50k repos to build Stratum's enterprise data layer and model training corpus, the telemetry schema needs structural fixes that cannot be retrofitted after collection.

**Principle:** Collect what you can't reconstruct later. Compute what you can at analysis time.

**Non-goals:** No repo_name/repo_url in pings (privacy promise in telemetry banner). No per-agent detail vectors (separate event type if needed). No fix attribution (rescans, not initial scans). No org_id (product feature, not data requirement). No real-time streaming (batch is fine for 50k).

---

## The Six Structural Problems

### P1: Pings Are Anonymous

The ping has `scan_id` (random) and `topology_signature_hash` (architecture fingerprint). Neither identifies which repo was scanned. `topology_signature_hash` is deliberately a content hash — two repos with identical agent graphs produce the same value.

At 50k repos: 50k JSON objects with no way to join back to repos without a separate mapping table that doesn't exist in the schema.

### P2: No Failure Tracking

If the scanner fails on a repo, no ping is emitted. At 50k repos, 5-10% will fail or produce empty results (no Python, parser crash, no agents detected). These silent drops create survivorship bias — the dataset only represents well-structured repos, and the messy repos that would teach us the most about parser limitations vanish.

### P3: Fleet Data in Per-Repo Pings

`provider_confidence_breakdown` sums to 16 (the fleet size). It's fleet-level aggregate data embedded in a per-repo event. At 50k repos, every ping carries the same values — 50k copies of identical data that goes stale when the fleet changes. `progress_card_shown` is UI display state, not repo telemetry.

### P4: No Normalized Features

`agent_count=56` with `finding_severities={CRITICAL:4}` and `agent_count=2` with `finding_severities={CRITICAL:4}` look identical to a model but represent vastly different risk profiles. ML needs features that are comparable across repos of different sizes. The intermediate values needed to compute ratios (total tool count, total finding count) aren't all in the ping.

### P5: Coarse Topology Features

`graph_node_count=92`, `graph_edge_count=93`, `edge_density=0.011` — three numbers describing a 92-node graph. A hub-spoke architecture and a linear pipeline can produce the same values but have completely different risk profiles. Architecture classification (Model 3) requires graph-theoretic features that distinguish topological patterns.

### P6: No Schema Evolution Strategy

`schema_version="0.2"` is a string with no migration tracking. When fields are added mid-collection (inevitable), `null` becomes ambiguous: old schema (field didn't exist), new schema (repo had no data), or partial scan (field wasn't populated). At 50k rows this ambiguity breaks every downstream analysis.

---

## Schema Changes

### TIER 1: Pipeline Integrity (must-have, blocks 50k scan)

These fields prevent data loss and corruption at scale.

#### Add: `repo_hash` (string)
```json
"repo_hash": "22e1d1b5ef859fb4"
```
The anonymized repo identifier already computed for batch-results. This is NOT repo_name (privacy). It's a deterministic hash of repo content, so rescanning the same repo produces the same hash. This is the **primary join key** across all Stratum data.

#### Add: `scan_status` (enum string)
```json
"scan_status": "success"
```
Values:
- `"success"` — full scan completed, all parseable files processed
- `"partial"` — scan completed but some files failed parsing (results valid but incomplete)
- `"failed"` — scan could not complete (ping contains metadata only, no findings/topology)
- `"empty"` — scan completed but no agents detected (repo is a library, not an application, or uses unsupported framework)

**Critical:** The scanner MUST emit a ping even for `"failed"` and `"empty"` repos. Silent drops create survivorship bias.

#### Add: `scan_duration_ms` (integer)
```json
"scan_duration_ms": 1247
```
Wall-clock time from scan start to ping emission. At 50k repos, this identifies parser performance cliffs (repos that take 30s vs 300ms) and pipeline bottlenecks.

#### Add: `files_scanned` / `files_total` (integers)
```json
"files_scanned": 94,
"files_total": 116
```
`files_total` is all files in the repo. `files_scanned` is files the parser successfully processed. The ratio `files_scanned/files_total` is the **coverage denominator** — what fraction of the codebase was actually analyzed. A scan that only covered 20% of files has low confidence regardless of risk score.

#### Add: `parser_errors` (integer)
```json
"parser_errors": 3
```
Count of files where AST parsing failed (syntax errors, encoding issues, files too large). Combined with `files_scanned`, this tells you parse failure rate.

#### Add: `schema_id` (integer)
```json
"schema_id": 3
```
Integer that increments on every schema change. Replaces `schema_version` as the primary version indicator. Analysis code can filter `WHERE schema_id >= 3` to get only pings with a specific field guaranteed present.

Schema changelog:
- `1` = v5 schema (34 fields)
- `2` = v6.1 schema (v5 + finding_coverages, severity_downgrades, crews_clean, crews_with_findings)
- `3` = v7 schema (this patch)

`schema_version` stays as a human-readable string (`"0.3.0"`) but `schema_id` is the machine-readable version.

### TIER 2: Model Training Features (must-have, enables all 4 models)

These fields make the data ML-ready.

#### Add: `finding_count` (integer)
```json
"finding_count": 18
```
Total finding count. Currently only derivable by summing `finding_severities` values. Every ML pipeline will need this as a first-class feature.

#### Add: `total_tool_count` (integer)
```json
"total_tool_count": 30
```
Total unique tools detected across all agents. Required for `tools_per_agent` ratio and for understanding tool proliferation.

#### Add: `normalized_features` (object)
```json
"normalized_features": {
  "findings_per_agent": 0.32,
  "findings_per_crew": 0.60,
  "guardrails_per_agent": 0.23,
  "tools_per_agent": 0.54,
  "external_exposure_ratio": 0.60,
  "guardrail_coverage_ratio": 0.72
}
```
Pre-computed ratios that are comparable across repos of different sizes. These are the features that distinguish "large well-managed system" (low findings_per_agent) from "small dangerous system" (high findings_per_agent).

Definitions:
- `findings_per_agent`: finding_count / agent_count (0 if agent_count=0)
- `findings_per_crew`: finding_count / crew_count (0 if crew_count=0)
- `guardrails_per_agent`: guardrail_count / agent_count
- `tools_per_agent`: total_tool_count / agent_count
- `external_exposure_ratio`: external capabilities / total_capabilities
- `guardrail_coverage_ratio`: guardrail_linked_count / finding_count (what fraction of findings have a guardrail that addresses them)

#### Add: `graph_topology_metrics` (object)
```json
"graph_topology_metrics": {
  "diameter": 6,
  "avg_degree": 2.02,
  "max_degree": 12,
  "clustering_coefficient": 0.03,
  "connected_components": 5,
  "longest_chain": 4,
  "hub_score": 0.15
}
```
Standard graph-theoretic features computed from the agent topology graph. These are what distinguish architectures:

- `diameter`: longest shortest path between any two nodes. High = deep pipeline. Low = hub-spoke.
- `avg_degree`: mean connections per node. High = mesh/dense. Low = linear.
- `max_degree`: highest connection count on any single node. High = central hub exists.
- `clustering_coefficient`: transitivity measure. High = tightly clustered crews. Low = sparse tree.
- `connected_components`: number of disconnected subgraphs. Equals crew count if crews don't share resources.
- `longest_chain`: longest sequential agent chain without branching. Measures pipeline depth.
- `hub_score`: max_degree / graph_node_count. >0.3 = hub-spoke pattern. <0.05 = no clear hub.

All computable with networkx in O(n²), which is fast for agent graphs (typically <200 nodes).

#### Add: `crew_size_distribution` (list of integers)
```json
"crew_size_distribution": [4, 4, 3, 3, 2, 2, 2, 1, 1, 1]
```
Sorted descending list of agent counts per crew. This is the input to architecture classification — a crew_size_distribution of [20, 1, 1, 1] looks very different from [5, 5, 5, 5].

#### Add: `agent_tool_count_distribution` (list of integers)
```json
"agent_tool_count_distribution": [5, 4, 4, 3, 3, 2, 2, 1, 1, 0, 0]
```
Sorted descending list of tool counts per agent. Agents with 0 tools are pure orchestrators. Agents with 5+ tools are high-capability workers. The distribution shape is a strong architecture signal.

#### Add: `repo_metadata` (object)
```json
"repo_metadata": {
  "python_file_count": 94,
  "yaml_config_count": 12,
  "total_loc": 8400,
  "primary_framework": "CrewAI",
  "framework_count": 3
}
```
Repo-level metadata for benchmarking bucketing ("repos like yours"). NOT repo_name or repo_url.

- `python_file_count`: Python files found (the scanner's input surface)
- `yaml_config_count`: YAML files that contain agent/crew config (CrewAI pattern)
- `total_loc`: total lines of code in scanned files (size bucket)
- `primary_framework`: most-detected framework (for benchmarking group)
- `framework_count`: number of distinct frameworks detected (multi-framework = higher complexity)

### TIER 3: Finding Intelligence (important, enables Models 2 & 3)

#### Add: `finding_rule_count` (integer)
```json
"finding_rule_count": 18
```
Count of unique finding rules that fired. `finding_rules` stays as the list (for human analysis), but models need the numeric feature.

#### Add: `finding_co_occurrence` (list of [string, string] pairs)
```json
"finding_co_occurrence": [
  ["STRATUM-001", "STRATUM-CR05"],
  ["STRATUM-001", "STRATUM-CR06"],
  ["STRATUM-CR05", "STRATUM-CR05.1"],
  ["STRATUM-CR05", "STRATUM-CR05.2"]
]
```
Pairs of findings that co-occur **within the same crew**. At 50k repos, this becomes an association-rule dataset: "If a crew has STRATUM-CR05, there's a 73% probability it also has STRATUM-001." This powers finding prediction (Model 2).

Only include pairs where both findings fire in at least one shared crew. Global co-occurrence (both fire in the same repo) is less interesting — crew-level co-occurrence reveals architectural patterns.

#### Add: `per_crew_finding_density` (object)
```json
"per_crew_finding_density": {
  "max": 6,
  "min": 0,
  "mean": 2.1,
  "median": 2,
  "stddev": 1.8
}
```
Summary statistics of finding counts per crew. High variance means risk is concentrated in a few crews. Low variance means uniform risk. This is the "blast radius" signal at the fleet level.

### REMOVE: 2 Fields

#### Remove: `provider_confidence_breakdown`
Fleet-level aggregate (sums to fleet size, not repo size). At 50k repos, every ping has identical values. Per-repo provider confidence already exists in batch-results as `provider_confidence` (string: detected/inferred_env_var/inferred_framework/unknown).

**Replacement:** Add `provider_confidence` (string) to the ping itself:
```json
"provider_confidence": "inferred_env_var"
```
This is the per-repo value, not the fleet aggregate.

#### Remove: `progress_card_shown`
UI display state, not repo telemetry. Whether the terminal showed a progress card depends on the CLI version and display mode, not the repo's risk profile. This field has zero predictive value for any model and zero analytical value for the enterprise product.

### MODIFY: 2 Fields

#### Modify: `schema_version`
```
BEFORE: "schema_version": "0.2"
AFTER:  "schema_version": "0.3.0"
```
Human-readable version string updated. `schema_id: 3` is the machine-readable version.

#### Modify: Rescan pings add `pre_scan_id`
```json
"pre_scan_id": "4cde4df6"
```
For rescan pings only (`is_rescan: true`). Explicit foreign key to the prior scan. `prev_score` alone is ambiguous at scale — many repos can share the same score.

---

## Complete Field Inventory (v7)

### New fields (Tier 1 — pipeline): 6
| Field | Type | Example |
|-------|------|---------|
| `repo_hash` | string | `"22e1d1b5ef859fb4"` |
| `scan_status` | enum | `"success"` |
| `scan_duration_ms` | int | `1247` |
| `files_scanned` | int | `94` |
| `files_total` | int | `116` |
| `parser_errors` | int | `3` |

### New fields (Tier 1 — versioning): 1
| Field | Type | Example |
|-------|------|---------|
| `schema_id` | int | `3` |

### New fields (Tier 2 — ML features): 7
| Field | Type | Example |
|-------|------|---------|
| `finding_count` | int | `18` |
| `total_tool_count` | int | `30` |
| `normalized_features` | object | `{findings_per_agent: 0.32, ...}` |
| `graph_topology_metrics` | object | `{diameter: 6, ...}` |
| `crew_size_distribution` | [int] | `[4, 4, 3, 2, 1]` |
| `agent_tool_count_distribution` | [int] | `[5, 4, 3, 2, 1]` |
| `repo_metadata` | object | `{python_file_count: 94, ...}` |

### New fields (Tier 3 — finding intelligence): 3
| Field | Type | Example |
|-------|------|---------|
| `finding_rule_count` | int | `18` |
| `finding_co_occurrence` | [[str,str]] | `[["STRATUM-001","CR05"]]` |
| `per_crew_finding_density` | object | `{max: 6, min: 0, mean: 2.1}` |

### New fields (replacements): 1
| Field | Type | Example |
|-------|------|---------|
| `provider_confidence` | string | `"inferred_env_var"` |

### New fields (rescan only): 1
| Field | Type | Example |
|-------|------|---------|
| `pre_scan_id` | string | `"4cde4df6"` |

### Removed fields: 2
| Field | Reason |
|-------|--------|
| `provider_confidence_breakdown` | Fleet-level aggregate in per-repo ping |
| `progress_card_shown` | UI display state, not telemetry |

### Modified fields: 1
| Field | Before | After |
|-------|--------|-------|
| `schema_version` | `"0.2"` | `"0.3.0"` |

**Net change:** +19 new fields, -2 removed, +1 modified = 17 net new fields.
**Total fields per ping:** ~90 (was ~73).

---

## Validation Plan

Before running the 50k scan, validate the v7 schema against the existing 16 repos. Every repo must produce a valid ping. Specific checks:

### Schema integrity (S1-S7)
- S1: Every ping has `repo_hash` that matches batch-results
- S2: `scan_status` is one of the 4 enum values for all 16 repos
- S3: `files_scanned <= files_total` for all pings
- S4: `schema_id == 3` on all pings
- S5: `finding_count == sum(finding_severities.values())` for all pings
- S6: `normalized_features.findings_per_agent == finding_count / agent_count` (within float tolerance)
- S7: No ping contains `provider_confidence_breakdown` or `progress_card_shown`

### ML readiness (S8-S12)
- S8: `graph_topology_metrics.diameter >= 1` for all repos with agents
- S9: `graph_topology_metrics.connected_components >= 1` for all repos with agents
- S10: `len(crew_size_distribution) == crew_count` for all pings
- S11: `len(agent_tool_count_distribution) == agent_count` for all pings
- S12: `finding_co_occurrence` pairs reference only rules in `finding_rules`

### Failure handling (S13-S15)
- S13: Simulate a parser failure on 1 repo → ping emitted with `scan_status: "partial"`
- S14: Simulate a repo with 0 agents → ping emitted with `scan_status: "empty"`, `finding_count: 0`
- S15: `scan_duration_ms > 0` for all pings

### Backward compatibility (S16-S18)
- S16: All v6.1 V-checks (V1-V16) still pass
- S17: All v6.1 M-checks (M1-M18) still pass
- S18: `schema_version == "0.3.0"` and `schema_id == 3`

---

## Implementation Notes

**Graph metrics** require the agent topology graph to be available at ping emission time. The scanner already builds this graph (it's used for `graph_node_count`, `graph_edge_count`, `edge_density`). Adding networkx metrics is ~15 lines of code:
```python
import networkx as nx
G = build_topology_graph(scan_result)
metrics = {
    "diameter": nx.diameter(G) if nx.is_connected(G) else max(nx.diameter(nx.subgraph(G, c)) for c in nx.connected_components(G)),
    "avg_degree": sum(dict(G.degree()).values()) / G.number_of_nodes(),
    "max_degree": max(dict(G.degree()).values()),
    "clustering_coefficient": nx.transitivity(G),
    "connected_components": nx.number_connected_components(G),
    "longest_chain": nx.dag_longest_path_length(G) if nx.is_directed_acyclic_graph(G) else -1,
    "hub_score": max(dict(G.degree()).values()) / G.number_of_nodes()
}
```

**Finding co-occurrence** requires per-crew finding lists, which the scanner already computes (used for per-crew scores). Extracting co-occurrence pairs is:
```python
from itertools import combinations
co_occur = set()
for crew in crews_with_findings:
    crew_findings = get_findings_for_crew(crew)
    for a, b in combinations(sorted(crew_findings), 2):
        co_occur.add((a, b))
```

**Normalized features** are trivial divisions with zero-guards.

**repo_metadata** requires counting files and LOC during the initial file scan phase, which already walks the directory tree.

**Estimated effort:** 1-2 days for the scanner changes. The artifact generation (sample pings, batch results, eval) is a separate step using the same Claude Code workflow.

---

## What This Enables

After the 50k scan with v7 schema:

**Immediate analysis (no model needed):**
- "73% of LangChain repos have STRATUM-001 (no HITL). Industry-wide gap."
- "Repos with crew_count > 10 have 3.2x higher finding density than single-crew repos."
- "Hub-spoke architectures (hub_score > 0.3) have 40% fewer findings than mesh architectures."
- "OpenAI is the sole provider for 61% of scanned repos. Anthropic: 12%."

**Model 1 — Risk Benchmarking (supervised, tabular):**
- Features: `normalized_features.*`, `graph_topology_metrics.*`, `repo_metadata.*`
- Label: `risk_score`
- Bucketing: `primary_framework` × `agent_count_bucket`
- Output: "Your LangChain repo with 5 agents scores 72. Median for this bucket: 45. You're in the 89th percentile."

**Model 2 — Finding Prediction (multi-label classification):**
- Features: `graph_topology_metrics.*`, `capability_distribution`, `crew_size_distribution`
- Labels: `finding_rules` (binary vector)
- Training signal: `finding_co_occurrence` for association rules
- Output: "Your architecture pattern has 78% correlation with STRATUM-CR05 (shared tool blast radius). We recommend scanning for this even though it wasn't detected."

**Model 3 — Architecture Classification (unsupervised clustering):**
- Features: `graph_topology_metrics.*`, `crew_size_distribution`, `agent_tool_count_distribution`, `archetype_class`
- Method: k-means or DBSCAN on topology feature vectors
- Output: 5-8 canonical architecture types with names, risk profiles, and common findings.
- `archetype_class` (currently rule-based) becomes a validation label for the learned clusters.

**Model 4 — Provider Concentration (aggregation + anomaly detection):**
- Features: per-repo `llm_providers` + `provider_confidence` + `repo_metadata.primary_framework`
- Aggregation: fleet-level concentration by framework, by org, by architecture type
- Output: "67% of your fleet depends on OpenAI. If OpenAI has a 4-hour outage, these 134 repos are affected."
