# Schema Diff: Pre vs Post Reliability Scanner

## Summary

The reliability scanner extends the existing Stratum schema from `schema_id: 7` to `schema_id: 8`. All changes are additive — no existing fields or behavior were removed.

## Node Types

| Node Type | Pre | Post | Change |
|---|---|---|---|
| CAPABILITY | Yes | Yes | New fields: `reversibility`, `subtype`, `regulatory_category`, `external_service`, `data_mutation`, `human_visible`, `idempotent` |
| DATA_STORE | Yes | Yes | New fields: `concurrency_control`, `sensitivity`, `persistence`, `access_pattern`, `schema_defined`, `contains_pii`, `freshness_mechanism`, `store_domain` |
| MCP_SERVER | Yes | Yes | No change |
| EXTERNAL_SERVICE | Yes | Yes | No change |
| GUARDRAIL | Yes | Yes | No change |
| AGENT | Yes | Yes | New fields: `makes_decisions`, `error_handling_pattern`, `objective_tag`, `domain`, `betweenness_centrality`, `closeness_centrality`, `pagerank`, `delegation_enabled`, `human_input_enabled`, `llm_model`, `temperature`, `output_schema`, `memory_enabled`, `implicit_authority`, `shared_state_conflicts` |
| OBSERVABILITY_SINK | No | Yes | **NEW** — logging, monitoring, audit trail sinks |

## Edge Types

| Edge Type | Pre | Post | Change |
|---|---|---|---|
| READS_FROM | Yes | Yes | New fields: `purpose_limited` |
| WRITES_TO | Yes | Yes | No change |
| SENDS_TO | Yes | Yes | No change |
| CALLS | Yes | Yes | No change |
| SHARES_WITH | Yes | Yes | No change |
| FILTERED_BY | Yes | Yes | No change |
| GATED_BY | Yes | Yes | No change |
| TOOL_OF | Yes | Yes | No change |
| DELEGATES_TO | Yes | Yes | No change |
| FEEDS_INTO | Yes | Yes | New fields: `schema_validated`, `preserves_uncertainty` |
| SHARES_TOOL | Yes | Yes | No change |
| OBSERVED_BY | No | Yes | **NEW** — agent → observability sink |
| RATE_LIMITED_BY | No | Yes | **NEW** — agent → rate limiter |
| ARBITRATED_BY | No | Yes | **NEW** — agent → arbiter |
| APPROVAL_REQUIRED | No | Yes | **NEW** — agent → approval gate |
| TASK_SEQUENCE | No | Yes | **NEW** — task execution ordering |
| IMPLICIT_AUTHORITY_OVER | No | Yes | **NEW** — computed: agent → transitive capability |
| ERROR_PROPAGATION_PATH | No | Yes | **NEW** — computed: error flow between agents |
| ERROR_BOUNDARY | No | Yes | **NEW** — computed: error handling scope boundary |
| SHARED_STATE_CONFLICT | No | Yes | **NEW** — computed: multi-agent write contention |

## New Dataclasses

### StructuredFinding (reliability/schema.py)
```python
@dataclass
class StructuredFinding:
    finding_id: str       # "STRAT-DC-001"
    name: str
    category: str         # DC/OC/SI/EA/AB
    severity: str
    description: str
    structural_evidence: dict
    nodes_involved: list[str]
    edges_involved: list[str]
    subgraph_type: str    # "path"|"pair"|"cycle"|"node"|"transitive_closure"|"global"
    primary_node: str | None
    runtime_confirmation: dict
```

### GlobalMetrics (reliability/schema.py)
35 fields across 8 categories: Scale (6), Topology (5), Control Coverage (4), Risk Surface (5), Error Handling (4), Concentration (4), Feedback/Loops (2), Data Integrity (2).

### AgentMetrics (reliability/schema.py)
10 per-node fields: betweenness_centrality, closeness_centrality, pagerank, delegation_depth_downstream, critical_capabilities_reachable, implicit_authorities, guardrail_count, observability_count, error_blast_radius.

### GraphMotif (reliability/schema.py)
For novel pattern detection: motif_id (canonical hash), node_types, edge_types, edge_pairs, instances, instance_node_ids, enrichment_summary.

### ObservationPointSpec (reliability/schema.py)
Runtime instrumentation recommendations: priority, node_id, rationale, preconditions_at_this_node, structural_risk_score, recommended_observations.

### ReliabilityScanOutput (reliability/schema.py)
Complete output per repo: repo_id, framework, scan_timestamp, scanner_version, schema_id=8, graph, structural_metrics, preconditions, compositions, structural_anomalies, graph_motifs, observation_points, security_risk_score, reliability_risk_score, gap_classification, security_findings.

## ScanResult Extensions (models.py)

| Field | Pre | Post |
|---|---|---|
| `reliability_findings` | No | `list[Finding]` — Bucket A reliability findings |
| `composite_findings` | No | `list[Finding]` — STRAT-COMP + STRAT-XCOMP compositions |
| `reliability_score` | No | `int` — 0-100 reliability risk score |
| `reliability_metrics` | No | `dict` — GlobalMetrics as dict |
| `per_node_metrics` | No | `list[dict]` — AgentMetrics per agent |
| `observation_points` | No | `list[dict]` — Observation point recommendations |
| `graph_motifs` | No | `list[dict]` — Structural motifs |
| `repo_profile` | No | `dict` — Aggregate repo profile |

## CLI Extensions

| Flag | Pre | Post |
|---|---|---|
| `--reliability` | No | Yes — Include reliability findings |
| `--security-only` | No | Yes — Disable reliability, schema_id 7 output |
| `--output-dir` | No | Yes — Write ReliabilityScanOutput to `<dir>/graphs/<repo_id>.json` |

## JSON Output Schema Changes

When `--reliability` is active (or auto-enabled for multi-agent projects):

```json
{
  "schema_id": 8,  // was 5-7
  "reliability": {
    "findings": [...],
    "composite_findings": [...],
    "score": 68,
    "metrics": { /* GlobalMetrics */ },
    "observation_points": [...]
  },
  "repo_profile": { /* gap_classification, risk_scores */ }
}
```

When `--security-only`: output matches schema_id 7 exactly, no reliability fields.

## Risk Score Formula

**Pre (security):** Asymptotic normalization `raw / (raw + K) * 100` with class-weighted findings.

**Post (reliability):** Linear sum capped at 100:
- CRITICAL * 25, HIGH * 15, MEDIUM * 8, LOW * 3
- +10 per STRAT-COMP composition, +15 per STRAT-XCOMP composition
- +3 per topological anomaly

## Gap Classification (NEW)

```
threshold = 30
both_clean:                        sec <= 30 AND rel <= 30
security_clean_reliability_poor:   sec <= 30 AND rel > 30  (THE BLIND SPOT)
security_poor_reliability_clean:   sec > 30 AND rel <= 30
both_poor:                         sec > 30 AND rel > 30
```
