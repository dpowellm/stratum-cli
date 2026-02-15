# Codebase Map: Spec Concepts to Implementation

## Directory Structure

```
stratum-cli/stratum/
├── reliability/           # Reliability scanner (core innovation)
│   ├── schema.py          # StructuredFinding, GlobalMetrics, AgentMetrics, GraphMotif, ReliabilityScanOutput
│   ├── enrichment.py      # Phase 5: Graph enrichment (8 passes)
│   ├── traversals.py      # Phase 4: 5 traversal primitives (PATH, PAIR, CYCLE, CENTRALITY, TRANSITIVE)
│   ├── engine.py          # Phase 7: 27 Bucket A + 2 partial Bucket B finding rules
│   ├── composition.py     # Phase 8: 7 COMP + 6 XCOMP tables
│   ├── metrics_compute.py # Phase 6: ~35 global + 10 per-node metrics + risk score + gap classification
│   ├── anomalies.py       # Phase 9: Z-scores + 7 topological anomalies + motif extraction
│   ├── observations.py    # Phase 9: 5-category observation point generation
│   └── config.py          # Phase 11: .stratum.yml Bucket B bridge
├── graph/
│   ├── models.py          # NodeType (7), EdgeType (17+), GraphNode, GraphEdge, RiskGraph
│   ├── builder.py         # Graph construction from ScanResult
│   ├── traversal.py       # Security traversals (blast radii, control bypasses)
│   ├── toxic_combinations.py # TC matching via subgraph isomorphism
│   ├── agents.py          # Agent/crew extraction from YAML/Python
│   └── export.py          # Graph serialization
├── parsers/
│   ├── capabilities.py    # AST-based capability detection
│   ├── agents.py          # Crew/agent definition extraction
│   ├── langgraph_parser.py # LangGraph state machine parsing
│   ├── langchain_parser.py # LangChain agent parsing
│   └── surfaces.py        # LLM model, env var, vector store detection
├── rules/                 # Security finding rules (existing)
├── output/
│   ├── terminal.py        # Rich terminal rendering + reliability section + dual-axis summary
│   ├── action_groups.py   # Finding-to-action grouping
│   ├── flow_map.py        # ASCII flow maps
│   └── sarif.py           # SARIF output
├── telemetry/
│   ├── profile.py         # ScanProfile aggregation
│   ├── ping.py            # v7.2 telemetry ping (schema_id 5 base, 8 with reliability)
│   └── history.py         # Scan history/delta
├── stratum_core/
│   └── schema.py          # Canonical schema: all IDs, categories, edge types
├── cli.py                 # Click CLI entry point (--reliability, --security-only, --output-dir)
├── scanner.py             # Orchestrator: parsers → graph → reliability → output
└── models.py              # Core data models: Capability, Finding, ScanResult
```

## Spec Section to File Mapping

| Spec Section | Concept | File(s) |
|---|---|---|
| Section 3 | Three-Layer Architecture | `scanner.py` (orchestration), `reliability/enrichment.py` (Layer 2), `reliability/engine.py` (Layer 3) |
| Section 4 | Node Types & Edge Types | `graph/models.py` (NodeType, EdgeType enums + GraphNode/GraphEdge dataclasses) |
| Section 5 | Edge Type Extensions | `graph/models.py` (GraphEdge fields), `graph/builder.py` (edge construction) |
| Section 6 | Enrichment Layer | `reliability/enrichment.py` (8 passes: capabilities, agents, data stores, observability sinks, edge metadata, implicit authority, error boundaries, shared state conflicts) |
| Section 7 | Structural Metrics | `reliability/metrics_compute.py` (~35 GlobalMetrics, 10 AgentMetrics), `reliability/schema.py` (dataclasses) |
| Section 8 | Traversal Primitives | `reliability/traversals.py` (find_paths, find_pairs_shared_state, detect_cycles, compute_centrality, compute_transitive_capabilities) |
| Section 9 | Taxonomy Preconditions | `reliability/engine.py` (27 Bucket A rules across DC/OC/SI/EA/AB + 2 partial Bucket B) |
| Section 10 | Compositions | `reliability/composition.py` (7 STRAT-COMP + 6 STRAT-XCOMP tables) |
| Section 11 | Anomaly Detection | `reliability/anomalies.py` (z-scores, 7 topological types, motif extraction) |
| Section 12 | Observation Points | `reliability/observations.py` (5 categories: decision_audit, error_boundary, volume_monitoring, schema_validation, authority_audit) |
| Section 13 | Output Format | `reliability/schema.py` (ReliabilityScanOutput dataclass, schema_id=8) |
| Section 14 | Terminal Output | `output/terminal.py` (_render_reliability_section, _render_dual_axis_summary) |
| Section 15 | Telemetry Integration | `cli.py` (schema_id 8 injection), `telemetry/ping.py` |
| Section 16-P1 | Schema Extensions | `graph/models.py` (new fields), `reliability/schema.py` (new dataclasses) |
| Section 16-P5 | Enrichment | `reliability/enrichment.py` |
| Section 16-P6 | Metrics | `reliability/metrics_compute.py` |
| Section 16-P7 | Finding Rules | `reliability/engine.py` |
| Section 16-P8 | Compositions | `reliability/composition.py` |
| Section 16-P9 | Anomalies + Obs | `reliability/anomalies.py`, `reliability/observations.py` |
| Section 16-P10 | Integration | `scanner.py` (pipeline wiring), `cli.py` (flags + output-dir) |
| Section 16-P11 | .stratum.yml | `reliability/config.py` |

## Pipeline Flow (scanner.py)

```
scan(path)
  → parsers (capabilities, agents, env, MCP, frameworks)
  → build_graph(result)
  → RELIABILITY PIPELINE:
      1. enrich_graph(graph, py_files)           # enrichment.py
      2. load_stratum_config / apply_config       # config.py
      3. evaluate(graph)                          # engine.py — 27 Bucket A rules
      4. run_compositions(sec, rel)               # composition.py — 7 COMP + 6 XCOMP
      5. compute_global_metrics / per_node        # metrics_compute.py
      6. detect_structural_anomalies(graph)       # anomalies.py — 7 topological + z-scores
      6b. extract_motifs(graph)                   # anomalies.py — novel pattern detection
      7. generate_observation_points(graph, all)  # observations.py
      8. compute_risk_score(findings, comps, anomalies)
      9. build_repo_profile(graph, sec, rel, comp)
  → blast_radii, control_bypasses
  → security rules (business, operational, compounding)
  → risk_score normalization
  → toxic_combinations
  → incident_matches
  → return ScanResult
```

## Finding Categories

| Category | ID Prefix | Count | Engine Function Pattern |
|---|---|---|---|
| Decision Chain Risk | STRAT-DC-* | 8 | `_dc001_*` through `_dc008_*` |
| Objective Conflict | STRAT-OC-* | 4 (2A+2B) | `_oc001_*` through `_oc004_*` |
| Signal Integrity | STRAT-SI-* | 7 | `_si001_*` through `_si007_*` |
| Emergent Authority | STRAT-EA-* | 5 | `_ea001_*`, `_ea002_*`, `_ea003_*`, `_ea004_*`, `_ea006_*` |
| Aggregate Behavioral | STRAT-AB-* | 5 | `_ab001_*`, `_ab003_*`, `_ab004_*`, `_ab006_*`, `_ab007_*` |
