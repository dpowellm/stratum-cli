Read the spec at ./SPEC-CLI-TOXIC-COMBINATIONS.md in full before writing any code.

Then implement everything it describes in the stratum-cli codebase. Specifically:

1. CREATE stratum/data/toxic_combinations.json — the full TC catalog with all 10 TCs (TC-001 through TC-010) defined with complete pattern schemas (nodes, edges, negative_constraints), severity, finding_components, owasp_ids, remediation with framework_specific code for CrewAI and LangGraph. Use the spec's catalog schema exactly.

2. CREATE stratum/graph/toxic_combinations.py — the pattern matcher. Loads the catalog, runs subgraph isomorphism via NetworkX DiGraphMatcher against the scan graph, checks negative constraints, returns sorted TCMatch objects. Follow the spec's implementation closely — it has the full module with _build_template_graph, _make_node_matcher, _make_edge_matcher, _any_negative_constraint_satisfied, _extract_path, _extract_matched_edges.

3. CREATE stratum/graph/export.py — the --export-graph serializer. Writes full graph (nodes, edges, properties, findings, TC matches) to .stratum/graph.json. Privacy contract: no file paths, function names, or code content.

4. MODIFY stratum/scanner.py — after the existing graph build + finding detection steps, add TC matching by calling match_all(scan_graph) from toxic_combinations.py. Compute compound risk score using the formula in the spec (TC_SEVERITY_WEIGHTS, COMPONENT_MULTIPLIER, partial double-count deduction). Pass tc_matches to the output renderer and telemetry profile.

5. MODIFY stratum/output/terminal.py — add the TOXIC COMBINATIONS section after findings, before RISK SUMMARY. Render each TC with severity color, matched path, description, and framework-specific remediation code. Follow the spec's terminal output mockup exactly.

6. MODIFY stratum/telemetry/profile.py — add 6 new fields: tc_count, tc_ids, tc_severities, tc_max_severity, compound_risk_score, compound_risk_delta. Bump schema_id to 6, schema_version to "0.4.0".

7. MODIFY stratum/cli.py — add --export-graph click option (is_flag=True). When set, call graph.export.export_graph() after TC matching and print the output path.

8. ADD the TCMatch dataclass to stratum/models.py if it exists, or to a sensible location.

IMPORTANT IMPLEMENTATION NOTES:
- The scan graph is a NetworkX DiGraph built by stratum/graph/builder.py. Nodes have a "type" or "node_type" attribute. Edges have a "type" or "edge_type" attribute plus properties like has_control, data_sensitivity, trust_crossing.
- The TC pattern matcher must handle type fields being either "type" or "node_type" (check both).
- Pattern node types can be a string OR a list of strings (match any).
- Pattern edge types can be a string OR a list of strings (match any).
- Negative constraints have two forms: edge_on_path (check edges between two nodes) and node+has_guardrail_type (check for guardrail connections).
- compound_risk_score must always be >= base risk_score and <= 100.

After implementing everything, create evaluation files:

CREATE eval/test_toxic_combinations.py — pytest tests for the pattern matcher:
- test_load_catalog: verify catalog loads, has 10 TCs, each has required fields
- test_match_tc_001: build a minimal graph that should trigger TC-001 (unsupervised delegation to credential-exposed worker), verify it matches
- test_no_match_tc_001_with_control: same graph but with has_control=true on delegation edge, verify TC-001 does NOT fire (negative constraint works)
- test_match_tc_002: build graph triggering TC-002 (PII exfiltration through delegation chain)
- test_match_tc_005: build graph triggering TC-005 (EchoLeak inbox-to-outbound)
- test_match_tc_007: build graph triggering TC-007 (blast radius amplification, fan_out >= 3)
- test_no_match_empty_graph: empty graph matches no TCs
- test_no_match_single_agent: single agent with tools, no delegation, should not match delegation-based TCs
- test_multiple_tc_match: build a graph that triggers 2+ TCs simultaneously
- test_match_results_sorted_by_severity: verify CRITICAL comes before HIGH
- test_dedup_same_subgraph: same TC pattern appearing via different isomorphism mappings should be deduped
- test_negative_constraint_hitl_suppresses: verify that adding a HITL guardrail to a worker suppresses TC-001

CREATE eval/test_compound_scoring.py — pytest tests for compound risk scoring:
- test_base_score_unchanged_no_tcs: without TCs, compound score equals base score
- test_compound_score_higher_with_tcs: with TCs, compound score > base score
- test_compound_score_capped_at_100: even with many TCs, score never exceeds 100
- test_compound_score_never_below_base: compound score >= base score always
- test_double_count_deduction: verify partial deduction for overlapping finding components
- test_critical_tc_weight: CRITICAL TC adds 20 base points
- test_component_multiplier: TC with 3 components adds more than TC with 2 components

CREATE eval/test_graph_export.py — pytest tests for graph export:
- test_export_creates_file: verify graph.json is created in output dir
- test_export_schema: verify exported JSON has scan_id, schema_version, graph.nodes, graph.edges, findings, toxic_combinations
- test_export_node_serialization: verify nodes have id, type, properties
- test_export_edge_serialization: verify edges have source, target, type, properties
- test_export_tc_matches_included: verify TC matches appear in export

CREATE eval/test_catalog_schema.py — pytest tests for catalog integrity:
- test_all_tcs_have_unique_ids: no duplicate tc_ids
- test_all_tcs_have_patterns: every TC has nodes, edges in pattern
- test_all_tcs_have_remediation: every TC has remediation with description and effort
- test_all_tcs_have_severity: severity is CRITICAL, HIGH, or MEDIUM
- test_all_tcs_have_finding_components: each TC references valid STRATUM rule IDs
- test_pattern_nodes_have_vars: every pattern node has a var field
- test_pattern_edges_reference_valid_vars: every edge from/to references a defined node var
- test_catalog_version_present: catalog has catalog_version and schema_version fields

Each test file should be self-contained with clear docstrings. Build test graphs using networkx directly — don't depend on the scanner. Example helper:

```python
import networkx as nx

def build_tc001_graph():
    """Build minimal graph that should trigger TC-001."""
    G = nx.DiGraph()
    G.add_node("orch", type="agent")
    G.add_node("worker", type="agent")
    G.add_node("cred_store", type="data_store", data_sensitivity="credentials")
    G.add_edge("orch", "worker", type="delegates_to", has_control=False)
    G.add_edge("cred_store", "worker", type="reads_from")
    return G
```

Output all eval files to the eval/ directory in the project root.
