# Stratum Telemetry Schema v0.3.2 (schema_id: 5)

Comprehensive data dictionary for Stratum telemetry pings. Each scan produces one ping; rescans include additional fields. No source code, file paths, or secrets are collected.

## Identity & Versioning

| Field | Type | Description | Example | Nullable | Since |
|-------|------|-------------|---------|----------|-------|
| scan_id | string | Unique identifier for this scan | `"4cde4df6"` | No | v5 |
| timestamp | string | ISO 8601 timestamp of scan completion | `"2026-02-14T01:20:26.853535+00:00"` | No | v5 |
| scanner_version | string | CLI version that produced this ping | `"0.3.1"` | No | v7.2 |
| repo_hash | string | Anonymized hash of the repository path | `"a1b2c3d4e5f6a7b8"` | No | v7 |
| schema_id | int | Machine-readable schema version integer | `5` | No | v7 |
| schema_version | string | Human-readable schema version string | `"0.3.2"` | No | v5 |

## Scan Metadata

| Field | Type | Description | Example | Nullable | Since |
|-------|------|-------------|---------|----------|-------|
| scan_status | string | Outcome of the scan: "success" or "failure" | `"success"` | No | v7 |
| scan_duration_ms | int | Wall-clock time of the scan in milliseconds | `1247` | No | v7 |
| files_scanned | int | Number of files successfully parsed | `116` | No | v7 |
| files_total | int | Total files discovered in the repository | `116` | No | v7 |
| parser_errors | int | Number of files that failed to parse | `0` | No | v7 |
| failure_reason | string | Error message if scan_status is "failure" | `null` | Yes | v7.1 |

## Rescan Fields

These fields are only present on rescan pings (is_rescan=true).

| Field | Type | Description | Example | Nullable | Since |
|-------|------|-------------|---------|----------|-------|
| is_rescan | bool | Whether this scan is a rescan of a previously scanned repo | `true` | No | v5 |
| prev_score | int | Risk score from the previous scan | `69` | No | v5 |
| score_delta | int | Change in risk score (negative = improvement) | `-14` | No | v5 |
| resolved_count | int | Number of findings resolved since last scan | `3` | No | v5 |
| new_count | int | Number of new findings since last scan | `0` | No | v5 |
| pre_scan_id | string | scan_id of the previous scan this rescan compares against | `"4cde4df6"` | No | v7 |

## Architecture

| Field | Type | Description | Example | Nullable | Since |
|-------|------|-------------|---------|----------|-------|
| agent_count | int | Total number of agents detected across all crews | `56` | No | v5 |
| crew_count | int | Number of crews (agent groups) detected | `30` | No | v5 |
| frameworks | list[string] | All detected frameworks in the repository | `["CrewAI", "LangChain", "LangGraph"]` | No | v7.2 |
| framework_versions | object | Detected framework versions; values may be null if version unknown | `{"CrewAI": "0.80.0", "LangChain": "0.3.7", "LangGraph": "0.2.44"}` | No | v7.1 |
| archetype_class | string | High-level architecture classification | `"multi_agent_orchestrator"` | No | v5 |
| total_capabilities | int | Total number of tool capabilities across all agents | `30` | No | v5 |
| capability_distribution | object | Breakdown of capabilities by type | `{"outbound": 18, "data_access": 11, "destructive": 1}` | No | v5 |
| trust_level_distribution | object | Count of capabilities by trust level | `{"external": 18, "internal": 12}` | No | v5 |
| trust_crossings | object | Count of trust boundary crossings by direction | `{"external→internal": 216}` | No | v5 |
| total_trust_crossings | int | Total number of trust boundary crossings | `216` | No | v5 |
| topology_signature_hash | string | Hash of the agent-tool topology for change detection | `"f9e0f129986fd183"` | No | v5 |
| trust_crossing_adjacency | object | Bidirectional trust crossing counts | `{"external→internal": 216, "internal→external": 216}` | No | v5 |

## Graph Topology

| Field | Type | Description | Example | Nullable | Since |
|-------|------|-------------|---------|----------|-------|
| graph_node_count | int | Total nodes in the agent-tool-data graph | `92` | No | v5 |
| graph_edge_count | int | Total edges in the agent-tool-data graph | `93` | No | v5 |
| graph_node_type_distribution | object | Node counts by type (agent, capability, external, data_store, guardrail) | `{"capability": 14, "external": 6, "data_store": 4, "guardrail": 12, "agent": 56}` | No | v5 |
| graph_edge_type_distribution | object | Edge counts by type (sends_to, reads_from, writes_to, etc.) | `{"sends_to": 6, "reads_from": 7, "writes_to": 1, ...}` | No | v5 |
| edge_density | float | Graph edge density: edges / (nodes * (nodes-1)) | `0.0111` | No | v5 |
| graph_topology_metrics | object | Graph-theoretic metrics (diameter, clustering, etc.) | `{"diameter": 6, "avg_degree": 2.02, "max_degree": 12, ...}` | No | v7 |
| crew_size_distribution | list[int] | Sorted list of agents-per-crew counts (descending) | `[4, 4, 3, 3, 3, 2, 2, ...]` | No | v7 |
| agent_tool_count_distribution | list[int] | Sorted list of tools-per-agent counts (descending) | `[5, 5, 4, 4, 4, 3, 3, ...]` | No | v7 |
| inter_crew_edges | int | Number of edges connecting agents in different crews | `4` | No | v7.1 |

## Findings

| Field | Type | Description | Example | Nullable | Since |
|-------|------|-------------|---------|----------|-------|
| finding_rule_count | int | Number of unique finding rules that fired | `18` | No | v7 |
| finding_rules | list[string] | List of unique finding rule IDs that fired | `["CONTEXT-001", "STRATUM-001", ...]` | No | v5 |
| finding_severities | object | Count of findings by severity level | `{"CRITICAL": 4, "HIGH": 5, "MEDIUM": 8, "LOW": 1}` | No | v5 |
| finding_confidences | object | Count of findings by confidence level | `{"confirmed": 12, "probable": 6}` | No | v5 |
| finding_instance_counts | object | Number of instances per finding rule | `{"STRATUM-001": 20, "STRATUM-002": 8, ...}` | No | v7.1 |
| total_finding_instances | int | Total count of all finding instances across all rules | `94` | No | v7.1 |
| fix_impact_estimates | object | Estimated score reduction per finding if fixed (negative integers) | `{"STRATUM-CR05": -12, "STRATUM-001": -8, ...}` | No | v7.1 |
| finding_co_occurrence | list[list[string]] | Pairs of finding rules that co-occur in the same crew | `[["STRATUM-001", "STRATUM-CR05"], ...]` | No | v7 |
| per_crew_finding_density | object | Statistics on findings per crew (max, min, mean, median, stddev) | `{"max": 6, "min": 0, "mean": 0.6, "median": 0, "stddev": 1.4}` | No | v7 |
| findings_by_class | object | Count of findings by class (hygiene, operational, architecture) | `{"hygiene": 2, "operational": 6, "architecture": 10}` | No | v5 |
| findings_by_category | object | Count of findings by category (security, business, etc.) | `{"compliance": 1, "business": 3, "compounding": 7, ...}` | No | v5 |

## Guardrails & Controls

| Field | Type | Description | Example | Nullable | Since |
|-------|------|-------------|---------|----------|-------|
| guardrail_count | int | Total number of guardrails detected | `13` | No | v5 |
| has_any_guardrails | bool | Whether at least one guardrail was detected | `true` | No | v5 |
| guardrail_types | list[string] | Types of guardrails detected (validation, hitl, etc.) | `["validation"]` | No | v5 |
| guardrail_linked_count | int | Number of guardrails linked to specific data paths | `3` | No | v5 |
| control_bypass_count | int | Number of detected control bypass patterns | `2` | No | v5 |
| control_coverage_pct | float | Percentage of data paths with at least one control | `3.6` | No | v5 |
| has_hitl_anywhere | bool | Whether human-in-the-loop is present anywhere | `false` | No | v5 |

## MCP

| Field | Type | Description | Example | Nullable | Since |
|-------|------|-------------|---------|----------|-------|
| mcp_server_count | int | Number of MCP server configurations detected | `0` | No | v5 |
| mcp_remote_count | int | Number of MCP servers using remote (non-stdio) transport | `0` | No | v5 |
| mcp_auth_ratio | float | Fraction of MCP servers with authentication configured | `0.0` | No | v5 |
| mcp_pinned_ratio | float | Fraction of MCP servers with pinned versions | `0.0` | No | v5 |

## Risk Score

| Field | Type | Description | Example | Nullable | Since |
|-------|------|-------------|---------|----------|-------|
| risk_score | int | Normalized risk score (0-100) using asymptotic formula raw/(raw+50)*100 | `69` | No | v5 |
| finding_coverages | object | Per-finding mitigation coverage details (populated on rescan) | `{"STRATUM-001": {"total_paths": 20, "guarded_paths": 11, "coverage_pct": 55}}` | No | v5 |
| severity_downgrades | object | Per-finding severity downgrades due to partial mitigation | `{"STRATUM-001": {"original": "critical", "adjusted": "high", "reason": "partial_mitigation_55pct"}}` | No | v5 |
| blast_radius_distribution | list[int] | Sorted blast radius values per finding (descending) | `[4, 3, 3, 3, 3, ...]` | No | v5 |
| max_blast_radius | int | Maximum blast radius across all findings | `4` | No | v5 |
| crews_clean | int | Number of crews with zero findings (populated on rescan) | `0` | No | v5 |
| crews_with_findings | int | Number of crews with at least one finding | `30` | No | v5 |

## Environment

| Field | Type | Description | Example | Nullable | Since |
|-------|------|-------------|---------|----------|-------|
| total_tool_count | int | Number of unique tool classes across all agents | `30` | No | v7 |
| env_var_count | int | Number of environment variables referenced in code | `0` | No | v5 |
| has_env_in_gitignore | bool | Whether .env files are listed in .gitignore | `false` | No | v5 |
| error_handling_rate | float | Fraction of external calls with error handling | `0.07` | No | v5 |
| timeout_rate | float | Fraction of HTTP calls with timeout configured | `0.0` | No | v5 |
| checkpoint_type | string | Type of checkpointing detected (none, memory, persistent) | `"none"` | No | v5 |

## Data & Privacy

| Field | Type | Description | Example | Nullable | Since |
|-------|------|-------------|---------|----------|-------|
| has_pii | bool | Whether PII handling was detected | `true` | No | v5 |
| has_financial_data | bool | Whether financial data handling was detected | `false` | No | v5 |
| has_financial_tools | bool | Whether financial transaction tools are present | `false` | No | v5 |
| financial_validation_rate | float | Fraction of financial operations with validation | `0.0` | No | v5 |
| data_sensitivity_types | list[string] | Types of sensitive data detected (personal, financial, health) | `["personal"]` | No | v5 |
| has_shared_credentials | bool | Whether credentials are shared across agents | `false` | No | v5 |

## Security Posture

| Field | Type | Description | Example | Nullable | Since |
|-------|------|-------------|---------|----------|-------|
| mitigation_coverage | object | Coverage rates for key mitigation categories | `{"outbound_output_filter_rate": 0.0, "destructive_hitl_rate": 0.0, "financial_validation_rate": 0.0}` | No | v5 |
| uncontrolled_path_count | int | Number of data paths with no controls | `2` | No | v5 |
| max_path_hops | int | Maximum number of hops in any uncontrolled data path | `3` | No | v5 |
| downward_trust_crossings | int | Number of trust crossings from higher to lower trust | `8` | No | v5 |
| external_sink_count | int | Number of external data sinks (APIs, services) | `6` | No | v5 |
| shared_tool_max_agents | int | Maximum number of agents sharing a single tool | `4` | No | v5 |
| incident_match_count | int | Number of known breach patterns matched | `4` | No | v5 |
| incident_ids | list[string] | IDs of matched breach patterns | `["ECHOLEAK-2025", "SERVICENOW-NOWASSIST-2025", ...]` | No | v5 |
| regulatory_framework_count | int | Number of regulatory frameworks with surface area | `4` | No | v5 |
| regulatory_surface | list[string] | Specific regulatory articles/sections with exposure | `["EU AI Act Art. 14", "GDPR Art. 35", ...]` | No | v5 |

## Agent Properties

| Field | Type | Description | Example | Nullable | Since |
|-------|------|-------------|---------|----------|-------|
| has_agent_identity | bool | Whether agents have distinct identity/role definitions | `true` | No | v5 |
| has_shared_context | bool | Whether agents share a common context/memory space | `false` | No | v5 |
| has_context_provenance | bool | Whether context includes provenance tracking | `false` | No | v5 |
| has_context_rollback | bool | Whether context supports rollback/undo | `true` | No | v5 |
| has_memory_store | bool | Whether a persistent memory store is used | `true` | No | v5 |
| memory_store_types | list[string] | Types of memory stores detected | `[]` | No | v5 |
| has_learning_loop | bool | Whether a self-learning/feedback loop is present | `true` | No | v5 |
| learning_type | string | Type of learning loop (context_level, persistent, none) | `"context_level"` | No | v5 |
| has_eval_framework | bool | Whether an evaluation framework is present | `true` | No | v5 |
| has_eval_conflict | bool | Whether the eval framework conflicts with agent behavior | `false` | No | v5 |
| has_observability | bool | Whether observability/logging infrastructure is present | `false` | No | v5 |
| telemetry_destination_count | int | Number of external telemetry destinations | `0` | No | v5 |

## Normalized Features

| Field | Type | Description | Example | Nullable | Since |
|-------|------|-------------|---------|----------|-------|
| normalized_features | object | ML-ready normalized ratios derived from raw counts | *(see sub-fields)* | No | v7 |
| normalized_features.findings_per_agent | float | finding_rule_count / agent_count | `0.32` | No | v7 |
| normalized_features.findings_per_crew | float | finding_rule_count / crew_count | `0.6` | No | v7 |
| normalized_features.guardrails_per_agent | float | guardrail_count / agent_count | `0.23` | No | v7 |
| normalized_features.tools_per_agent | float | total_tool_count / agent_count | `0.54` | No | v7 |
| normalized_features.external_exposure_ratio | float | external capabilities / total capabilities | `0.6` | No | v7 |
| normalized_features.guardrail_coverage_ratio | float | guardrail_linked_count / finding_rule_count | `0.17` | No | v7 |

## LLM & Provider

| Field | Type | Description | Example | Nullable | Since |
|-------|------|-------------|---------|----------|-------|
| llm_providers | list[string] | LLM providers detected or inferred | `["openai"]` | No | v7.1 |
| llm_models | list[string] | Specific LLM models detected in code | `["gpt-4o"]` | No | v7.1 |
| provider_confidence | string | Confidence tier for provider detection (detected, inferred_env_var, inferred_framework, unknown) | `"detected"` | No | v7 |

## Repo Metadata

| Field | Type | Description | Example | Nullable | Since |
|-------|------|-------------|---------|----------|-------|
| repo_metadata | object | Repository-level metadata | *(see sub-fields)* | No | v7 |
| repo_metadata.python_file_count | int | Number of Python files in the repository | `94` | No | v7 |
| repo_metadata.yaml_config_count | int | Number of YAML configuration files | `12` | No | v7 |
| repo_metadata.total_loc | int | Total lines of code across scanned files | `8400` | No | v7 |
| repo_metadata.primary_framework | string | Most prominent framework detected | `"CrewAI"` | No | v7 |
| repo_metadata.framework_count | int | Number of distinct frameworks detected | `3` | No | v7 |

## Deployment Signals

| Field | Type | Description | Example | Nullable | Since |
|-------|------|-------------|---------|----------|-------|
| deployment_signals | object | Indicators of production readiness | *(see sub-fields)* | No | v7.1 |
| deployment_signals.has_dockerfile | bool | Whether a Dockerfile is present | `false` | No | v7.1 |
| deployment_signals.has_ci_config | bool | Whether CI/CD configuration is present | `false` | No | v7.1 |
| deployment_signals.has_tests | bool | Whether test files are present | `true` | No | v7.1 |
| deployment_signals.has_lockfile | bool | Whether a dependency lockfile is present | `true` | No | v7.1 |
| deployment_signals.has_env_example | bool | Whether a .env.example file is present | `true` | No | v7.1 |
| deployment_signals.deployment_score | int | Count of true boolean deployment signals (0-5) | `3` | No | v7.1 |

---

## Notes for Analysts

- **finding_rule_count** is the number of unique finding rules that fired. **total_finding_instances** is the total count of all instances across all rules. Use `total_finding_instances` for "how many findings does this repo have."

- **scanner_version** is the CLI version. **schema_version** and **schema_id** describe the telemetry format.

- For initial-scan-only datasets (like the 50k scan), rescan fields (`is_rescan`, `prev_score`, `score_delta`, `pre_scan_id`, `resolved_count`, `new_count`) will be absent. `finding_coverages` and `severity_downgrades` will be empty objects. `crews_clean` will be 0.

- **frameworks** lists all detected frameworks. **framework_versions** provides version strings where detection succeeded (values may be null for detected frameworks with unknown versions).

- **total_capabilities** and **total_tool_count** may have the same value. `total_capabilities` is decomposed by `capability_distribution` (outbound/data_access/destructive). `total_tool_count` counts unique tool classes across all agents.
