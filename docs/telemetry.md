# Telemetry Profile Schema

Every `stratum scan` produces an anonymized `TelemetryProfile` saved to `.stratum/last-scan.json`. This document describes every field.

## What is NOT collected

- Source code, function names, file paths, class names
- Environment variable values or secret material
- README content, docstrings, or comments
- Any data requiring network access to compute

## Field Reference

Fields are annotated **[structural]** (used for benchmarking/grouping) or **[scale]** (individual dashboard only).

### Identity

| Field | Type | Annotation | Description |
|---|---|---|---|
| `scan_id` | string | [scale] | Unique random ID per scan |
| `timestamp` | string | [scale] | ISO 8601 UTC timestamp |
| `version` | string | [scale] | CLI version that produced this profile |

### Capability Structure

| Field | Type | Annotation | Description |
|---|---|---|---|
| `total_capabilities` | int | [scale] | Total number of detected capabilities |
| `capability_distribution` | dict[str, int] | [scale] | Count per capability kind (outbound, data_access, etc.) |
| `trust_level_distribution` | dict[str, int] | [scale] | Count per trust level |

### Trust Crossings

| Field | Type | Annotation | Description |
|---|---|---|---|
| `trust_crossings` | dict[str, int] | [scale] | Undirected trust-level crossing counts |
| `total_trust_crossings` | int | [scale] | Sum of all crossing counts |

### Topology

| Field | Type | Annotation | Description |
|---|---|---|---|
| `topology_signature_hash` | string | [structural] | SHA-256 hash (16 hex chars) of capability topology. Encodes: capability kinds present, directed crossing directions, financial flag, checkpoint type. Irreversible. |
| `trust_crossing_adjacency` | dict[str, int] | [structural] | Directed trust-crossing counts. Keys are "LEVEL_A->LEVEL_B", values are product of level counts. |

### Archetype

| Field | Type | Annotation | Description |
|---|---|---|---|
| `archetype_class` | string | [structural] | SHA-256 hash (12 hex chars) of capability-kind set. Primary grouping key for benchmarking. |

### MCP

| Field | Type | Annotation | Description |
|---|---|---|---|
| `mcp_server_count` | int | [scale] | Number of MCP servers found |
| `mcp_remote_count` | int | [scale] | Number of remote MCP servers |
| `mcp_auth_ratio` | float | [structural] | Fraction of MCP servers with authentication |
| `mcp_pinned_ratio` | float | [structural] | Fraction of MCP servers with pinned versions |

### Guardrails

| Field | Type | Annotation | Description |
|---|---|---|---|
| `guardrail_count` | int | [scale] | Number of guardrails detected |
| `has_any_guardrails` | bool | [structural] | Whether any guardrails exist |
| `guardrail_types` | list[str] | [structural] | Which guardrail kinds are present |

### Risk

| Field | Type | Annotation | Description |
|---|---|---|---|
| `risk_score` | int | [scale] | Composite risk score (0-100) |
| `finding_severities` | dict[str, int] | [scale] | Count per severity level |
| `finding_confidences` | dict[str, int] | [scale] | Count per confidence level |
| `finding_rules` | list[str] | [structural] | Sorted list of unique rule IDs that fired |

### Environment

| Field | Type | Annotation | Description |
|---|---|---|---|
| `env_var_count` | int | [scale] | Number of env vars detected |
| `has_env_in_gitignore` | bool | [structural] | Whether .env is in .gitignore |

### Operational Signals

| Field | Type | Annotation | Description |
|---|---|---|---|
| `error_handling_rate` | float | [structural] | Fraction of external capabilities with error handling |
| `timeout_rate` | float | [structural] | Fraction of HTTP capabilities with timeouts |
| `checkpoint_type` | string | [structural] | "durable", "memory_only", or "none" |
| `has_financial_tools` | bool | [structural] | Whether financial capabilities exist |
| `financial_validation_rate` | float | [structural] | Fraction of financial capabilities with input validation |

### Mitigation Coverage

| Field | Type | Annotation | Description |
|---|---|---|---|
| `mitigation_coverage` | dict[str, float] | [structural] | Three coverage ratios: `outbound_output_filter_rate`, `destructive_hitl_rate`, `financial_validation_rate` |

## Opting Out

- `--no-telemetry`: Skips writing `.stratum/last-scan.json` entirely
- `--share-telemetry`: Submits the profile to `telemetry.stratum.dev` (one-way POST, no data received)
- `stratum config suppress-share-prompt`: Hides the share nudge
- `stratum config suppress-benchmark-teaser`: Hides the benchmark teaser
