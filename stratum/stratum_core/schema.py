"""Canonical graph schema: node types, edge types, taxonomy IDs.

This module is the single source of truth for schema enumerations.
Both stratum-cli and stratum-lab import from here.
"""
from __future__ import annotations


# ---------------------------------------------------------------------------
# Node types
# ---------------------------------------------------------------------------

class NodeType:
    CAPABILITY = "capability"
    DATA_STORE = "data_store"
    MCP_SERVER = "mcp_server"
    EXTERNAL_SERVICE = "external"
    GUARDRAIL = "guardrail"
    AGENT = "agent"
    OBSERVABILITY_SINK = "observability_sink"

    ALL = {
        CAPABILITY, DATA_STORE, MCP_SERVER, EXTERNAL_SERVICE,
        GUARDRAIL, AGENT, OBSERVABILITY_SINK,
    }


# ---------------------------------------------------------------------------
# Edge types
# ---------------------------------------------------------------------------

class EdgeType:
    # Existing
    READS_FROM = "reads_from"
    WRITES_TO = "writes_to"
    SENDS_TO = "sends_to"
    CALLS = "calls"
    SHARES_WITH = "shares_with"
    FILTERED_BY = "filtered_by"
    GATED_BY = "gated_by"
    TOOL_OF = "tool_of"
    DELEGATES_TO = "delegates_to"
    FEEDS_INTO = "feeds_into"
    SHARES_TOOL = "shares_tool"

    # New reliability edge types
    OBSERVED_BY = "observed_by"
    RATE_LIMITED_BY = "rate_limited_by"
    ARBITRATED_BY = "arbitrated_by"
    IMPLICIT_AUTHORITY_OVER = "implicit_authority_over"
    ERROR_PROPAGATION_PATH = "error_propagation_path"
    ERROR_BOUNDARY = "error_boundary"

    ALL = {
        READS_FROM, WRITES_TO, SENDS_TO, CALLS, SHARES_WITH,
        FILTERED_BY, GATED_BY, TOOL_OF, DELEGATES_TO, FEEDS_INTO,
        SHARES_TOOL, OBSERVED_BY, RATE_LIMITED_BY, ARBITRATED_BY,
        IMPLICIT_AUTHORITY_OVER, ERROR_PROPAGATION_PATH, ERROR_BOUNDARY,
    }

    # Delegation/flow edges used in chain traversal
    CHAIN_EDGES = {DELEGATES_TO, FEEDS_INTO}


# ---------------------------------------------------------------------------
# Taxonomy IDs
# ---------------------------------------------------------------------------

SECURITY_FINDING_IDS = {
    "STRATUM-001", "STRATUM-002", "STRATUM-003", "STRATUM-004",
    "STRATUM-005", "STRATUM-006", "STRATUM-007", "STRATUM-008",
    "STRATUM-009", "STRATUM-010",
    "STRATUM-CR05", "STRATUM-CR06",
    "STRATUM-BR01", "STRATUM-BR02", "STRATUM-BR03", "STRATUM-BR04",
    "STRATUM-OP01", "STRATUM-OP02",
    "ENV-001", "ENV-002",
    "LEARNING-001", "LEARNING-002", "LEARNING-003",
    "CONTEXT-001", "CONTEXT-002",
    "TELEMETRY-001", "TELEMETRY-002", "TELEMETRY-003",
    "EVAL-001", "EVAL-002",
    "IDENTITY-001", "IDENTITY-002",
    "PORTABILITY-001",
}

# Bucket A: 18 static reliability findings
RELIABILITY_FINDING_IDS = {
    # Decision Chain Risk
    "STRAT-DC-001", "STRAT-DC-002", "STRAT-DC-003", "STRAT-DC-004",
    "STRAT-DC-005", "STRAT-DC-006", "STRAT-DC-007", "STRAT-DC-008",
    # Objective & Incentive Conflict
    "STRAT-OC-002", "STRAT-OC-003", "STRAT-OC-005",
    # Signal Integrity & Error Propagation
    "STRAT-SI-001", "STRAT-SI-004", "STRAT-SI-006", "STRAT-SI-007",
    # Emergent Authority & Scope Creep
    "STRAT-EA-001", "STRAT-EA-002", "STRAT-EA-003",
}

# Bucket B: 12 hybrid findings (require .stratum.yml)
RELIABILITY_BUCKET_B_IDS = {
    "STRAT-OC-001", "STRAT-OC-004",
    "STRAT-SI-002", "STRAT-SI-003", "STRAT-SI-005",
    "STRAT-EA-004",
    "STRAT-AB-001", "STRAT-AB-002", "STRAT-AB-003", "STRAT-AB-004",
    "STRAT-AB-005", "STRAT-AB-007",
}

# Within-reliability compositions
COMPOSITION_IDS = {
    "STRAT-COMP-001", "STRAT-COMP-002", "STRAT-COMP-003",
    "STRAT-COMP-004", "STRAT-COMP-005", "STRAT-COMP-006",
    "STRAT-COMP-007",
}

# Cross-dataset compositions (security x reliability)
CROSS_COMPOSITION_IDS = {
    "STRAT-XCOMP-001", "STRAT-XCOMP-002", "STRAT-XCOMP-003",
    "STRAT-XCOMP-004", "STRAT-XCOMP-005", "STRAT-XCOMP-006",
}

ALL_FINDING_IDS = (
    SECURITY_FINDING_IDS | RELIABILITY_FINDING_IDS
    | RELIABILITY_BUCKET_B_IDS | COMPOSITION_IDS | CROSS_COMPOSITION_IDS
)


# ---------------------------------------------------------------------------
# Ordering constants
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
CONFIDENCE_ORDER = {"confirmed": 2, "probable": 1, "heuristic": 0}


# ---------------------------------------------------------------------------
# Finding categories
# ---------------------------------------------------------------------------

RELIABILITY_CATEGORIES = {
    "DC": "Decision Chain Risk",
    "OC": "Objective & Incentive Conflict",
    "SI": "Signal Integrity & Error Propagation",
    "EA": "Emergent Authority & Scope Creep",
    "AB": "Aggregate Behavioral Exposure",
}
