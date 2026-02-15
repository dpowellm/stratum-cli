"""stratum_core — shared schema definitions for Stratum CLI and stratum-lab.

This package contains the canonical definitions for:
- Node types and edge types (graph schema)
- Metric definitions (structural and per-node)
- Taxonomy IDs (security + reliability finding IDs)
- Node ID generation logic
"""
from stratum.stratum_core.schema import (
    NodeType, EdgeType, SECURITY_FINDING_IDS, RELIABILITY_FINDING_IDS,
    COMPOSITION_IDS, CROSS_COMPOSITION_IDS, ALL_FINDING_IDS,
    SEVERITY_ORDER, CONFIDENCE_ORDER,
)
from stratum.stratum_core.node_ids import (
    capability_node_id, agent_node_id, data_store_node_id,
    service_node_id, mcp_node_id, guardrail_node_id,
    observability_node_id,
)
from stratum.stratum_core.metrics import (
    GLOBAL_METRICS, PER_NODE_METRICS, MetricDefinition,
)

__all__ = [
    "NodeType", "EdgeType",
    "SECURITY_FINDING_IDS", "RELIABILITY_FINDING_IDS",
    "COMPOSITION_IDS", "CROSS_COMPOSITION_IDS", "ALL_FINDING_IDS",
    "SEVERITY_ORDER", "CONFIDENCE_ORDER",
    "capability_node_id", "agent_node_id", "data_store_node_id",
    "service_node_id", "mcp_node_id", "guardrail_node_id",
    "observability_node_id",
    "GLOBAL_METRICS", "PER_NODE_METRICS", "MetricDefinition",
]
