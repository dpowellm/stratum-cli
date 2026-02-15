"""Graph data models: nodes, edges, paths, surfaces."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from stratum.models import TrustLevel


class NodeType(str, Enum):
    CAPABILITY = "capability"
    DATA_STORE = "data_store"
    MCP_SERVER = "mcp_server"
    EXTERNAL_SERVICE = "external"
    GUARDRAIL = "guardrail"
    AGENT = "agent"
    OBSERVABILITY_SINK = "observability_sink"


class EdgeType(str, Enum):
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
    # Reliability edge types
    OBSERVED_BY = "observed_by"
    RATE_LIMITED_BY = "rate_limited_by"
    ARBITRATED_BY = "arbitrated_by"
    IMPLICIT_AUTHORITY_OVER = "implicit_authority_over"
    ERROR_PROPAGATION_PATH = "error_propagation_path"
    ERROR_BOUNDARY = "error_boundary"


@dataclass
class GraphNode:
    id: str
    node_type: NodeType
    label: str
    trust_level: TrustLevel

    # Properties (all optional, populated when inferable)
    data_sensitivity: str = "unknown"
    framework: str = ""
    source_file: str = ""
    line_number: int = 0
    has_error_handling: bool = False
    has_timeout: bool = False

    # For MCP_SERVER nodes
    mcp_auth: bool = False
    mcp_pinned: bool = False
    mcp_remote: bool = False

    # For GUARDRAIL nodes
    guardrail_kind: str = ""
    guardrail_active: bool = False

    # Reliability enrichment fields — capability nodes
    reversibility: str = ""       # "reversible" | "irreversible" | "conditional"
    subtype: str = ""             # "selection_tool" | "approve" | "reject" | "categorize" | "route" | "recommend" | "general"
    regulatory_category: str = "" # "financial" | "personal_data" | "automated_decision" | "communications" | ""
    side_effects: list[str] = field(default_factory=list)

    # Reliability enrichment fields — agent nodes
    error_handling_pattern: str = ""  # "fail_loud" | "fail_silent" | "default_on_error" | "retry_then_default"
    model_pinned: bool = False
    prompt_dynamic: bool = False
    timeout_config: bool = False
    objective_tag: str = ""
    agent_domain: str = ""
    business_priority: str = ""   # "critical" | "high" | "medium" | "low"
    makes_decisions: bool = False
    duty_class: str = ""          # "request" | "approve" | "execute" | "review" | "reconcile"

    # Reliability enrichment fields — data_store nodes
    concurrency_control: str = "" # "none" | "lock" | "version" | "queue"
    freshness_mechanism: str = "" # "none" | "ttl" | "timestamp_check" | "refresh_trigger"
    store_domain: str = ""

    # For OBSERVABILITY_SINK nodes
    observability_type: str = ""  # "langsmith" | "logging" | "opentelemetry" | "custom"
    captures_decision_rationale: bool = False


@dataclass
class GraphEdge:
    source: str
    target: str
    edge_type: EdgeType
    has_control: bool
    control_type: str = ""
    data_sensitivity: str = "unknown"
    trust_crossing: bool = False
    crossing_direction: str = ""  # "inward" or "outward"

    # Reliability enrichment fields
    schema_validated: bool = False   # feeds_into: whether schema contract exists
    preserves_uncertainty: bool = False  # feeds_into: whether uncertainty propagates
    scoped: bool = False             # delegates_to: whether delegation is capability-scoped
    purpose_limited: bool = False    # reads_from: whether data access has purpose limitation


@dataclass
class RiskPath:
    """A path through the graph that represents a risk."""
    nodes: list[str]
    edges: list[GraphEdge]
    hops: int
    source_sensitivity: str
    destination_trust: str
    missing_controls: list[str]
    severity: str
    description: str = ""
    plain_description: str = ""
    regulatory_flags: list[str] = field(default_factory=list)


@dataclass
class RiskSurface:
    """Aggregate risk metrics computed from the graph."""
    total_nodes: int = 0
    total_edges: int = 0

    # Path metrics
    uncontrolled_path_count: int = 0
    max_path_hops: int = 0
    sensitive_data_types: list[str] = field(default_factory=list)
    external_sink_count: int = 0

    # Control coverage
    edges_with_controls: int = 0
    edges_needing_controls: int = 0
    control_coverage_pct: float = 0.0

    # Regulatory exposure
    regulatory_frameworks: list[str] = field(default_factory=list)

    # Trust boundary metrics
    trust_boundary_crossings: int = 0
    downward_crossings: int = 0
    outward_crossings: int = 0
    inward_crossings: int = 0

    # Topology metrics (v0.2)
    max_fan_out_per_crew: int = 0
    max_chain_depth: int = 0
    edge_density: float = 0.0
    crew_count: int = 0


@dataclass
class RiskGraph:
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)
    uncontrolled_paths: list[RiskPath] = field(default_factory=list)
    risk_surface: RiskSurface = field(default_factory=RiskSurface)

    def to_dict(self, enriched: bool = False) -> dict:
        """Serialize graph for JSON output.

        If enriched=True, includes reliability enrichment fields.
        """
        node_list = []
        for n in self.nodes.values():
            nd = {
                "id": n.id,
                "type": n.node_type.value,
                "label": n.label,
                "trust_level": n.trust_level.value,
                "data_sensitivity": n.data_sensitivity,
            }
            if enriched:
                if n.reversibility:
                    nd["reversibility"] = n.reversibility
                if n.subtype:
                    nd["subtype"] = n.subtype
                if n.error_handling_pattern:
                    nd["error_handling_pattern"] = n.error_handling_pattern
                if n.timeout_config:
                    nd["timeout_config"] = True
                if n.objective_tag:
                    nd["objective_tag"] = n.objective_tag
                if n.concurrency_control:
                    nd["concurrency_control"] = n.concurrency_control
                if n.observability_type:
                    nd["observability_type"] = n.observability_type
            node_list.append(nd)

        edge_list = []
        for e in self.edges:
            ed = {
                "source": e.source,
                "target": e.target,
                "type": e.edge_type.value,
                "has_control": e.has_control,
                "data_sensitivity": e.data_sensitivity,
                "trust_crossing": e.trust_crossing,
                "crossing_direction": e.crossing_direction,
            }
            if enriched:
                if e.schema_validated:
                    ed["schema_validated"] = True
                if e.scoped:
                    ed["scoped"] = True
            edge_list.append(ed)

        return {
            "nodes": node_list,
            "edges": edge_list,
            "risk_surface": {
                "total_nodes": self.risk_surface.total_nodes,
                "total_edges": self.risk_surface.total_edges,
                "uncontrolled_path_count": self.risk_surface.uncontrolled_path_count,
                "max_path_hops": self.risk_surface.max_path_hops,
                "sensitive_data_types": self.risk_surface.sensitive_data_types,
                "external_sink_count": self.risk_surface.external_sink_count,
                "control_coverage_pct": self.risk_surface.control_coverage_pct,
                "regulatory_frameworks": self.risk_surface.regulatory_frameworks,
                "trust_boundary_crossings": self.risk_surface.trust_boundary_crossings,
                "downward_crossings": self.risk_surface.downward_crossings,
                "max_fan_out_per_crew": self.risk_surface.max_fan_out_per_crew,
                "max_chain_depth": self.risk_surface.max_chain_depth,
                "edge_density": self.risk_surface.edge_density,
                "crew_count": self.risk_surface.crew_count,
            },
        }
