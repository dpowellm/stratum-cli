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
    # Spec v2 edge types
    TASK_SEQUENCE = "task_sequence"
    APPROVAL_REQUIRED = "approval_required"
    DAMPENED_BY = "dampened_by"
    SHARED_STATE_CONFLICT = "shared_state_conflict"


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
    subtype: str = ""             # "selection_tool" | "approve" | "reject" | "categorize" | "route" | "recommend" | "crud" | "query" | "general"
    regulatory_category: str = "" # "financial" | "personal_data" | "automated_decision" | "communications" | ""
    side_effects: list[str] = field(default_factory=list)
    idempotent: bool | None = None
    rate_limited: bool = False
    timeout_configured: bool = False
    validation_on_input: bool = False
    validation_on_output: bool = False
    cap_error_handling: str = ""  # "fail_loud" | "fail_silent" | "default_on_error" | "retry_then_default" | "unknown"
    external_service: bool = False
    data_mutation: bool = False
    human_visible: bool = False

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
    max_iterations: int | None = None
    memory_enabled: bool = False
    delegation_enabled: bool = False
    human_input_enabled: bool = False
    llm_model: str | None = None
    temperature: float | None = None
    output_schema: str | None = None
    # Computed at graph level
    betweenness_centrality: float = 0.0
    closeness_centrality: float = 0.0
    pagerank: float = 0.0
    tools_count: int = 0
    delegation_depth_downstream: int = 0
    critical_capabilities_reachable: int = 0
    implicit_authorities: int = 0
    error_blast_radius: int = 0

    # Reliability enrichment fields — data_store nodes
    concurrency_control: str = "" # "none" | "lock" | "version" | "queue"
    freshness_mechanism: str = "" # "none" | "ttl" | "timestamp_check" | "refresh_trigger"
    store_domain: str = ""
    persistence: str = ""         # "persistent" | "ephemeral" | "session"
    access_pattern: str = ""      # "read_only" | "write_only" | "read_write"
    concurrent_writers: int = 0
    concurrent_readers: int = 0
    schema_defined: bool = False
    contains_pii: bool | None = None
    ttl_configured: bool = False

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
                # Capability fields
                if n.reversibility:
                    nd["reversibility"] = n.reversibility
                if n.subtype:
                    nd["subtype"] = n.subtype
                if n.regulatory_category:
                    nd["regulatory_category"] = n.regulatory_category
                if n.external_service:
                    nd["external_service"] = True
                if n.data_mutation:
                    nd["data_mutation"] = True
                if n.validation_on_input:
                    nd["validation_on_input"] = True
                if n.validation_on_output:
                    nd["validation_on_output"] = True
                # Agent fields
                if n.error_handling_pattern:
                    nd["error_handling_pattern"] = n.error_handling_pattern
                if n.timeout_config:
                    nd["timeout_config"] = True
                if n.objective_tag:
                    nd["objective_tag"] = n.objective_tag
                if n.agent_domain:
                    nd["domain"] = n.agent_domain
                if n.llm_model:
                    nd["llm_model"] = n.llm_model
                if n.delegation_enabled:
                    nd["delegation_enabled"] = True
                if n.human_input_enabled:
                    nd["human_input_enabled"] = True
                if n.memory_enabled:
                    nd["memory_enabled"] = True
                if n.makes_decisions:
                    nd["makes_decisions"] = True
                if n.betweenness_centrality > 0:
                    nd["betweenness_centrality"] = round(n.betweenness_centrality, 4)
                if n.output_schema:
                    nd["output_schema"] = n.output_schema
                # Data store fields
                if n.concurrency_control:
                    nd["concurrency_control"] = n.concurrency_control
                if n.ttl_configured:
                    nd["ttl_configured"] = True
                if n.freshness_mechanism:
                    nd["freshness_mechanism"] = n.freshness_mechanism
                # Observability fields
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
                if e.preserves_uncertainty:
                    ed["preserves_uncertainty"] = True
                if e.purpose_limited:
                    ed["purpose_limited"] = True
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
