"""Graph data models: nodes, edges, paths, surfaces."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from stratum.models import TrustLevel


class NodeType(str, Enum):
    CAPABILITY = "capability"
    DATA_STORE = "data_store"
    MCP_SERVER = "mcp_server"
    EXTERNAL_SERVICE = "external_service"
    GUARDRAIL = "guardrail"
    AGENT = "agent"


class EdgeType(str, Enum):
    READS_FROM = "reads_from"
    WRITES_TO = "writes_to"
    CALLS = "calls"
    SHARES_WITH = "shares_with"
    FILTERED_BY = "filtered_by"
    GATED_BY = "gated_by"
    TOOL_OF = "tool_of"
    DELEGATES_TO = "delegates_to"
    CONNECTS_TO = "connects_to"


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
    trust_boundary: str = ""  # e.g. "INTERNAL→EXTERNAL" or ""


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

    def to_dict(self) -> dict:
        """Serialize graph for JSON output."""
        return {
            "nodes": [
                {
                    "id": n.id,
                    "type": n.node_type.value,
                    "label": n.label,
                    "trust_level": n.trust_level.value,
                    "data_sensitivity": n.data_sensitivity,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "type": e.edge_type.value,
                    "has_control": e.has_control,
                    "data_sensitivity": e.data_sensitivity,
                    "trust_crossing": e.trust_crossing,
                    "crossing_direction": e.crossing_direction,
                    "trust_boundary": e.trust_boundary,
                }
                for e in self.edges
            ],
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
