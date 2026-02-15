"""Reliability scanner data models — spec Section 7, 9, 11, 12, 13.

StructuredFinding, GlobalMetrics, AgentMetrics, GraphMotif,
ObservationPoint, and ReliabilityScanOutput dataclasses.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class StructuredFinding:
    """A taxonomy precondition label on the graph (spec Section 9)."""
    finding_id: str                        # e.g. "STRAT-DC-001"
    name: str
    category: str                          # "decision_chain" | "objective_conflict" | "signal_integrity" | "emergent_authority" | "aggregate_behavioral"
    severity: str                          # "critical" | "high" | "medium" | "low"
    description: str
    structural_evidence: dict = field(default_factory=dict)
    nodes_involved: list[str] = field(default_factory=list)
    edges_involved: list[str] = field(default_factory=list)
    subgraph_type: str = "path"            # "path" | "pair" | "cycle" | "node" | "transitive_closure" | "global"
    primary_node: str | None = None
    runtime_confirmation: dict = field(default_factory=dict)


@dataclass
class GlobalMetrics:
    """Structural metrics computed per repo (spec Section 7)."""
    # Scale
    total_agents: int = 0
    total_capabilities: int = 0
    total_data_stores: int = 0
    total_edges: int = 0
    total_guardrails: int = 0
    total_observability_sinks: int = 0

    # Topology
    max_delegation_depth: int = 0
    max_data_flow_depth: int = 0
    graph_density: float = 0.0
    strongly_connected_components: int = 0
    avg_path_length_to_critical: float = 0.0

    # Control coverage
    control_coverage_pct: float = 0.0
    observability_coverage_pct: float = 0.0
    human_checkpoint_ratio: float = 0.0
    approval_gate_ratio: float = 0.0

    # Risk surface
    trust_boundary_crossings: int = 0
    unguarded_trust_crossings: int = 0
    shared_state_conflicts: int = 0
    irreversible_capabilities: int = 0
    unguarded_irreversible: int = 0

    # Error handling
    fail_silent_agents_pct: float = 0.0
    fail_silent_on_critical_path: int = 0
    default_on_error_pct: float = 0.0
    error_propagation_paths: int = 0

    # Concentration
    max_betweenness_centrality: float = 0.0
    single_points_of_failure: int = 0
    tool_to_agent_ratio: float = 0.0
    max_tools_per_agent: int = 0

    # Feedback / loops
    feedback_loops_detected: int = 0
    undampened_feedback_loops: int = 0

    # Data integrity
    unvalidated_data_flows: int = 0
    schema_coverage_pct: float = 0.0


@dataclass
class AgentMetrics:
    """Per-node metrics for each agent (spec Section 7)."""
    node_id: str = ""
    betweenness_centrality: float = 0.0
    closeness_centrality: float = 0.0
    pagerank: float = 0.0
    delegation_depth_downstream: int = 0
    critical_capabilities_reachable: int = 0
    implicit_authorities: int = 0
    guardrail_count: int = 0
    observability_count: int = 0
    error_blast_radius: int = 0


@dataclass
class GraphMotif:
    """Structural motif for novel pattern detection (spec Section 11)."""
    motif_id: str = ""
    node_types: list[str] = field(default_factory=list)
    edge_types: list[str] = field(default_factory=list)
    edge_pairs: list[tuple[int, int]] = field(default_factory=list)
    instances: int = 0
    instance_node_ids: list[list[str]] = field(default_factory=list)
    enrichment_summary: dict = field(default_factory=dict)


@dataclass
class ObservationPointSpec:
    """Runtime instrumentation recommendation (spec Section 12)."""
    priority: int = 0
    node_id: str = ""
    rationale: str = ""
    preconditions_at_this_node: list[str] = field(default_factory=list)
    structural_risk_score: float = 0.0
    recommended_observations: list[dict] = field(default_factory=list)


@dataclass
class ReliabilityScanOutput:
    """Complete reliability scanner output per repo (spec Section 13)."""
    repo_id: str = ""
    framework: str = ""
    scan_timestamp: str = ""
    scanner_version: str = ""
    schema_id: int = 8

    graph: dict = field(default_factory=dict)
    structural_metrics: dict = field(default_factory=dict)
    preconditions: list = field(default_factory=list)
    compositions: list = field(default_factory=list)
    structural_anomalies: list = field(default_factory=list)
    graph_motifs: list = field(default_factory=list)
    observation_points: list = field(default_factory=list)

    security_risk_score: float = 0.0
    reliability_risk_score: float = 0.0
    gap_classification: str = "both_clean"
    security_findings: list = field(default_factory=list)
