"""Structural metric definitions for the reliability scanner.

Each metric has:
- id: stable identifier
- name: human-readable label
- computation: description of how to compute
- scope: "global" (per-repo) or "per_node"
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class MetricDefinition:
    id: str
    name: str
    description: str
    scope: str  # "global" or "per_node"


GLOBAL_METRICS: list[MetricDefinition] = [
    MetricDefinition("max_chain_depth", "Maximum Chain Depth",
                     "Longest path through delegates_to/feeds_into edges", "global"),
    MetricDefinition("mean_chain_depth", "Mean Chain Depth",
                     "Average path length through delegation edges", "global"),
    MetricDefinition("human_gate_coverage", "Human Gate Coverage",
                     "Fraction of agent chains with at least one HITL gate", "global"),
    MetricDefinition("irreversible_gate_rate", "Irreversible Action Gate Rate",
                     "Fraction of irreversible capabilities with upstream HITL", "global"),
    MetricDefinition("schema_contract_coverage", "Schema Contract Coverage",
                     "Fraction of feeds_into edges with validated schemas", "global"),
    MetricDefinition("error_laundering_rate", "Error Laundering Rate",
                     "Fraction of agents with default_on_error feeding downstream", "global"),
    MetricDefinition("delegation_scope_rate", "Delegation Scope Rate",
                     "Fraction of delegates_to edges that are capability-scoped", "global"),
    MetricDefinition("observability_coverage", "Observability Coverage",
                     "Fraction of agents with observed_by edges", "global"),
    MetricDefinition("cycle_count", "Cycle Count",
                     "Number of cycles in the delegation graph", "global"),
    MetricDefinition("timeout_coverage", "Timeout Coverage",
                     "Fraction of agent chains with timeout config", "global"),
    MetricDefinition("transitive_escalation_count", "Transitive Escalation Count",
                     "Number of agents with capabilities exceeding direct assignment", "global"),
    MetricDefinition("authority_amplification_factor", "Authority Amplification Factor",
                     "Max ratio of effective to direct capabilities", "global"),
    MetricDefinition("agent_count", "Agent Count", "Total agents in graph", "global"),
    MetricDefinition("reliability_finding_count", "Reliability Finding Count",
                     "Total reliability findings", "global"),
    MetricDefinition("reliability_score", "Reliability Score",
                     "0-100 reliability risk score (asymptotic)", "global"),
]

PER_NODE_METRICS: list[MetricDefinition] = [
    MetricDefinition("betweenness_centrality", "Betweenness Centrality",
                     "Fraction of shortest paths through this node", "per_node"),
    MetricDefinition("in_degree", "In-Degree", "Number of incoming edges", "per_node"),
    MetricDefinition("out_degree", "Out-Degree", "Number of outgoing edges", "per_node"),
    MetricDefinition("effective_capability_count", "Effective Capability Count",
                     "Capabilities reachable through delegation", "per_node"),
    MetricDefinition("direct_capability_count", "Direct Capability Count",
                     "Capabilities directly assigned", "per_node"),
]
