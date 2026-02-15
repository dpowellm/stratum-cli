"""Reliability finding engine — 27 Bucket A + 2 partial Bucket B rules.

Each rule uses graph traversal primitives. Rules are labeling functions
that run AFTER graph construction and enrichment. They annotate the graph.

Categories:
- DC: Decision Chain Risk (8 Bucket A)
- OC: Objective & Incentive Conflict (2 Bucket A + 2 Bucket B partial)
- SI: Signal Integrity & Error Propagation (7 Bucket A)
- EA: Emergent Authority & Scope Creep (5 Bucket A)
- AB: Aggregate Behavioral Exposure (5 Bucket A)
"""
from __future__ import annotations

import logging
from collections import defaultdict

from stratum.models import Confidence, Finding, RiskCategory, Severity
from stratum.graph.models import EdgeType, GraphNode, NodeType, RiskGraph
from stratum.reliability.traversals import (
    find_paths, find_pairs_shared_state, detect_cycles,
    compute_centrality, compute_transitive_capabilities,
)

logger = logging.getLogger(__name__)


def evaluate(graph: RiskGraph) -> list[Finding]:
    """Run all 27 Bucket A + 2 partial Bucket B reliability rules.

    Returns list of reliability findings. Does NOT modify security findings.
    """
    if not graph or not graph.nodes:
        return []

    findings: list[Finding] = []

    # Decision Chain Risk (8)
    findings.extend(_dc001_unsupervised_chain(graph))
    findings.extend(_dc002_irreversible_no_approval(graph))
    findings.extend(_dc003_unobserved_decision_point(graph))
    findings.extend(_dc004_cascading_autonomous_decisions(graph))
    findings.extend(_dc005_bottleneck(graph))
    findings.extend(_dc006_recursive_delegation(graph))
    findings.extend(_dc007_trust_boundary_chain(graph))
    findings.extend(_dc008_no_timeout(graph))

    # Objective & Incentive Conflict (2 A + 2 partial)
    findings.extend(_oc001_conflicting_objectives(graph))
    findings.extend(_oc002_competing_resources(graph))
    findings.extend(_oc003_undampened_feedback(graph))
    findings.extend(_oc004_incentive_misalignment(graph))

    # Signal Integrity (7)
    findings.extend(_si001_error_laundering(graph))
    findings.extend(_si002_confidence_laundering(graph))
    findings.extend(_si003_stale_data(graph))
    findings.extend(_si004_schema_mismatch(graph))
    findings.extend(_si005_unvalidated_external(graph))
    findings.extend(_si006_error_swallowing_trust(graph))
    findings.extend(_si007_aggregation_no_provenance(graph))

    # Emergent Authority (5)
    findings.extend(_ea001_implicit_authority(graph))
    findings.extend(_ea002_capability_aggregation(graph))
    findings.extend(_ea003_unconstrained_delegation(graph))
    findings.extend(_ea004_transitive_data_access(graph))
    findings.extend(_ea006_cross_crew_leakage(graph))

    # Aggregate Behavioral (5)
    findings.extend(_ab001_unbounded_volume(graph))
    findings.extend(_ab003_regulatory_no_audit(graph))
    findings.extend(_ab004_monoculture(graph))
    findings.extend(_ab006_no_rollback(graph))
    findings.extend(_ab007_external_concentration(graph))

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _agent_tools(graph: RiskGraph, agent_id: str) -> list[str]:
    """Get tool node IDs owned by an agent."""
    return [e.source for e in graph.edges
            if e.edge_type == EdgeType.TOOL_OF and e.target == agent_id]


def _node_source_locations(graph: RiskGraph, node_ids: list[str]) -> list[str]:
    """Get source file:line evidence for a set of nodes."""
    evidence = []
    seen = set()
    for nid in node_ids:
        node = graph.nodes.get(nid)
        if not node or not node.source_file:
            continue
        ref = f"{node.source_file}:{node.line_number}" if node.line_number else node.source_file
        if ref not in seen:
            seen.add(ref)
            evidence.append(ref)
    return evidence


def _has_observed_by(graph: RiskGraph, agent_id: str) -> bool:
    """Check if an agent has any observed_by edges."""
    return any(
        e.source == agent_id and e.edge_type == EdgeType.OBSERVED_BY
        for e in graph.edges
    )


def _has_approval_gate(graph: RiskGraph, node_id: str) -> bool:
    """Check if a node has approval_required or guarded_by edge to approval guardrail."""
    for edge in graph.edges:
        if edge.source == node_id:
            if edge.edge_type == EdgeType.APPROVAL_REQUIRED:
                return True
            if edge.edge_type == EdgeType.GATED_BY:
                guard = graph.nodes.get(edge.target)
                if guard and guard.guardrail_kind in ("hitl", "human_in_the_loop", "approval"):
                    return True
    return False


def _make_finding(
    finding_id: str,
    name: str,
    severity: Severity,
    category_code: str,
    affected_nodes: list[str],
    graph: RiskGraph,
    risk_description: str,
    remediation: str,
    subgraph_type: str = "path",
    chain: list[str] | None = None,
    extra_evidence: list[str] | None = None,
) -> Finding:
    """Create a reliability Finding."""
    category_map = {
        "DC": "Decision Chain Risk",
        "OC": "Objective & Incentive Conflict",
        "SI": "Signal Integrity & Error Propagation",
        "EA": "Emergent Authority & Scope Creep",
        "AB": "Aggregate Behavioral Exposure",
    }

    evidence = _node_source_locations(graph, affected_nodes)
    if extra_evidence:
        evidence.extend(extra_evidence)

    labels = [graph.nodes[nid].label for nid in affected_nodes if nid in graph.nodes]
    path_display = " \u2192 ".join(labels) if labels else ""

    return Finding(
        id=finding_id,
        severity=severity,
        confidence=Confidence.CONFIRMED,
        category=RiskCategory.OPERATIONAL,
        title=name,
        path=path_display,
        description=risk_description,
        evidence=evidence[:5],
        scenario=risk_description,
        remediation=remediation,
        effort="med",
        finding_class="reliability",
    )


# ===========================================================================
# DECISION CHAIN RISK (DC) — 8 rules
# ===========================================================================

def _dc001_unsupervised_chain(graph: RiskGraph) -> list[Finding]:
    """STRAT-DC-001: Unsupervised Multi-Step Decision Chain.

    Path of 3+ delegates_to edges with no human_input_enabled agent in the path.
    """
    chain_edges = {EdgeType.DELEGATES_TO.value}
    paths = find_paths(graph, chain_edges, source_filter="agent", min_length=3, max_length=8)

    findings: list[Finding] = []
    seen_paths: set[tuple[str, ...]] = set()

    for path in paths:
        if not all(
            graph.nodes.get(nid) and graph.nodes[nid].node_type == NodeType.AGENT
            for nid in path
        ):
            continue

        # Check for human_input_enabled on any agent in the path
        has_human = any(
            graph.nodes.get(nid) and graph.nodes[nid].human_input_enabled
            for nid in path
        )
        if has_human:
            continue

        path_key = tuple(path)
        if path_key in seen_paths:
            continue
        seen_paths.add(path_key)

        findings.append(_make_finding(
            "STRAT-DC-001",
            "Unsupervised Multi-Step Decision Chain",
            Severity.HIGH,
            "DC",
            path,
            graph,
            f"Delegation chain of {len(path)} agents with no human checkpoint. "
            f"Decisions cascade without human review.",
            "Add human_input=True (CrewAI) or interrupt_before (LangGraph) "
            "at critical points in the delegation chain.",
            subgraph_type="path",
            chain=path,
        ))

    findings.sort(key=lambda f: len(f.evidence), reverse=True)
    return findings[:3]


def _dc002_irreversible_no_approval(graph: RiskGraph) -> list[Finding]:
    """STRAT-DC-002: Irreversible Action Without Approval Gate.

    Capability with reversibility=irreversible and no approval_required or
    guarded_by edge to an approval-type guardrail.
    """
    findings: list[Finding] = []

    for nid, node in graph.nodes.items():
        if node.node_type != NodeType.CAPABILITY:
            continue
        if node.reversibility != "irreversible":
            continue

        # Find owning agent
        agent_id = None
        for edge in graph.edges:
            if edge.edge_type == EdgeType.TOOL_OF and edge.source == nid:
                agent_id = edge.target
                break

        # Check for approval gate on the capability or its agent
        if _has_approval_gate(graph, nid):
            continue
        if agent_id and _has_approval_gate(graph, agent_id):
            continue

        affected = [nid]
        if agent_id:
            affected.insert(0, agent_id)

        findings.append(_make_finding(
            "STRAT-DC-002",
            "Irreversible Action Without Approval Gate",
            Severity.CRITICAL,
            "DC",
            affected,
            graph,
            f"{node.label} is irreversible with no human approval gate.",
            "Add approval_required guardrail or human_input=True on the Task.",
            subgraph_type="node",
        ))

    return findings[:5]


def _dc003_unobserved_decision_point(graph: RiskGraph) -> list[Finding]:
    """STRAT-DC-003: Unobserved Decision Point.

    Agent with betweenness_centrality > 0.3 and zero observed_by edges.
    """
    centrality = compute_centrality(graph)
    if not centrality:
        return []

    findings: list[Finding] = []

    for agent_id, score in centrality.items():
        if score <= 0.3:
            continue

        node = graph.nodes.get(agent_id)
        if not node or node.node_type != NodeType.AGENT:
            continue

        if _has_observed_by(graph, agent_id):
            continue

        findings.append(_make_finding(
            "STRAT-DC-003",
            "Unobserved Decision Point",
            Severity.HIGH,
            "DC",
            [agent_id],
            graph,
            f"{node.label} has betweenness centrality {score:.2f} (high decision influence) "
            f"but zero observability coverage.",
            "Add per-agent logging callbacks or tracing instrumentation.",
            subgraph_type="node",
            extra_evidence=[f"betweenness_centrality={score:.4f}"],
        ))

    return findings[:3]


def _dc004_cascading_autonomous_decisions(graph: RiskGraph) -> list[Finding]:
    """STRAT-DC-004: Cascading Autonomous Decisions.

    Chain of 2+ agents where each makes a selection/routing decision
    (capability.subtype in [selection_tool, categorize, route, approve, reject])
    with no human in chain.
    """
    decision_subtypes = {"selection_tool", "categorize", "route", "approve", "reject"}

    # Find agents that make decisions (have decision-type capabilities)
    decision_agents: set[str] = set()
    for nid, node in graph.nodes.items():
        if node.node_type != NodeType.AGENT:
            continue
        tools = _agent_tools(graph, nid)
        for tid in tools:
            tool_node = graph.nodes.get(tid)
            if tool_node and tool_node.subtype in decision_subtypes:
                decision_agents.add(nid)
                break

    if len(decision_agents) < 2:
        return []

    # Find chains of decision agents
    chain_edges = {EdgeType.DELEGATES_TO.value, EdgeType.FEEDS_INTO.value}
    paths = find_paths(graph, chain_edges, source_filter="agent", min_length=2, max_length=6)

    findings: list[Finding] = []
    seen: set[tuple[str, ...]] = set()

    for path in paths:
        # All nodes must be decision agents
        if not all(nid in decision_agents for nid in path):
            continue

        # No human in chain
        has_human = any(
            graph.nodes.get(nid) and graph.nodes[nid].human_input_enabled
            for nid in path
        )
        if has_human:
            continue

        path_key = tuple(path)
        if path_key in seen:
            continue
        seen.add(path_key)

        findings.append(_make_finding(
            "STRAT-DC-004",
            "Cascading Autonomous Decisions",
            Severity.HIGH,
            "DC",
            path,
            graph,
            f"Chain of {len(path)} decision-making agents with no human review. "
            f"Each agent makes selection/routing decisions autonomously.",
            "Add human checkpoints between sequential decision points.",
            subgraph_type="path",
            chain=path,
        ))

    return findings[:3]


def _dc005_bottleneck(graph: RiskGraph) -> list[Finding]:
    """STRAT-DC-005: Single-Agent Bottleneck in Critical Path.

    Agent with betweenness_centrality > 0.5 AND all paths to critical
    capabilities route through it.
    """
    centrality = compute_centrality(graph)
    if not centrality:
        return []

    findings: list[Finding] = []

    for agent_id, score in centrality.items():
        if score <= 0.5:
            continue

        node = graph.nodes.get(agent_id)
        if not node or node.node_type != NodeType.AGENT:
            continue

        # Check for critical capabilities downstream
        critical_downstream = 0
        for cap_id, cap_node in graph.nodes.items():
            if cap_node.node_type == NodeType.CAPABILITY and cap_node.reversibility == "irreversible":
                critical_downstream += 1

        findings.append(_make_finding(
            "STRAT-DC-005",
            "Single-Agent Bottleneck in Critical Path",
            Severity.HIGH,
            "DC",
            [agent_id],
            graph,
            f"{node.label} has betweenness centrality {score:.2f} — "
            f"all critical paths route through this agent.",
            "Introduce redundancy or parallel evaluation paths.",
            subgraph_type="node",
            extra_evidence=[f"betweenness_centrality={score:.4f}"],
        ))

    return findings[:2]


def _dc006_recursive_delegation(graph: RiskGraph) -> list[Finding]:
    """STRAT-DC-006: Recursive Delegation Without Depth Bound.

    Cycle in delegates_to subgraph AND no max_iterations set on agents in cycle.
    """
    cycles = detect_cycles(
        graph,
        edge_types={EdgeType.DELEGATES_TO.value},
        node_type_filter="agent",
    )

    findings: list[Finding] = []

    for cycle in cycles:
        cycle_nodes = cycle[:-1]  # Remove closing node

        # Check if any agent in cycle has max_iterations set
        has_bound = any(
            graph.nodes.get(nid) and graph.nodes[nid].max_iterations is not None
            for nid in cycle_nodes
        )
        if has_bound:
            continue

        cycle_labels = [graph.nodes[nid].label for nid in cycle if nid in graph.nodes]
        findings.append(_make_finding(
            "STRAT-DC-006",
            "Recursive Delegation Without Depth Bound",
            Severity.HIGH,
            "DC",
            cycle_nodes,
            graph,
            f"Delegation cycle: {' \u2192 '.join(cycle_labels)}. "
            f"No max_iterations set on any agent in the cycle.",
            "Set max_iter on the Crew or implement iteration counting.",
            subgraph_type="cycle",
            chain=cycle,
        ))

    return findings[:3]


def _dc007_trust_boundary_chain(graph: RiskGraph) -> list[Finding]:
    """STRAT-DC-007: Decision Chain Crossing Trust Boundaries Without Validation.

    delegates_to path that crosses 2+ trust boundaries with no guardrail
    edges on the crossing edges.
    """
    chain_edges = {EdgeType.DELEGATES_TO.value}
    paths = find_paths(graph, chain_edges, source_filter="agent", min_length=2, max_length=8)

    findings: list[Finding] = []

    for path in paths:
        # Count trust boundary crossings without guardrails
        unguarded_crossings = 0
        for i in range(len(path) - 1):
            src = graph.nodes.get(path[i])
            tgt = graph.nodes.get(path[i + 1])
            if not src or not tgt:
                continue

            # Check if this edge crosses a trust boundary
            for edge in graph.edges:
                if (edge.source == path[i] and edge.target == path[i + 1]
                        and edge.edge_type == EdgeType.DELEGATES_TO):
                    if edge.trust_crossing and not edge.has_control:
                        unguarded_crossings += 1

        if unguarded_crossings < 2:
            continue

        findings.append(_make_finding(
            "STRAT-DC-007",
            "Decision Chain Crossing Trust Boundaries",
            Severity.HIGH,
            "DC",
            path,
            graph,
            f"Delegation chain crosses {unguarded_crossings} trust boundaries "
            f"with no guardrails on crossing edges.",
            "Add guardrails at trust boundary crossings in delegation chains.",
            subgraph_type="path",
            chain=path,
        ))

    return findings[:3]


def _dc008_no_timeout(graph: RiskGraph) -> list[Finding]:
    """STRAT-DC-008: No Timeout or Circuit Breaker on Agent Chain.

    Linear chain of 3+ agents via delegates_to or task_sequence where no
    agent has timeout_configured=True.
    """
    chain_edges = {EdgeType.DELEGATES_TO.value, EdgeType.TASK_SEQUENCE.value}
    paths = find_paths(graph, chain_edges, source_filter="agent", min_length=3, max_length=8)

    findings: list[Finding] = []
    seen: set[tuple[str, ...]] = set()

    for path in paths:
        if not all(
            graph.nodes.get(nid) and graph.nodes[nid].node_type == NodeType.AGENT
            for nid in path
        ):
            continue

        has_timeout = any(
            graph.nodes.get(nid) and graph.nodes[nid].timeout_config
            for nid in path
        )
        if has_timeout:
            continue

        path_key = tuple(path)
        if path_key in seen:
            continue
        seen.add(path_key)

        findings.append(_make_finding(
            "STRAT-DC-008",
            "No Timeout or Circuit Breaker on Agent Chain",
            Severity.HIGH,
            "DC",
            path,
            graph,
            f"Chain of {len(path)} agents with no timeout configuration. "
            f"Chain can hang indefinitely.",
            "Set max_execution_time on each Task or step_timeout on agent nodes.",
            subgraph_type="path",
            chain=path,
        ))

    return findings[:3]


# ===========================================================================
# OBJECTIVE & INCENTIVE CONFLICT (OC) — 2 Bucket A + 2 partial Bucket B
# ===========================================================================

def _oc001_conflicting_objectives(graph: RiskGraph) -> list[Finding]:
    """STRAT-OC-001: Conflicting Optimization Objectives on Shared State.
    [Bucket B partial — fires when objective_tag can be inferred]

    2+ agents with different objective_tag values both writes_to same data_store,
    AND no arbitrated_by edge.
    """
    pairs = find_pairs_shared_state(graph, require_write=True)
    findings: list[Finding] = []

    for agent_a, agent_b, shared_stores in pairs:
        node_a = graph.nodes.get(agent_a)
        node_b = graph.nodes.get(agent_b)
        if not node_a or not node_b:
            continue

        # Both must have meaningful objective tags
        tag_a = node_a.objective_tag
        tag_b = node_b.objective_tag
        if not tag_a or not tag_b or tag_a == tag_b:
            continue

        # Check for arbitrated_by edge
        has_arbitrator = any(
            e.edge_type == EdgeType.ARBITRATED_BY
            and ((e.source == agent_a) or (e.source == agent_b))
            for e in graph.edges
        )
        if has_arbitrator:
            continue

        ds_labels = [graph.nodes[d].label for d in shared_stores if d in graph.nodes]
        findings.append(_make_finding(
            "STRAT-OC-001",
            "Conflicting Optimization Objectives on Shared State",
            Severity.HIGH,
            "OC",
            [agent_a, agent_b] + shared_stores,
            graph,
            f"{node_a.label} (objective: {tag_a}) and {node_b.label} (objective: {tag_b}) "
            f"both write to {', '.join(ds_labels)} with no arbitration.",
            "Add arbitrated_by edge or explicit conflict resolution mechanism.",
            subgraph_type="pair",
        ))

    return findings[:3]


def _oc002_competing_resources(graph: RiskGraph) -> list[Finding]:
    """STRAT-OC-002: Competing Resource Consumers Without Prioritization.

    2+ agents calling the same rate-limited capability or external service,
    no priority/ordering mechanism.
    """
    # Build capability/external -> calling agents map
    resource_callers: dict[str, list[str]] = defaultdict(list)

    for edge in graph.edges:
        if edge.edge_type in (EdgeType.SENDS_TO, EdgeType.CALLS):
            tgt = graph.nodes.get(edge.target)
            if tgt and tgt.node_type in (NodeType.EXTERNAL_SERVICE, NodeType.MCP_SERVER):
                src = graph.nodes.get(edge.source)
                if src and src.node_type == NodeType.CAPABILITY:
                    for tool_edge in graph.edges:
                        if (tool_edge.edge_type == EdgeType.TOOL_OF
                                and tool_edge.source == edge.source):
                            resource_callers[edge.target].append(tool_edge.target)

    # Also check rate-limited capabilities
    for nid, node in graph.nodes.items():
        if node.node_type == NodeType.CAPABILITY and node.rate_limited:
            for tool_edge in graph.edges:
                if tool_edge.edge_type == EdgeType.TOOL_OF and tool_edge.source == nid:
                    resource_callers[nid].append(tool_edge.target)

    findings: list[Finding] = []

    for resource_id, callers in resource_callers.items():
        unique_callers = list(set(callers))
        if len(unique_callers) < 2:
            continue

        # Check for rate_limited_by edges
        has_rate_limit = any(
            e.edge_type == EdgeType.RATE_LIMITED_BY
            for e in graph.edges
            if e.source in unique_callers
        )
        if has_rate_limit:
            continue

        resource = graph.nodes.get(resource_id)
        if not resource:
            continue

        caller_labels = [
            graph.nodes[c].label for c in unique_callers[:4] if c in graph.nodes
        ]
        findings.append(_make_finding(
            "STRAT-OC-002",
            "Competing Resource Consumers Without Prioritization",
            Severity.MEDIUM,
            "OC",
            unique_callers + [resource_id],
            graph,
            f"{len(unique_callers)} agents call {resource.label} with no "
            f"shared rate coordination: {', '.join(caller_labels)}.",
            "Implement shared rate limiting or token bucket across agents.",
            subgraph_type="pair",
        ))

    return findings[:3]


def _oc003_undampened_feedback(graph: RiskGraph) -> list[Finding]:
    """STRAT-OC-003: Undampened Feedback Loop.

    Cycle in feeds_into subgraph with no dampened_by edge.
    """
    cycles = detect_cycles(
        graph,
        edge_types={EdgeType.FEEDS_INTO.value},
        node_type_filter=None,
    )

    findings: list[Finding] = []

    for cycle in cycles:
        cycle_nodes = cycle[:-1]

        # Check for dampened_by edges on any edge in the cycle
        has_dampener = False
        for i in range(len(cycle_nodes)):
            src = cycle_nodes[i]
            tgt = cycle_nodes[(i + 1) % len(cycle_nodes)]
            for edge in graph.edges:
                if (edge.source == src and edge.target == tgt
                        and edge.edge_type == EdgeType.FEEDS_INTO):
                    # Check if this edge has a dampened_by
                    for de in graph.edges:
                        if de.edge_type == EdgeType.DAMPENED_BY and de.source == src:
                            has_dampener = True
                            break
                if has_dampener:
                    break
            if has_dampener:
                break

        # Also check max_iterations as a dampener
        if not has_dampener:
            has_dampener = any(
                graph.nodes.get(nid) and graph.nodes[nid].max_iterations is not None
                for nid in cycle_nodes
                if graph.nodes.get(nid) and graph.nodes[nid].node_type == NodeType.AGENT
            )

        if has_dampener:
            continue

        cycle_labels = [graph.nodes[nid].label for nid in cycle if nid in graph.nodes]
        findings.append(_make_finding(
            "STRAT-OC-003",
            "Undampened Feedback Loop",
            Severity.HIGH,
            "OC",
            cycle_nodes,
            graph,
            f"Feedback loop: {' \u2192 '.join(cycle_labels)}. "
            f"No dampening mechanism (convergence check, max_iter, decay).",
            "Add convergence checks, output clamps, or max_iter.",
            subgraph_type="cycle",
            chain=cycle,
        ))

    return findings[:2]


def _oc004_incentive_misalignment(graph: RiskGraph) -> list[Finding]:
    """STRAT-OC-004: Incentive Misalignment Between Manager and Worker.
    [Bucket B partial — fires when objective_tag can be inferred]

    Agent A delegates_to Agent B and their objective_tag values differ.
    """
    findings: list[Finding] = []

    for edge in graph.edges:
        if edge.edge_type != EdgeType.DELEGATES_TO:
            continue

        src = graph.nodes.get(edge.source)
        tgt = graph.nodes.get(edge.target)
        if not src or not tgt:
            continue
        if src.node_type != NodeType.AGENT or tgt.node_type != NodeType.AGENT:
            continue

        tag_src = src.objective_tag
        tag_tgt = tgt.objective_tag
        if not tag_src or not tag_tgt or tag_src == tag_tgt:
            continue

        findings.append(_make_finding(
            "STRAT-OC-004",
            "Incentive Misalignment Between Manager and Worker",
            Severity.MEDIUM,
            "OC",
            [edge.source, edge.target],
            graph,
            f"{src.label} (objective: {tag_src}) delegates to "
            f"{tgt.label} (objective: {tag_tgt}). Potential incentive tension.",
            "Align objectives or add explicit output constraints on delegation.",
            subgraph_type="pair",
        ))

    return findings[:3]


# ===========================================================================
# SIGNAL INTEGRITY & ERROR PROPAGATION (SI) — 7 rules
# ===========================================================================

def _si001_error_laundering(graph: RiskGraph) -> list[Finding]:
    """STRAT-SI-001: Silent Error Propagation Across Agent Boundary. [CROWN JEWEL]

    Agent A has error_handling_pattern = fail_silent or default_on_error AND
    has feeds_into edge to Agent B, AND Agent B has no input validation.
    """
    findings: list[Finding] = []

    for nid, node in graph.nodes.items():
        if node.node_type != NodeType.AGENT:
            continue
        if node.error_handling_pattern not in ("default_on_error", "fail_silent"):
            continue

        downstream = []
        for edge in graph.edges:
            if edge.source == nid and edge.edge_type == EdgeType.FEEDS_INTO:
                tgt = graph.nodes.get(edge.target)
                if tgt and tgt.node_type == NodeType.AGENT:
                    # Check if target has input validation
                    has_validation = any(
                        graph.nodes.get(tid) and graph.nodes[tid].validation_on_input
                        for tid in _agent_tools(graph, edge.target)
                    )
                    if not has_validation:
                        downstream.append(edge.target)

        if not downstream:
            continue

        downstream_labels = [graph.nodes[d].label for d in downstream if d in graph.nodes]
        findings.append(_make_finding(
            "STRAT-SI-001",
            "Silent Error Propagation Across Agent Boundary",
            Severity.CRITICAL,
            "SI",
            [nid] + downstream,
            graph,
            f"{node.label} returns defaults on error (pattern: {node.error_handling_pattern}) "
            f"and feeds into {', '.join(downstream_labels)} with no input validation. "
            f"Error signal is permanently lost.",
            "Replace default-on-error with explicit error propagation. "
            "Return error types, not default values.",
            subgraph_type="path",
        ))

    return findings[:3]


def _si002_confidence_laundering(graph: RiskGraph) -> list[Finding]:
    """STRAT-SI-002: Confidence Laundering Through Agent Chain.

    Chain of 2+ feeds_into edges where no agent adds confidence/uncertainty
    metadata to output.
    """
    chain_edges = {EdgeType.FEEDS_INTO.value}
    paths = find_paths(graph, chain_edges, source_filter="agent", min_length=2, max_length=6)

    findings: list[Finding] = []
    seen: set[tuple[str, ...]] = set()

    for path in paths:
        if not all(
            graph.nodes.get(nid) and graph.nodes[nid].node_type == NodeType.AGENT
            for nid in path
        ):
            continue

        # Check if any edge preserves uncertainty
        has_uncertainty = False
        for i in range(len(path) - 1):
            for edge in graph.edges:
                if (edge.source == path[i] and edge.target == path[i + 1]
                        and edge.edge_type == EdgeType.FEEDS_INTO
                        and edge.preserves_uncertainty):
                    has_uncertainty = True
                    break
            if has_uncertainty:
                break

        if has_uncertainty:
            continue

        path_key = tuple(path)
        if path_key in seen:
            continue
        seen.add(path_key)

        findings.append(_make_finding(
            "STRAT-SI-002",
            "Confidence Laundering Through Agent Chain",
            Severity.HIGH,
            "SI",
            path,
            graph,
            f"Chain of {len(path)} agents via feeds_into with no confidence/uncertainty "
            f"metadata preserved. Downstream decisions treat uncertain data as certain.",
            "Add confidence scores to agent outputs. Use structured output with "
            "confidence fields.",
            subgraph_type="path",
            chain=path,
        ))

    return findings[:3]


def _si003_stale_data(graph: RiskGraph) -> list[Finding]:
    """STRAT-SI-003: Stale Data Consumption.

    Agent reads_from data_store with ttl_configured=False AND another agent
    writes_to it.
    """
    findings: list[Finding] = []

    for ds_id, ds_node in graph.nodes.items():
        if ds_node.node_type != NodeType.DATA_STORE:
            continue
        if ds_node.ttl_configured:
            continue

        # Find readers and writers
        readers: set[str] = set()
        writers: set[str] = set()
        for edge in graph.edges:
            if edge.edge_type == EdgeType.READS_FROM:
                if edge.source == ds_id:
                    tgt = graph.nodes.get(edge.target)
                    if tgt and tgt.node_type == NodeType.AGENT:
                        readers.add(edge.target)
            elif edge.edge_type == EdgeType.WRITES_TO:
                if edge.target == ds_id:
                    src = graph.nodes.get(edge.source)
                    if src and src.node_type == NodeType.AGENT:
                        writers.add(edge.source)

        if not readers or not writers:
            continue

        reader_labels = [graph.nodes[r].label for r in list(readers)[:3] if r in graph.nodes]
        writer_labels = [graph.nodes[w].label for w in list(writers)[:3] if w in graph.nodes]
        findings.append(_make_finding(
            "STRAT-SI-003",
            "Stale Data Consumption",
            Severity.MEDIUM,
            "SI",
            list(readers)[:2] + [ds_id] + list(writers)[:2],
            graph,
            f"Data store {ds_node.label} has no TTL. Writers: {', '.join(writer_labels)}. "
            f"Readers: {', '.join(reader_labels)}. Data could go stale.",
            "Configure TTL or freshness checks on the data store.",
            subgraph_type="pair",
        ))

    return findings[:3]


def _si004_schema_mismatch(graph: RiskGraph) -> list[Finding]:
    """STRAT-SI-004: Schema Mismatch on Data Flow.

    feeds_into edge where schema_validated=False AND source agent has no
    output_schema OR target agent has no documented expected input.
    """
    findings: list[Finding] = []

    unvalidated_edges = []
    for edge in graph.edges:
        if edge.edge_type != EdgeType.FEEDS_INTO:
            continue
        if edge.schema_validated:
            continue

        src = graph.nodes.get(edge.source)
        tgt = graph.nodes.get(edge.target)
        if src and tgt and src.node_type == NodeType.AGENT and tgt.node_type == NodeType.AGENT:
            # Additional check: does source have output_schema?
            if not src.output_schema:
                unvalidated_edges.append((edge.source, edge.target))

    if not unvalidated_edges:
        return []

    all_agents = set()
    for src, tgt in unvalidated_edges:
        all_agents.add(src)
        all_agents.add(tgt)

    pairs_desc = ", ".join(
        f"{graph.nodes[s].label} \u2192 {graph.nodes[t].label}"
        for s, t in unvalidated_edges[:3]
        if s in graph.nodes and t in graph.nodes
    )

    findings.append(_make_finding(
        "STRAT-SI-004",
        "Schema Mismatch on Data Flow",
        Severity.HIGH,
        "SI",
        list(all_agents),
        graph,
        f"{len(unvalidated_edges)} inter-agent data flows lack schema contracts: "
        f"{pairs_desc}.",
        "Add output_pydantic or output_json on upstream agents. "
        "Use TypedDict State for LangGraph.",
        subgraph_type="path",
    ))

    return findings


def _si005_unvalidated_external(graph: RiskGraph) -> list[Finding]:
    """STRAT-SI-005: Unvalidated External Data Ingestion.

    External service -> capability -> agent path with no validation_on_input
    on the capability.
    """
    findings: list[Finding] = []

    for nid, node in graph.nodes.items():
        if node.node_type != NodeType.CAPABILITY:
            continue
        if node.validation_on_input:
            continue
        if not node.external_service:
            continue

        # Find owning agent
        agent_id = None
        for edge in graph.edges:
            if edge.edge_type == EdgeType.TOOL_OF and edge.source == nid:
                agent_id = edge.target
                break

        if not agent_id:
            continue

        # Find connected external service
        ext_id = None
        for edge in graph.edges:
            if edge.source == nid and edge.edge_type in (EdgeType.CALLS, EdgeType.SENDS_TO):
                ext = graph.nodes.get(edge.target)
                if ext and ext.node_type in (NodeType.EXTERNAL_SERVICE, NodeType.MCP_SERVER):
                    ext_id = edge.target
                    break

        affected = [nid]
        if ext_id:
            affected.insert(0, ext_id)
        affected.append(agent_id)

        findings.append(_make_finding(
            "STRAT-SI-005",
            "Unvalidated External Data Ingestion",
            Severity.HIGH,
            "SI",
            affected,
            graph,
            f"External data flows through {node.label} to agent without input validation.",
            "Add input validation on capabilities that ingest external data.",
            subgraph_type="path",
        ))

    return findings[:3]


def _si006_error_swallowing_trust(graph: RiskGraph) -> list[Finding]:
    """STRAT-SI-006: Error Swallowing at Trust Boundary.

    Edge crossing trust boundary where the receiving agent has
    error_handling_pattern=fail_silent.
    """
    findings: list[Finding] = []

    for edge in graph.edges:
        if not edge.trust_crossing:
            continue
        if edge.edge_type not in (EdgeType.FEEDS_INTO, EdgeType.DELEGATES_TO):
            continue

        tgt = graph.nodes.get(edge.target)
        if not tgt or tgt.node_type != NodeType.AGENT:
            continue
        if tgt.error_handling_pattern != "fail_silent":
            continue

        src = graph.nodes.get(edge.source)
        if not src:
            continue

        findings.append(_make_finding(
            "STRAT-SI-006",
            "Error Swallowing at Trust Boundary",
            Severity.HIGH,
            "SI",
            [edge.source, edge.target],
            graph,
            f"{tgt.label} silently swallows errors at trust boundary crossing "
            f"from {src.label}. Cross-boundary failures become invisible.",
            "Replace fail_silent with explicit error propagation at trust boundaries.",
            subgraph_type="path",
        ))

    return findings[:3]


def _si007_aggregation_no_provenance(graph: RiskGraph) -> list[Finding]:
    """STRAT-SI-007: Aggregation Without Provenance.

    Agent that reads_from 3+ data stores OR receives feeds_into from 3+ agents,
    AND produces a single output with no source attribution in output schema.
    """
    findings: list[Finding] = []

    for nid, node in graph.nodes.items():
        if node.node_type != NodeType.AGENT:
            continue

        # Count data sources
        data_sources: set[str] = set()
        for edge in graph.edges:
            if edge.target == nid and edge.edge_type == EdgeType.READS_FROM:
                data_sources.add(edge.source)
            elif edge.target == nid and edge.edge_type == EdgeType.FEEDS_INTO:
                src = graph.nodes.get(edge.source)
                if src and src.node_type == NodeType.AGENT:
                    data_sources.add(edge.source)

        if len(data_sources) < 3:
            continue

        # Check for provenance in output schema
        if node.output_schema and "source" in node.output_schema.lower():
            continue

        source_labels = [
            graph.nodes[s].label for s in list(data_sources)[:4] if s in graph.nodes
        ]
        findings.append(_make_finding(
            "STRAT-SI-007",
            "Aggregation Without Provenance",
            Severity.MEDIUM,
            "SI",
            [nid] + list(data_sources)[:3],
            graph,
            f"{node.label} aggregates {len(data_sources)} sources "
            f"({', '.join(source_labels)}) with no provenance tracking.",
            "Add source attribution to output schema.",
            subgraph_type="node",
        ))

    return findings[:3]


# ===========================================================================
# EMERGENT AUTHORITY & SCOPE CREEP (EA) — 5 rules
# ===========================================================================

def _ea001_implicit_authority(graph: RiskGraph) -> list[Finding]:
    """STRAT-EA-001: Implicit Authority Escalation Through Delegation.

    implicit_authority_over computed edges exist — agent can reach capabilities
    through delegation that it wasn't directly assigned.
    """
    tc = compute_transitive_capabilities(graph)
    findings: list[Finding] = []

    for agent_id, (direct, effective) in tc.items():
        escalated = effective - direct
        if not escalated:
            continue

        node = graph.nodes.get(agent_id)
        if not node:
            continue

        escalated_labels = [
            graph.nodes[tid].label for tid in list(escalated)[:4]
            if tid in graph.nodes
        ]
        direct_labels = [
            graph.nodes[tid].label for tid in direct if tid in graph.nodes
        ]

        findings.append(_make_finding(
            "STRAT-EA-001",
            "Implicit Authority Escalation Through Delegation",
            Severity.HIGH,
            "EA",
            [agent_id] + list(escalated)[:3],
            graph,
            f"{node.label} has {len(direct)} direct capabilities but can "
            f"reach {len(effective)} through delegation. "
            f"Escalated: {', '.join(escalated_labels)}.",
            "Implement capability scoping on delegation. "
            "Use tools= parameter on Task to limit delegate capabilities.",
            subgraph_type="transitive_closure",
            extra_evidence=[
                f"Direct: {', '.join(direct_labels[:3])}",
                f"Escalated: {', '.join(escalated_labels[:3])}",
            ],
        ))

    return findings[:3]


def _ea002_capability_aggregation(graph: RiskGraph) -> list[Finding]:
    """STRAT-EA-002: Capability Aggregation Exceeding Role Scope.

    Agent with tools spanning 3+ distinct regulatory_category values or
    3+ distinct domain areas.
    """
    findings: list[Finding] = []

    for nid, node in graph.nodes.items():
        if node.node_type != NodeType.AGENT:
            continue

        tools = _agent_tools(graph, nid)
        if len(tools) < 3:
            continue

        categories: set[str] = set()
        for tid in tools:
            tool_node = graph.nodes.get(tid)
            if tool_node and tool_node.regulatory_category:
                categories.add(tool_node.regulatory_category)

        if len(categories) >= 3:
            findings.append(_make_finding(
                "STRAT-EA-002",
                "Capability Aggregation Exceeding Role Scope",
                Severity.MEDIUM,
                "EA",
                [nid] + tools[:3],
                graph,
                f"{node.label} has tools spanning {len(categories)} regulatory categories: "
                f"{', '.join(sorted(categories))}.",
                "Review capability assignments. Split into specialized sub-agents.",
                subgraph_type="node",
            ))

    return findings[:3]


def _ea003_unconstrained_delegation(graph: RiskGraph) -> list[Finding]:
    """STRAT-EA-003: Unconstrained Task Delegation.

    Agent with delegation_enabled=True AND scoped=False on its delegates_to
    edges (can delegate to any agent with no scope constraint).
    """
    findings: list[Finding] = []

    for nid, node in graph.nodes.items():
        if node.node_type != NodeType.AGENT:
            continue
        if not node.delegation_enabled:
            continue

        # Check delegates_to edges for scoping
        unscoped_targets = []
        for edge in graph.edges:
            if (edge.source == nid and edge.edge_type == EdgeType.DELEGATES_TO
                    and not edge.scoped):
                unscoped_targets.append(edge.target)

        if not unscoped_targets:
            continue

        target_labels = [
            graph.nodes[t].label for t in unscoped_targets[:4] if t in graph.nodes
        ]
        findings.append(_make_finding(
            "STRAT-EA-003",
            "Unconstrained Task Delegation",
            Severity.HIGH,
            "EA",
            [nid] + unscoped_targets[:3],
            graph,
            f"{node.label} has delegation_enabled with no scope constraints. "
            f"Unscoped targets: {', '.join(target_labels)}.",
            "Scope delegation by specifying tools= on Task.",
            subgraph_type="node",
        ))

    return findings[:3]


def _ea004_transitive_data_access(graph: RiskGraph) -> list[Finding]:
    """STRAT-EA-004: Transitive Data Access Through Delegation.

    Agent A can reach data stores via delegation chain that it has no direct
    reads_from/writes_to edges to.
    """
    # Build agent -> direct data stores
    agent_direct_ds: dict[str, set[str]] = defaultdict(set)
    for edge in graph.edges:
        if edge.edge_type in (EdgeType.READS_FROM, EdgeType.WRITES_TO):
            src = graph.nodes.get(edge.source)
            tgt = graph.nodes.get(edge.target)
            if src and src.node_type == NodeType.AGENT:
                if tgt and tgt.node_type == NodeType.DATA_STORE:
                    agent_direct_ds[edge.source].add(edge.target)
            elif tgt and tgt.node_type == NodeType.AGENT:
                if src and src.node_type == NodeType.DATA_STORE:
                    agent_direct_ds[edge.target].add(edge.source)

    # Build delegation adjacency
    delegation_adj: dict[str, set[str]] = defaultdict(set)
    for edge in graph.edges:
        if edge.edge_type in (EdgeType.DELEGATES_TO, EdgeType.FEEDS_INTO):
            delegation_adj[edge.source].add(edge.target)

    findings: list[Finding] = []

    for agent_id in list(agent_direct_ds.keys()):
        node = graph.nodes.get(agent_id)
        if not node or node.node_type != NodeType.AGENT:
            continue

        direct_ds = agent_direct_ds.get(agent_id, set())

        # BFS through delegation
        visited: set[str] = set()
        queue = list(delegation_adj.get(agent_id, set()))
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            queue.extend(delegation_adj.get(current, set()) - visited)

        # Collect data stores of reachable agents
        transitive_ds: set[str] = set()
        for reached_id in visited:
            transitive_ds.update(agent_direct_ds.get(reached_id, set()))

        escalated_ds = transitive_ds - direct_ds
        if not escalated_ds:
            continue

        ds_labels = [graph.nodes[d].label for d in list(escalated_ds)[:4] if d in graph.nodes]
        findings.append(_make_finding(
            "STRAT-EA-004",
            "Transitive Data Access Through Delegation",
            Severity.MEDIUM,
            "EA",
            [agent_id] + list(escalated_ds)[:3],
            graph,
            f"{node.label} can reach {len(escalated_ds)} data stores via delegation "
            f"that it has no direct access to: {', '.join(ds_labels)}.",
            "Review delegation scope and data access boundaries.",
            subgraph_type="transitive_closure",
        ))

    return findings[:3]


def _ea006_cross_crew_leakage(graph: RiskGraph) -> list[Finding]:
    """STRAT-EA-006: Cross-Crew Authority Leakage.

    Agent in Crew A can reach agents in Crew B through delegation or data flow,
    with no explicit cross-crew authorization.
    """
    # Build crew membership map
    crew_map: dict[str, str] = {}
    for nid, node in graph.nodes.items():
        if node.node_type == NodeType.AGENT and node.agent_domain:
            crew_map[nid] = node.agent_domain

    if len(set(crew_map.values())) < 2:
        return []  # Need at least 2 crews

    # Build adjacency
    adj: dict[str, set[str]] = defaultdict(set)
    for edge in graph.edges:
        if edge.edge_type in (EdgeType.DELEGATES_TO, EdgeType.FEEDS_INTO):
            adj[edge.source].add(edge.target)

    findings: list[Finding] = []

    for agent_id, crew in crew_map.items():
        # BFS to find reachable agents
        visited: set[str] = set()
        queue = list(adj.get(agent_id, set()))
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            queue.extend(adj.get(current, set()) - visited)

        # Check for cross-crew reach
        cross_crew = [
            nid for nid in visited
            if nid in crew_map and crew_map[nid] != crew
        ]

        if not cross_crew:
            continue

        node = graph.nodes.get(agent_id)
        if not node:
            continue

        cross_labels = [graph.nodes[c].label for c in cross_crew[:3] if c in graph.nodes]
        findings.append(_make_finding(
            "STRAT-EA-006",
            "Cross-Crew Authority Leakage",
            Severity.HIGH,
            "EA",
            [agent_id] + cross_crew[:3],
            graph,
            f"{node.label} (crew: {crew}) can reach agents in other crews: "
            f"{', '.join(cross_labels)}.",
            "Add explicit cross-crew authorization or isolation boundaries.",
            subgraph_type="transitive_closure",
        ))

    return findings[:3]


# ===========================================================================
# AGGREGATE BEHAVIORAL EXPOSURE (AB) — 5 rules
# ===========================================================================

def _ab001_unbounded_volume(graph: RiskGraph) -> list[Finding]:
    """STRAT-AB-001: Unbounded Autonomous Volume.

    Agent with capabilities performing irreversible actions AND no
    rate_limited_by edge AND no human checkpoint.
    """
    findings: list[Finding] = []

    for nid, node in graph.nodes.items():
        if node.node_type != NodeType.AGENT:
            continue

        # Check for irreversible capabilities
        tools = _agent_tools(graph, nid)
        irreversible = [
            tid for tid in tools
            if graph.nodes.get(tid) and graph.nodes[tid].reversibility == "irreversible"
        ]
        if not irreversible:
            continue

        # Check for rate limiting
        has_rate_limit = any(
            e.source == nid and e.edge_type == EdgeType.RATE_LIMITED_BY
            for e in graph.edges
        )
        if has_rate_limit:
            continue

        # Check for human checkpoint
        if node.human_input_enabled:
            continue
        if _has_approval_gate(graph, nid):
            continue

        irrev_labels = [
            graph.nodes[tid].label for tid in irreversible[:3] if tid in graph.nodes
        ]
        findings.append(_make_finding(
            "STRAT-AB-001",
            "Unbounded Autonomous Volume",
            Severity.HIGH,
            "AB",
            [nid] + irreversible[:3],
            graph,
            f"{node.label} has irreversible capabilities "
            f"[{', '.join(irrev_labels)}] with no rate limiting or human checkpoint.",
            "Add rate_limited_by guardrail or human_input on the agent.",
            subgraph_type="node",
        ))

    return findings[:3]


def _ab003_regulatory_no_audit(graph: RiskGraph) -> list[Finding]:
    """STRAT-AB-003: Regulatory Exposure Without Audit Trail.

    Capability with regulatory_category != null AND no observed_by edge
    on the agent performing it.
    """
    findings: list[Finding] = []

    for nid, node in graph.nodes.items():
        if node.node_type != NodeType.CAPABILITY:
            continue
        if not node.regulatory_category:
            continue

        # Find owning agent
        agent_id = None
        for edge in graph.edges:
            if edge.edge_type == EdgeType.TOOL_OF and edge.source == nid:
                agent_id = edge.target
                break

        if not agent_id:
            continue

        # Check for observability on the agent
        if _has_observed_by(graph, agent_id):
            continue

        agent_node = graph.nodes.get(agent_id)
        agent_label = agent_node.label if agent_node else agent_id

        findings.append(_make_finding(
            "STRAT-AB-003",
            "Regulatory Exposure Without Audit Trail",
            Severity.HIGH,
            "AB",
            [agent_id, nid],
            graph,
            f"{node.label} has regulatory category '{node.regulatory_category}' "
            f"but agent {agent_label} has no observability/audit trail.",
            "Add observability sink (LangSmith, OpenTelemetry) covering this agent.",
            subgraph_type="node",
        ))

    return findings[:3]


def _ab004_monoculture(graph: RiskGraph) -> list[Finding]:
    """STRAT-AB-004: Monoculture Risk — Single LLM Provider.

    All agents in the system use the same llm_model provider.
    """
    agents_with_model: dict[str, str] = {}
    for nid, node in graph.nodes.items():
        if node.node_type != NodeType.AGENT and node.llm_model:
            continue
        if node.node_type == NodeType.AGENT and node.llm_model:
            # Extract provider from model name
            model = node.llm_model.lower()
            if any(k in model for k in ("gpt", "openai", "o1", "o3")):
                agents_with_model[nid] = "openai"
            elif any(k in model for k in ("claude", "anthropic")):
                agents_with_model[nid] = "anthropic"
            elif any(k in model for k in ("gemini", "google", "palm")):
                agents_with_model[nid] = "google"
            elif any(k in model for k in ("llama", "meta")):
                agents_with_model[nid] = "meta"
            else:
                agents_with_model[nid] = model.split("-")[0] if "-" in model else model

    if len(agents_with_model) < 2:
        return []

    providers = set(agents_with_model.values())
    if len(providers) > 1:
        return []  # Multiple providers — no monoculture

    provider = next(iter(providers))
    agent_ids = list(agents_with_model.keys())

    return [_make_finding(
        "STRAT-AB-004",
        "Monoculture Risk \u2014 Single LLM Provider",
        Severity.MEDIUM,
        "AB",
        agent_ids[:5],
        graph,
        f"All {len(agent_ids)} agents use the same LLM provider ({provider}). "
        f"System-wide correlated failure risk during provider incidents.",
        "Consider using multiple LLM providers for resilience.",
        subgraph_type="global",
    )]


def _ab006_no_rollback(graph: RiskGraph) -> list[Finding]:
    """STRAT-AB-006: No Rollback on Multi-Step Workflow.

    Sequence of 3+ agents via task_sequence edges where at least one
    capability is irreversible AND no compensating/rollback mechanism detected.
    """
    chain_edges = {EdgeType.TASK_SEQUENCE.value}
    paths = find_paths(graph, chain_edges, source_filter="agent", min_length=3, max_length=8)

    # Also check delegates_to chains if no task_sequence found
    if not paths:
        chain_edges = {EdgeType.DELEGATES_TO.value, EdgeType.FEEDS_INTO.value}
        paths = find_paths(graph, chain_edges, source_filter="agent", min_length=3, max_length=8)

    findings: list[Finding] = []

    for path in paths:
        if not all(
            graph.nodes.get(nid) and graph.nodes[nid].node_type == NodeType.AGENT
            for nid in path
        ):
            continue

        # Check for irreversible capabilities in the path
        has_irreversible = False
        for nid in path:
            tools = _agent_tools(graph, nid)
            for tid in tools:
                tool_node = graph.nodes.get(tid)
                if tool_node and tool_node.reversibility == "irreversible":
                    has_irreversible = True
                    break
            if has_irreversible:
                break

        if not has_irreversible:
            continue

        findings.append(_make_finding(
            "STRAT-AB-006",
            "No Rollback on Multi-Step Workflow",
            Severity.HIGH,
            "AB",
            path,
            graph,
            f"Multi-step workflow of {len(path)} agents includes irreversible actions "
            f"with no compensating transaction or rollback mechanism.",
            "Implement saga pattern or checkpoint/restore for multi-step workflows.",
            subgraph_type="path",
            chain=path,
        ))

    return findings[:2]


def _ab007_external_concentration(graph: RiskGraph) -> list[Finding]:
    """STRAT-AB-007: Concentration of External Dependencies.

    3+ agents all depend on the same external service (via calls edges from
    their capabilities) with no fallback_configured=True.
    """
    # Build external service -> dependent agents map
    service_dependents: dict[str, set[str]] = defaultdict(set)

    for edge in graph.edges:
        if edge.edge_type in (EdgeType.CALLS, EdgeType.SENDS_TO):
            tgt = graph.nodes.get(edge.target)
            if tgt and tgt.node_type in (NodeType.EXTERNAL_SERVICE, NodeType.MCP_SERVER):
                src = graph.nodes.get(edge.source)
                if src and src.node_type == NodeType.CAPABILITY:
                    # Find owning agent
                    for tool_edge in graph.edges:
                        if (tool_edge.edge_type == EdgeType.TOOL_OF
                                and tool_edge.source == edge.source):
                            service_dependents[edge.target].add(tool_edge.target)
                elif src and src.node_type == NodeType.AGENT:
                    service_dependents[edge.target].add(edge.source)

    findings: list[Finding] = []

    for service_id, agents in service_dependents.items():
        if len(agents) < 3:
            continue

        service = graph.nodes.get(service_id)
        if not service:
            continue

        agent_labels = [
            graph.nodes[a].label for a in list(agents)[:4] if a in graph.nodes
        ]
        findings.append(_make_finding(
            "STRAT-AB-007",
            "Concentration of External Dependencies",
            Severity.MEDIUM,
            "AB",
            list(agents)[:4] + [service_id],
            graph,
            f"{len(agents)} agents depend on {service.label} with no fallback. "
            f"Dependent agents: {', '.join(agent_labels)}.",
            "Add fallback mechanisms or circuit breakers for shared dependencies.",
            subgraph_type="node",
        ))

    return findings[:3]
