"""Reliability finding engine — 18 Bucket A rules.

Each rule uses graph traversal primitives. Rules are labeling functions
that run AFTER graph construction and enrichment. They annotate the graph.

Categories:
- DC: Decision Chain Risk (8 rules)
- OC: Objective & Incentive Conflict (3 static rules)
- SI: Signal Integrity & Error Propagation (4 static rules)
- EA: Emergent Authority & Scope Creep (3 rules)
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
    """Run all 18 Bucket A reliability rules on the enriched graph.

    Returns list of reliability findings. Does NOT modify security findings.
    """
    if not graph or not graph.nodes:
        return []

    findings: list[Finding] = []

    # Decision Chain Risk
    findings.extend(_dc001_unsupervised_chain(graph))
    findings.extend(_dc002_irreversible_no_checkpoint(graph))
    findings.extend(_dc003_depth_exceeds_observability(graph))
    findings.extend(_dc004_circular_delegation(graph))
    findings.extend(_dc005_bottleneck(graph))
    findings.extend(_dc006_fanout_no_consolidation(graph))
    findings.extend(_dc007_no_rollback(graph))
    findings.extend(_dc008_no_timeout(graph))

    # Objective & Incentive Conflict (static subset)
    findings.extend(_oc002_uncoordinated_writes(graph))
    findings.extend(_oc003_feedback_loop(graph))
    findings.extend(_oc005_resource_contention(graph))

    # Signal Integrity
    findings.extend(_si001_error_laundering(graph))
    findings.extend(_si004_unvalidated_schema(graph))
    findings.extend(_si006_untyped_channel(graph))
    findings.extend(_si007_single_data_source(graph))

    # Emergent Authority
    findings.extend(_ea001_transitive_escalation(graph))
    findings.extend(_ea002_unbounded_delegation(graph))
    findings.extend(_ea003_mcp_aggregation(graph))

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _agent_has_hitl(graph: RiskGraph, agent_id: str) -> bool:
    """Check if an agent has a human-in-the-loop gate."""
    for edge in graph.edges:
        if edge.source == agent_id and edge.edge_type == EdgeType.GATED_BY:
            guard = graph.nodes.get(edge.target)
            if guard and guard.guardrail_kind in ("hitl", "human_in_the_loop"):
                return True
    return False


def _agent_tools(graph: RiskGraph, agent_id: str) -> list[str]:
    """Get tool node IDs owned by an agent."""
    return [e.source for e in graph.edges
            if e.edge_type == EdgeType.TOOL_OF and e.target == agent_id]


def _tool_kinds(graph: RiskGraph, tool_ids: list[str]) -> set[str]:
    """Extract capability kinds from tool node IDs."""
    kinds = set()
    for tid in tool_ids:
        if "_" in tid:
            kind = tid.rsplit("_", 1)[-1]
            kinds.add(kind)
    return kinds


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
# DECISION CHAIN RISK (DC)
# ===========================================================================

def _dc001_unsupervised_chain(graph: RiskGraph) -> list[Finding]:
    """STRAT-DC-001: Unsupervised Multi-Agent Decision Chain.

    Path of length >= 3 through delegates_to/feeds_into with zero HITL gates.
    CRITICAL if terminal agent has financial/destructive/outbound tools, else HIGH.
    """
    chain_edges = {EdgeType.DELEGATES_TO.value, EdgeType.FEEDS_INTO.value}
    paths = find_paths(graph, chain_edges, source_filter="agent", min_length=3, max_length=8)

    findings: list[Finding] = []
    seen_paths: set[tuple[str, ...]] = set()

    for path in paths:
        # All nodes must be agents
        if not all(
            graph.nodes.get(nid) and graph.nodes[nid].node_type == NodeType.AGENT
            for nid in path
        ):
            continue

        # Check for HITL gates on any node in the path
        has_gate = any(_agent_has_hitl(graph, nid) for nid in path)
        if has_gate:
            continue

        path_key = tuple(path)
        if path_key in seen_paths:
            continue
        seen_paths.add(path_key)

        # Check terminal agent capabilities
        terminal = path[-1]
        tools = _agent_tools(graph, terminal)
        kinds = _tool_kinds(graph, tools)
        high_risk = kinds & {"financial", "destructive", "outbound"}

        severity = Severity.CRITICAL if high_risk else Severity.HIGH

        findings.append(_make_finding(
            "STRAT-DC-001",
            "Unsupervised Multi-Agent Decision Chain",
            severity,
            "DC",
            path,
            graph,
            f"Decision chain of {len(path)} agents with 0 human gates. "
            f"Terminal capabilities: {', '.join(high_risk) if high_risk else 'none flagged'}.",
            "Add human_input=True (CrewAI) or interrupt_before (LangGraph) "
            "before agents with consequential capabilities.",
            subgraph_type="path",
            chain=path,
        ))

    # Keep only the longest non-overlapping chains
    findings.sort(key=lambda f: len(f.evidence), reverse=True)
    return findings[:3]


def _dc002_irreversible_no_checkpoint(graph: RiskGraph) -> list[Finding]:
    """STRAT-DC-002: Irreversible Action Without Checkpoint.

    Agent with irreversible capabilities and no upstream HITL gate.
    """
    findings: list[Finding] = []

    for nid, node in graph.nodes.items():
        if node.node_type != NodeType.AGENT:
            continue

        # Get agent's tools and check for irreversible ones
        tools = _agent_tools(graph, nid)
        irreversible = []
        for tid in tools:
            tool_node = graph.nodes.get(tid)
            if tool_node and tool_node.reversibility == "irreversible":
                irreversible.append(tid)

        if not irreversible:
            continue

        # Check for HITL gate
        if _agent_has_hitl(graph, nid):
            continue

        irreversible_labels = [
            graph.nodes[tid].label for tid in irreversible if tid in graph.nodes
        ]
        findings.append(_make_finding(
            "STRAT-DC-002",
            "Irreversible Action Without Checkpoint",
            Severity.CRITICAL,
            "DC",
            [nid] + irreversible,
            graph,
            f"{node.label} has irreversible capabilities "
            f"[{', '.join(irreversible_labels)}] with no human approval gate.",
            "Add human_input=True on the Task or interrupt_before at compile time.",
            subgraph_type="node",
        ))

    return findings[:5]


def _dc003_depth_exceeds_observability(graph: RiskGraph) -> list[Finding]:
    """STRAT-DC-003: Decision Depth Exceeds Observability.

    Chain of depth >= 3 where some agents lack observed_by edges.
    """
    chain_edges = {EdgeType.DELEGATES_TO.value, EdgeType.FEEDS_INTO.value}
    paths = find_paths(graph, chain_edges, source_filter="agent", min_length=3, max_length=8)

    findings: list[Finding] = []

    for path in paths:
        if not all(
            graph.nodes.get(nid) and graph.nodes[nid].node_type == NodeType.AGENT
            for nid in path
        ):
            continue

        # Check which agents lack observed_by edges
        unobserved = []
        for nid in path:
            has_obs = any(
                e.source == nid and e.edge_type == EdgeType.OBSERVED_BY
                for e in graph.edges
            )
            if not has_obs:
                unobserved.append(nid)

        if not unobserved:
            continue

        unobserved_labels = [graph.nodes[nid].label for nid in unobserved if nid in graph.nodes]
        findings.append(_make_finding(
            "STRAT-DC-003",
            "Decision Depth Exceeds Observability",
            Severity.HIGH,
            "DC",
            path,
            graph,
            f"Chain of {len(path)} agents; {len(unobserved)} unobserved: "
            f"{', '.join(unobserved_labels)}.",
            "Add per-agent logging callbacks. Configure RunnableConfig with "
            "callbacks at each node, not just the graph.",
            subgraph_type="path",
            chain=path,
        ))

    return findings[:3]


def _dc004_circular_delegation(graph: RiskGraph) -> list[Finding]:
    """STRAT-DC-004: Circular Delegation Path.

    Cycles in the delegation graph without termination conditions.
    """
    cycles = detect_cycles(graph, node_type_filter="agent")

    findings: list[Finding] = []

    for cycle in cycles:
        # Check for termination conditions (max_iter, convergence check)
        has_termination = any(
            graph.nodes.get(nid) and graph.nodes[nid].timeout_config
            for nid in cycle[:-1]
        )
        has_gate = any(_agent_has_hitl(graph, nid) for nid in cycle[:-1])

        if has_termination and has_gate:
            continue

        severity = Severity.CRITICAL if not has_termination and not has_gate else Severity.HIGH

        cycle_labels = [graph.nodes[nid].label for nid in cycle if nid in graph.nodes]
        findings.append(_make_finding(
            "STRAT-DC-004",
            "Circular Delegation Path",
            severity,
            "DC",
            cycle[:-1],
            graph,
            f"Cycle: {' \u2192 '.join(cycle_labels)}. "
            f"Termination: {'yes' if has_termination else 'none'}. "
            f"Human gate: {'yes' if has_gate else 'none'}.",
            "Set max_iter on the Crew or implement a should_continue conditional "
            "with iteration counting.",
            subgraph_type="cycle",
            chain=cycle,
        ))

    return findings[:3]


def _dc005_bottleneck(graph: RiskGraph) -> list[Finding]:
    """STRAT-DC-005: Single-Agent Bottleneck in Critical Path.

    Agent with high betweenness centrality on paths to critical capabilities.
    """
    centrality = compute_centrality(graph)
    if not centrality:
        return []

    # Find agents with centrality above threshold
    threshold = 0.3
    max_centrality = max(centrality.values()) if centrality else 0

    findings: list[Finding] = []

    for agent_id, score in centrality.items():
        if score < threshold or score < max_centrality * 0.7:
            continue

        node = graph.nodes.get(agent_id)
        if not node:
            continue

        findings.append(_make_finding(
            "STRAT-DC-005",
            "Single-Agent Bottleneck in Critical Path",
            Severity.MEDIUM,
            "DC",
            [agent_id],
            graph,
            f"{node.label} has betweenness centrality {score:.2f} — "
            f"all critical paths route through this agent.",
            "Introduce redundancy or parallel evaluation paths. "
            "Consider splitting into domain-specific sub-agents.",
            subgraph_type="node",
        ))

    return findings[:2]


def _dc006_fanout_no_consolidation(graph: RiskGraph) -> list[Finding]:
    """STRAT-DC-006: Fan-Out Delegation Without Consolidation.

    Agent delegates to >= 3 agents with no downstream merge point.
    """
    # Build delegation out-degree per agent
    delegation_out: dict[str, list[str]] = defaultdict(list)
    for edge in graph.edges:
        if edge.edge_type in (EdgeType.DELEGATES_TO, EdgeType.FEEDS_INTO):
            src = graph.nodes.get(edge.source)
            if src and src.node_type == NodeType.AGENT:
                delegation_out[edge.source].append(edge.target)

    findings: list[Finding] = []

    for agent_id, targets in delegation_out.items():
        if len(targets) < 3:
            continue

        node = graph.nodes.get(agent_id)
        if not node:
            continue

        # Check if any downstream node receives from multiple targets (consolidation)
        delegation_in: dict[str, int] = defaultdict(int)
        for t in targets:
            for edge in graph.edges:
                if edge.source == t and edge.edge_type in (EdgeType.DELEGATES_TO, EdgeType.FEEDS_INTO):
                    delegation_in[edge.target] += 1

        has_consolidation = any(c >= 2 for c in delegation_in.values())

        if has_consolidation:
            continue

        target_labels = [graph.nodes[t].label for t in targets if t in graph.nodes]
        findings.append(_make_finding(
            "STRAT-DC-006",
            "Fan-Out Delegation Without Consolidation",
            Severity.HIGH,
            "DC",
            [agent_id] + targets,
            graph,
            f"{node.label} delegates to {len(targets)} agents "
            f"[{', '.join(target_labels[:4])}] with no consolidation node.",
            "Add a consolidation agent that reconciles divergent outputs.",
            subgraph_type="path",
        ))

    return findings[:3]


def _dc007_no_rollback(graph: RiskGraph) -> list[Finding]:
    """STRAT-DC-007: No Rollback Path for Multi-Agent Workflow.

    Multi-agent workflow with writes_to at >= 2 stages and no compensating pattern.
    """
    chain_edges = {EdgeType.DELEGATES_TO.value, EdgeType.FEEDS_INTO.value}
    paths = find_paths(graph, chain_edges, source_filter="agent", min_length=3, max_length=8)

    findings: list[Finding] = []

    for path in paths:
        # Count agents that have write capabilities
        writing_agents = []
        for nid in path:
            node = graph.nodes.get(nid)
            if not node or node.node_type != NodeType.AGENT:
                continue
            tools = _agent_tools(graph, nid)
            kinds = _tool_kinds(graph, tools)
            if kinds & {"destructive", "financial"}:
                writing_agents.append(nid)
            # Also check for WRITES_TO edges from agent's tools
            for tid in tools:
                for e in graph.edges:
                    if e.source == tid and e.edge_type == EdgeType.WRITES_TO:
                        if nid not in writing_agents:
                            writing_agents.append(nid)
                        break

        if len(writing_agents) < 2:
            continue

        findings.append(_make_finding(
            "STRAT-DC-007",
            "No Rollback Path for Multi-Agent Workflow",
            Severity.HIGH,
            "DC",
            path,
            graph,
            f"Multi-agent workflow modifies state at {len(writing_agents)} stages "
            f"with no compensating transaction or rollback mechanism.",
            "Implement saga pattern or checkpoint/restore for multi-step workflows.",
            subgraph_type="path",
            chain=path,
        ))

    return findings[:2]


def _dc008_no_timeout(graph: RiskGraph) -> list[Finding]:
    """STRAT-DC-008: No Timeout or Circuit Breaker on Agent Chain.

    Agent chain >= 2 with no timeout_config on any agent.
    """
    chain_edges = {EdgeType.DELEGATES_TO.value, EdgeType.FEEDS_INTO.value}
    paths = find_paths(graph, chain_edges, source_filter="agent", min_length=2, max_length=8)

    findings: list[Finding] = []
    seen: set[tuple[str, ...]] = set()

    for path in paths:
        if not all(
            graph.nodes.get(nid) and graph.nodes[nid].node_type == NodeType.AGENT
            for nid in path
        ):
            continue

        # Check if ANY agent in the chain has timeout
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

        # Check if any agent calls external service
        calls_external = False
        for nid in path:
            tools = _agent_tools(graph, nid)
            for tid in tools:
                for e in graph.edges:
                    if e.source == tid and e.edge_type in (EdgeType.SENDS_TO, EdgeType.CALLS):
                        tgt = graph.nodes.get(e.target)
                        if tgt and tgt.node_type in (NodeType.EXTERNAL_SERVICE, NodeType.MCP_SERVER):
                            calls_external = True
                            break

        severity = Severity.HIGH if calls_external else Severity.MEDIUM

        findings.append(_make_finding(
            "STRAT-DC-008",
            "No Timeout or Circuit Breaker on Agent Chain",
            severity,
            "DC",
            path,
            graph,
            f"Chain of {len(path)} agents with no timeout config. "
            f"External dependency: {'yes' if calls_external else 'no'}.",
            "Set max_execution_time on each Task (CrewAI) or step_timeout (LangGraph). "
            "Add timeout parameters to external API calls.",
            subgraph_type="path",
            chain=path,
        ))

    return findings[:3]


# ===========================================================================
# OBJECTIVE & INCENTIVE CONFLICT (OC)
# ===========================================================================

def _oc002_uncoordinated_writes(graph: RiskGraph) -> list[Finding]:
    """STRAT-OC-002: Uncoordinated Parallel Writes to Shared State.

    Multiple agents write to same data store without concurrency control.
    """
    pairs = find_pairs_shared_state(graph, require_write=True)

    findings: list[Finding] = []

    for agent_a, agent_b, shared_stores in pairs:
        # Check concurrency control on shared stores
        uncontrolled = []
        for ds_id in shared_stores:
            ds = graph.nodes.get(ds_id)
            if ds and ds.concurrency_control in ("none", ""):
                uncontrolled.append(ds_id)

        if not uncontrolled:
            continue

        node_a = graph.nodes.get(agent_a)
        node_b = graph.nodes.get(agent_b)
        if not node_a or not node_b:
            continue

        ds_labels = [graph.nodes[d].label for d in uncontrolled if d in graph.nodes]
        findings.append(_make_finding(
            "STRAT-OC-002",
            "Uncoordinated Parallel Writes to Shared State",
            Severity.HIGH,
            "OC",
            [agent_a, agent_b] + uncontrolled,
            graph,
            f"{node_a.label} and {node_b.label} both write to "
            f"{', '.join(ds_labels)} without concurrency control.",
            "Add locking, versioning, or queue-based coordination on shared data stores.",
            subgraph_type="pair",
        ))

    return findings[:3]


def _oc003_feedback_loop(graph: RiskGraph) -> list[Finding]:
    """STRAT-OC-003: Feedback Loop Without Dampening.

    Cycles in agent-data bipartite graph without dampening mechanisms.
    """
    # Detect cycles through agents and data stores
    all_edge_types = {
        EdgeType.READS_FROM.value, EdgeType.WRITES_TO.value,
        EdgeType.FEEDS_INTO.value,
    }
    cycles = detect_cycles(graph, edge_types=all_edge_types, node_type_filter=None)

    findings: list[Finding] = []

    for cycle in cycles:
        # Filter to cycles that include both agents and data stores
        agent_nodes = [nid for nid in cycle[:-1]
                       if graph.nodes.get(nid) and graph.nodes[nid].node_type == NodeType.AGENT]
        data_nodes = [nid for nid in cycle[:-1]
                      if graph.nodes.get(nid) and graph.nodes[nid].node_type == NodeType.DATA_STORE]

        if not agent_nodes or not data_nodes:
            continue

        findings.append(_make_finding(
            "STRAT-OC-003",
            "Feedback Loop Without Dampening",
            Severity.HIGH,
            "OC",
            cycle[:-1],
            graph,
            f"Feedback loop detected through agents and data stores. "
            f"No dampening mechanism (convergence check, decay factor, clamp).",
            "Add convergence checks, output clamps, or decay factors. "
            "Set max_iter as a circuit breaker.",
            subgraph_type="cycle",
            chain=cycle,
        ))

    return findings[:2]


def _oc005_resource_contention(graph: RiskGraph) -> list[Finding]:
    """STRAT-OC-005: Resource Contention Between Agents.

    >= 2 agents calling same external service with no rate coordination.
    """
    # Build external service -> calling agents map
    service_callers: dict[str, list[str]] = defaultdict(list)

    for edge in graph.edges:
        if edge.edge_type in (EdgeType.SENDS_TO, EdgeType.CALLS):
            tgt = graph.nodes.get(edge.target)
            if tgt and tgt.node_type in (NodeType.EXTERNAL_SERVICE, NodeType.MCP_SERVER):
                # Find which agent owns the calling tool
                src = graph.nodes.get(edge.source)
                if src and src.node_type == NodeType.CAPABILITY:
                    for tool_edge in graph.edges:
                        if (tool_edge.edge_type == EdgeType.TOOL_OF
                                and tool_edge.source == edge.source):
                            service_callers[edge.target].append(tool_edge.target)

    findings: list[Finding] = []

    for service_id, callers in service_callers.items():
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

        service = graph.nodes.get(service_id)
        if not service:
            continue

        caller_labels = [
            graph.nodes[c].label for c in unique_callers[:4] if c in graph.nodes
        ]
        findings.append(_make_finding(
            "STRAT-OC-005",
            "Resource Contention Between Agents",
            Severity.MEDIUM,
            "OC",
            unique_callers + [service_id],
            graph,
            f"{len(unique_callers)} agents call {service.label} with no "
            f"shared rate coordination: {', '.join(caller_labels)}.",
            "Implement shared rate limiting or token bucket across agents.",
            subgraph_type="pair",
        ))

    return findings[:3]


# ===========================================================================
# SIGNAL INTEGRITY & ERROR PROPAGATION (SI)
# ===========================================================================

def _si001_error_laundering(graph: RiskGraph) -> list[Finding]:
    """STRAT-SI-001: Silent Error Laundering Across Agent Boundary.

    Agent with default_on_error/fail_silent feeding downstream agents.
    """
    findings: list[Finding] = []

    for nid, node in graph.nodes.items():
        if node.node_type != NodeType.AGENT:
            continue
        if node.error_handling_pattern not in ("default_on_error", "fail_silent"):
            continue

        # Find downstream agents
        downstream = []
        for edge in graph.edges:
            if edge.source == nid and edge.edge_type == EdgeType.FEEDS_INTO:
                tgt = graph.nodes.get(edge.target)
                if tgt and tgt.node_type == NodeType.AGENT:
                    downstream.append(edge.target)

        if not downstream:
            continue

        downstream_labels = [graph.nodes[d].label for d in downstream if d in graph.nodes]
        findings.append(_make_finding(
            "STRAT-SI-001",
            "Silent Error Laundering Across Agent Boundary",
            Severity.CRITICAL,
            "SI",
            [nid] + downstream,
            graph,
            f"{node.label} returns defaults on error (pattern: {node.error_handling_pattern}) "
            f"and feeds into {', '.join(downstream_labels)}. "
            f"Error signal is permanently lost at agent boundary.",
            "Replace default-on-error with explicit error propagation. "
            "Return error types, not default values.",
            subgraph_type="path",
        ))

    return findings[:3]


def _si004_unvalidated_schema(graph: RiskGraph) -> list[Finding]:
    """STRAT-SI-004: Unvalidated Cross-Agent Schema Assumption.

    feeds_into edge without schema_validated = True.
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
            unvalidated_edges.append((edge.source, edge.target))

    if not unvalidated_edges:
        return []

    # Group into one finding
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
        "Unvalidated Cross-Agent Schema Assumption",
        Severity.MEDIUM,
        "SI",
        list(all_agents),
        graph,
        f"{len(unvalidated_edges)} inter-agent data flows lack schema contracts: "
        f"{pairs_desc}.",
        "Add output_pydantic or output_json on upstream agents. "
        "Use TypedDict State for LangGraph.",
        subgraph_type="edge",
    ))

    return findings


def _si006_untyped_channel(graph: RiskGraph) -> list[Finding]:
    """STRAT-SI-006: Untyped Inter-Agent Data Channel.

    feeds_into edges where neither source has structured output nor target has input parsing.
    Same as SI-004 but focuses on complete absence of typing.
    """
    # This finding is similar to SI-004 but with different severity context.
    # We only fire it if there are no schema contracts at all across the system.
    total_feeds = 0
    validated_feeds = 0

    for edge in graph.edges:
        if edge.edge_type == EdgeType.FEEDS_INTO:
            src = graph.nodes.get(edge.source)
            tgt = graph.nodes.get(edge.target)
            if src and tgt and src.node_type == NodeType.AGENT and tgt.node_type == NodeType.AGENT:
                total_feeds += 1
                if edge.schema_validated:
                    validated_feeds += 1

    if total_feeds == 0 or validated_feeds > 0:
        return []

    # All channels are untyped
    agent_ids = [nid for nid, n in graph.nodes.items() if n.node_type == NodeType.AGENT]
    return [_make_finding(
        "STRAT-SI-006",
        "Untyped Inter-Agent Data Channel",
        Severity.MEDIUM,
        "SI",
        agent_ids[:5],
        graph,
        f"All {total_feeds} inter-agent data flows use unstructured strings. "
        f"No schema contracts detected anywhere in the system.",
        "Define output schemas (Pydantic models, TypedDict) on all inter-agent communication.",
        subgraph_type="edge",
    )]


def _si007_single_data_source(graph: RiskGraph) -> list[Finding]:
    """STRAT-SI-007: Single Data Source for Critical Decision.

    Agent with financial/destructive/outbound tools has only one reads_from edge.
    """
    findings: list[Finding] = []

    for nid, node in graph.nodes.items():
        if node.node_type != NodeType.AGENT:
            continue

        tools = _agent_tools(graph, nid)
        kinds = _tool_kinds(graph, tools)

        if not kinds & {"financial", "destructive", "outbound"}:
            continue

        # Count data sources (reads_from edges via tools)
        data_sources: set[str] = set()
        for tid in tools:
            for edge in graph.edges:
                if edge.target == tid and edge.edge_type == EdgeType.READS_FROM:
                    data_sources.add(edge.source)

        if len(data_sources) != 1:
            continue

        ds_id = next(iter(data_sources))
        ds = graph.nodes.get(ds_id)
        ds_label = ds.label if ds else ds_id

        findings.append(_make_finding(
            "STRAT-SI-007",
            "Single Data Source for Critical Decision",
            Severity.MEDIUM,
            "SI",
            [nid, ds_id],
            graph,
            f"{node.label} makes critical decisions "
            f"({', '.join(kinds & {'financial', 'destructive', 'outbound'})}) "
            f"based on single data source: {ds_label}.",
            "Add corroborating data sources or validation against multiple inputs.",
            subgraph_type="node",
        ))

    return findings[:3]


# ===========================================================================
# EMERGENT AUTHORITY & SCOPE CREEP (EA)
# ===========================================================================

def _ea001_transitive_escalation(graph: RiskGraph) -> list[Finding]:
    """STRAT-EA-001: Transitive Authority Escalation via Delegation Chain.

    Agent's effective capabilities exceed direct capabilities through delegation.
    """
    tc = compute_transitive_capabilities(graph)

    findings: list[Finding] = []

    for agent_id, (direct, effective) in tc.items():
        escalated = effective - direct
        if not escalated:
            continue

        # Only flag high-risk escalations
        high_risk_escalated = []
        for tid in escalated:
            kind = tid.rsplit("_", 1)[-1] if "_" in tid else ""
            if kind in ("financial", "destructive", "outbound", "code_exec"):
                high_risk_escalated.append(tid)

        if not high_risk_escalated:
            continue

        node = graph.nodes.get(agent_id)
        if not node:
            continue

        escalated_labels = [
            graph.nodes[tid].label for tid in high_risk_escalated[:4]
            if tid in graph.nodes
        ]
        direct_labels = [
            graph.nodes[tid].label for tid in direct if tid in graph.nodes
        ]

        findings.append(_make_finding(
            "STRAT-EA-001",
            "Transitive Authority Escalation via Delegation Chain",
            Severity.CRITICAL,
            "EA",
            [agent_id] + high_risk_escalated[:3],
            graph,
            f"{node.label} has {len(direct)} direct capabilities but can "
            f"effectively trigger {len(effective)} through delegation. "
            f"Escalated high-risk: {', '.join(escalated_labels)}.",
            "Implement capability scoping on delegation. "
            "Use tools= parameter on Task to limit delegate capabilities.",
            subgraph_type="transitive_closure",
            extra_evidence=[
                f"Direct: {', '.join(direct_labels[:3])}",
                f"Escalated: {', '.join(escalated_labels[:3])}",
            ],
        ))

    return findings[:3]


def _ea002_unbounded_delegation(graph: RiskGraph) -> list[Finding]:
    """STRAT-EA-002: Unbounded Task Delegation Scope.

    allow_delegation=True with no scoping, and delegate has high-risk capabilities.
    """
    findings: list[Finding] = []

    for edge in graph.edges:
        if edge.edge_type != EdgeType.DELEGATES_TO:
            continue
        if edge.scoped:
            continue  # Already scoped

        src = graph.nodes.get(edge.source)
        tgt = graph.nodes.get(edge.target)
        if not src or not tgt:
            continue
        if src.node_type != NodeType.AGENT or tgt.node_type != NodeType.AGENT:
            continue

        # Check delegate's capabilities
        tools = _agent_tools(graph, edge.target)
        kinds = _tool_kinds(graph, tools)
        high_risk = kinds & {"financial", "destructive", "outbound", "code_exec"}

        if not high_risk:
            continue

        findings.append(_make_finding(
            "STRAT-EA-002",
            "Unbounded Task Delegation Scope",
            Severity.HIGH,
            "EA",
            [edge.source, edge.target],
            graph,
            f"{src.label} delegates to {tgt.label} without capability scoping. "
            f"Delegate has: {', '.join(high_risk)}.",
            "Scope delegation by specifying which tools are available. "
            "Use tools= parameter on Task.",
            subgraph_type="edge",
        ))

    return findings[:3]


def _ea003_mcp_aggregation(graph: RiskGraph) -> list[Finding]:
    """STRAT-EA-003: MCP Server Capability Aggregation.

    Agent connected to >= 2 MCP servers spanning >= 3 high-risk categories.
    """
    # Build agent -> MCP servers map
    agent_mcp: dict[str, list[str]] = defaultdict(list)
    for edge in graph.edges:
        if edge.edge_type == EdgeType.CALLS:
            src = graph.nodes.get(edge.source)
            tgt = graph.nodes.get(edge.target)
            if not src or not tgt:
                continue
            if tgt.node_type == NodeType.MCP_SERVER:
                # Find agent that owns this tool
                for tool_edge in graph.edges:
                    if tool_edge.source == edge.source and tool_edge.edge_type == EdgeType.TOOL_OF:
                        agent_mcp[tool_edge.target].append(edge.target)

    # Also count agents with direct MCP connections
    for nid, node in graph.nodes.items():
        if node.node_type != NodeType.AGENT:
            continue
        for edge in graph.edges:
            if edge.source == nid and edge.edge_type == EdgeType.CALLS:
                tgt = graph.nodes.get(edge.target)
                if tgt and tgt.node_type == NodeType.MCP_SERVER:
                    if edge.target not in agent_mcp.get(nid, []):
                        agent_mcp.setdefault(nid, []).append(edge.target)

    findings: list[Finding] = []

    for agent_id, mcp_ids in agent_mcp.items():
        unique_mcps = list(set(mcp_ids))
        if len(unique_mcps) < 2:
            continue

        # Aggregate capability categories across MCP servers
        # Infer categories from MCP server labels and connected capabilities
        categories: set[str] = set()
        for mcp_id in unique_mcps:
            mcp = graph.nodes.get(mcp_id)
            if not mcp:
                continue
            label = mcp.label.lower()
            if any(k in label for k in ("slack", "email", "discord", "teams")):
                categories.add("outbound")
            if any(k in label for k in ("github", "exec", "code")):
                categories.add("code_exec")
            if any(k in label for k in ("postgres", "mysql", "mongo", "redis", "database", "db")):
                categories.add("data_access")
            if any(k in label for k in ("stripe", "payment", "billing")):
                categories.add("financial")
            if any(k in label for k in ("file", "s3", "storage")):
                categories.add("file_system")

        if len(categories) < 3:
            continue

        node = graph.nodes.get(agent_id)
        if not node:
            continue

        mcp_labels = [graph.nodes[m].label for m in unique_mcps if m in graph.nodes]
        findings.append(_make_finding(
            "STRAT-EA-003",
            "MCP Server Capability Aggregation",
            Severity.HIGH,
            "EA",
            [agent_id] + unique_mcps,
            graph,
            f"{node.label} connects to {len(unique_mcps)} MCP servers "
            f"[{', '.join(mcp_labels)}] spanning {len(categories)} high-risk "
            f"categories: {', '.join(sorted(categories))}.",
            "Review aggregate capability profile holistically. "
            "Split agent into specialized sub-agents.",
            subgraph_type="node",
        ))

    return findings[:3]
