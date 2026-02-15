"""Observation point generation for reliability analysis.

Phase 9: Generates recommended observation/monitoring points based on
the enriched graph. These are actionable locations where runtime
monitoring would add the most value.

Observation points are NOT findings — they are positive recommendations
for improving observability and runtime detection capability.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from stratum.graph.models import EdgeType, NodeType, RiskGraph
from stratum.models import Finding


@dataclass
class ObservationPoint:
    """A recommended monitoring/observation location."""
    id: str
    category: str  # "decision_audit" | "error_boundary" | "volume_monitoring" | "schema_validation" | "authority_audit"
    priority: str  # "critical" | "high" | "medium"
    node_id: str
    node_label: str
    description: str
    rationale: str
    suggested_implementation: str
    related_findings: list[str] = field(default_factory=list)


def generate_observation_points(
    graph: RiskGraph,
    findings: list[Finding],
) -> list[ObservationPoint]:
    """Generate observation points from graph structure and findings.

    Returns prioritized list of recommended monitoring locations.
    """
    points: list[ObservationPoint] = []
    counter = 0

    def _next_id() -> str:
        nonlocal counter
        counter += 1
        return f"OBS-{counter:03d}"

    points.extend(_decision_audit_points(graph, findings, _next_id))
    points.extend(_error_boundary_points(graph, findings, _next_id))
    points.extend(_volume_monitoring_points(graph, findings, _next_id))
    points.extend(_schema_validation_points(graph, findings, _next_id))
    points.extend(_authority_audit_points(graph, findings, _next_id))

    # Sort by priority
    priority_order = {"critical": 0, "high": 1, "medium": 2}
    points.sort(key=lambda p: priority_order.get(p.priority, 3))

    return points


def _decision_audit_points(
    graph: RiskGraph,
    findings: list[Finding],
    next_id,
) -> list[ObservationPoint]:
    """Observation points for decision chain auditing."""
    points: list[ObservationPoint] = []
    agents = {nid: n for nid, n in graph.nodes.items() if n.node_type == NodeType.AGENT}

    # Agents that make decisions without observation
    for nid, node in agents.items():
        if not node.makes_decisions:
            continue

        has_obs = any(
            e.source == nid and e.edge_type == EdgeType.OBSERVED_BY
            for e in graph.edges
        )
        if has_obs:
            continue

        # Check if this agent is involved in findings
        related = [
            f.id for f in findings
            if node.label in (f.path or "")
        ]

        priority = "critical" if related else "high"

        points.append(ObservationPoint(
            id=next_id(),
            category="decision_audit",
            priority=priority,
            node_id=nid,
            node_label=node.label,
            description=(
                f"Decision-making agent '{node.label}' has no observability. "
                f"Decisions are not auditable."
            ),
            rationale=(
                "Agents that make approve/reject/route decisions should log "
                "their decision rationale for audit and debugging."
            ),
            suggested_implementation=(
                "Add a LangSmith/LangFuse callback or structured logger that captures "
                "input, decision, and reasoning for each invocation."
            ),
            related_findings=related[:3],
        ))

    # Terminal agents in delegation chains (last to touch data before output)
    delegation_out: dict[str, set[str]] = defaultdict(set)
    delegation_in: dict[str, set[str]] = defaultdict(set)
    for edge in graph.edges:
        if edge.edge_type in (EdgeType.DELEGATES_TO, EdgeType.FEEDS_INTO):
            if edge.source in agents and edge.target in agents:
                delegation_out[edge.source].add(edge.target)
                delegation_in[edge.target].add(edge.source)

    terminal_agents = {
        nid for nid in agents
        if nid in delegation_in and nid not in delegation_out
    }

    for nid in terminal_agents:
        has_obs = any(
            e.source == nid and e.edge_type == EdgeType.OBSERVED_BY
            for e in graph.edges
        )
        if has_obs:
            continue

        node = agents[nid]
        points.append(ObservationPoint(
            id=next_id(),
            category="decision_audit",
            priority="high",
            node_id=nid,
            node_label=node.label,
            description=(
                f"Terminal agent '{node.label}' produces final output with no observation. "
                f"Output quality is not monitored."
            ),
            rationale=(
                "Terminal agents in delegation chains produce the final output "
                "that reaches users or external systems."
            ),
            suggested_implementation=(
                "Add output logging with quality metrics. Consider adding "
                "a sampling-based evaluation loop."
            ),
        ))

    return points[:5]


def _error_boundary_points(
    graph: RiskGraph,
    findings: list[Finding],
    next_id,
) -> list[ObservationPoint]:
    """Observation points at error boundaries."""
    points: list[ObservationPoint] = []

    for edge in graph.edges:
        if edge.edge_type != EdgeType.ERROR_BOUNDARY:
            continue

        src = graph.nodes.get(edge.source)
        tgt = graph.nodes.get(edge.target)
        if not src or not tgt:
            continue

        related = [f.id for f in findings if f.id == "STRAT-SI-001"]

        points.append(ObservationPoint(
            id=next_id(),
            category="error_boundary",
            priority="critical",
            node_id=edge.source,
            node_label=src.label,
            description=(
                f"Error boundary between '{src.label}' and '{tgt.label}'. "
                f"Error signal is lost at this boundary "
                f"(pattern: {src.error_handling_pattern})."
            ),
            rationale=(
                "When an agent silently converts errors to defaults, downstream "
                "agents receive corrupted data that looks valid."
            ),
            suggested_implementation=(
                "Add error rate monitoring at this boundary. Log when default "
                "values are returned and alert on sustained error rates."
            ),
            related_findings=related[:2],
        ))

    return points[:3]


def _volume_monitoring_points(
    graph: RiskGraph,
    findings: list[Finding],
    next_id,
) -> list[ObservationPoint]:
    """Observation points for outbound volume monitoring."""
    points: list[ObservationPoint] = []

    # Find agents that send to external services
    for edge in graph.edges:
        if edge.edge_type not in (EdgeType.SENDS_TO, EdgeType.CALLS):
            continue
        tgt = graph.nodes.get(edge.target)
        if not tgt or tgt.node_type not in (NodeType.EXTERNAL_SERVICE, NodeType.MCP_SERVER):
            continue

        # Find the agent that owns this capability
        src = graph.nodes.get(edge.source)
        if not src:
            continue

        agent_id = None
        if src.node_type == NodeType.AGENT:
            agent_id = edge.source
        elif src.node_type == NodeType.CAPABILITY:
            for tool_edge in graph.edges:
                if tool_edge.source == edge.source and tool_edge.edge_type == EdgeType.TOOL_OF:
                    agent_id = tool_edge.target
                    break

        if not agent_id:
            continue

        agent = graph.nodes.get(agent_id)
        if not agent:
            continue

        # Check if rate limited
        has_rate_limit = any(
            e.source == agent_id and e.edge_type == EdgeType.RATE_LIMITED_BY
            for e in graph.edges
        )
        if has_rate_limit:
            continue

        points.append(ObservationPoint(
            id=next_id(),
            category="volume_monitoring",
            priority="high",
            node_id=agent_id,
            node_label=agent.label,
            description=(
                f"Agent '{agent.label}' sends to external service "
                f"'{tgt.label}' with no rate monitoring."
            ),
            rationale=(
                "Outbound API calls should be monitored for unusual volume "
                "to detect runaway loops or data exfiltration."
            ),
            suggested_implementation=(
                "Add rate limiting and volume monitoring. Track calls/minute "
                "and alert on deviations from baseline."
            ),
        ))

    return points[:3]


def _schema_validation_points(
    graph: RiskGraph,
    findings: list[Finding],
    next_id,
) -> list[ObservationPoint]:
    """Observation points for inter-agent schema validation."""
    points: list[ObservationPoint] = []

    for edge in graph.edges:
        if edge.edge_type != EdgeType.FEEDS_INTO:
            continue
        if edge.schema_validated:
            continue

        src = graph.nodes.get(edge.source)
        tgt = graph.nodes.get(edge.target)
        if not src or not tgt:
            continue
        if src.node_type != NodeType.AGENT or tgt.node_type != NodeType.AGENT:
            continue

        points.append(ObservationPoint(
            id=next_id(),
            category="schema_validation",
            priority="medium",
            node_id=edge.source,
            node_label=src.label,
            description=(
                f"Data flow from '{src.label}' to '{tgt.label}' has no "
                f"schema contract."
            ),
            rationale=(
                "Unvalidated inter-agent data flows can silently pass "
                "malformed data that causes downstream failures."
            ),
            suggested_implementation=(
                "Add output_pydantic on the upstream agent (CrewAI) or "
                "TypedDict State (LangGraph) to enforce schema contracts."
            ),
            related_findings=[f.id for f in findings if f.id == "STRAT-SI-004"][:1],
        ))

    return points[:3]


def _authority_audit_points(
    graph: RiskGraph,
    findings: list[Finding],
    next_id,
) -> list[ObservationPoint]:
    """Observation points for authority escalation auditing."""
    points: list[ObservationPoint] = []

    # Find agents with implicit_authority_over edges
    escalated_agents: dict[str, list[str]] = defaultdict(list)
    for edge in graph.edges:
        if edge.edge_type == EdgeType.IMPLICIT_AUTHORITY_OVER:
            escalated_agents[edge.source].append(edge.target)

    for agent_id, escalated_caps in escalated_agents.items():
        agent = graph.nodes.get(agent_id)
        if not agent:
            continue

        cap_labels = [
            graph.nodes[c].label for c in escalated_caps[:3]
            if c in graph.nodes
        ]

        points.append(ObservationPoint(
            id=next_id(),
            category="authority_audit",
            priority="critical",
            node_id=agent_id,
            node_label=agent.label,
            description=(
                f"Agent '{agent.label}' has implicit authority over "
                f"{len(escalated_caps)} capabilities not directly assigned: "
                f"{', '.join(cap_labels)}."
            ),
            rationale=(
                "Transitive authority escalation should be monitored to detect "
                "when agents exercise capabilities beyond their direct scope."
            ),
            suggested_implementation=(
                "Log all delegation-chain invocations with the originating agent. "
                "Alert when escalated capabilities are actually exercised."
            ),
            related_findings=[f.id for f in findings if f.id == "STRAT-EA-001"][:1],
        ))

    return points[:3]


def observation_points_to_dict(points: list[ObservationPoint]) -> list[dict]:
    """Serialize observation points for JSON output."""
    return [
        {
            "id": p.id,
            "category": p.category,
            "priority": p.priority,
            "node_id": p.node_id,
            "node_label": p.node_label,
            "description": p.description,
            "rationale": p.rationale,
            "suggested_implementation": p.suggested_implementation,
            "related_findings": p.related_findings,
        }
        for p in points
    ]
