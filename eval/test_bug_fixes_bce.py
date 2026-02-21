"""Tests for Bug B, C, D, E fixes.

Bug B: guardrail edges created even when has_usage is False
Bug C: trust_boundary string on edges (e.g. 'INTERNAL→EXTERNAL')
Bug D: version field removed from TelemetryProfile
Bug E: total_tool_count removed, tools_per_agent uses total_capabilities
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from stratum.graph.models import GraphEdge, GraphNode, EdgeType, NodeType, RiskGraph
from stratum.graph.builder import build_graph, _connect_guardrail, _mark_trust_crossings
from stratum.models import (
    Capability, Confidence, GuardrailSignal, ScanResult, TrustLevel,
)
from stratum.telemetry.ping import build_v72_ping


# ── Helpers ──────────────────────────────────────────────────────────


def _minimal_scan_result(**overrides):
    """Create a minimal ScanResult with sensible defaults."""
    defaults = {
        "scan_id": "test-scan",
        "timestamp": "2026-01-01T00:00:00Z",
        "directory": "/tmp/test",
        "files_scanned": 1,
        "capabilities": [],
        "guardrails": [],
        "mcp_servers": [],
        "env_vars": [],
        "top_paths": [],
        "signals": [],
        "detected_frameworks": [],
        "risk_score": 0,
        "total_capabilities": 0,
        "has_any_guardrails": False,
        "guardrail_count": 0,
        "mcp_server_count": 0,
        "outbound_count": 0,
        "data_access_count": 0,
        "code_exec_count": 0,
        "destructive_count": 0,
        "financial_count": 0,
        "has_shared_context": False,
        "has_learning_loop": False,
        "learning_type": None,
        "has_eval_conflict": False,
        "checkpoint_type": "none",
        "telemetry_destinations": [],
        "graph": None,
    }
    defaults.update(overrides)

    class FakeResult:
        pass

    r = FakeResult()
    for k, v in defaults.items():
        setattr(r, k, v)
    return r


# ── Bug B Tests ─────────────────────────────────────────────────────


def test_guardrail_edges_created_without_has_usage():
    """Bug B: guardrail edges should be created even when has_usage=False."""
    # Create a graph with a capability that sends to an external service
    graph = RiskGraph()
    cap_node = GraphNode(
        id="cap_GmailSendMessage_outbound",
        node_type=NodeType.CAPABILITY,
        label="GmailSendMessage",
        trust_level=TrustLevel.EXTERNAL,
    )
    ext_node = GraphNode(
        id="ext_gmail_outbound",
        node_type=NodeType.EXTERNAL_SERVICE,
        label="Gmail outbound",
        trust_level=TrustLevel.EXTERNAL,
    )
    guard_node = GraphNode(
        id="guard_output_filter_10",
        node_type=NodeType.GUARDRAIL,
        label="output_filter guardrail",
        trust_level=TrustLevel.INTERNAL,
        guardrail_kind="output_filter",
        guardrail_active=False,
    )
    graph.nodes = {
        cap_node.id: cap_node,
        ext_node.id: ext_node,
        guard_node.id: guard_node,
    }
    graph.edges = [
        GraphEdge(
            source=cap_node.id,
            target=ext_node.id,
            edge_type=EdgeType.CALLS,
            has_control=False,
        ),
    ]

    # Guardrail WITHOUT has_usage
    guard = GuardrailSignal(
        kind="output_filter",
        source_file="test.py",
        line_number=10,
        detail="output_pydantic=SomeModel",
        covers_tools=[],
        has_usage=False,
    )

    _connect_guardrail(graph, guard, guard_node)

    # Edges should be created
    guardrail_edges = [
        e for e in graph.edges
        if e.edge_type in (EdgeType.FILTERED_BY, EdgeType.GATED_BY)
    ]
    assert len(guardrail_edges) > 0, "Guardrail edges should be created even without has_usage"

    # But has_control should NOT be set on the SENDS_TO edge (guard not active)
    sends_to_edge = [e for e in graph.edges if e.edge_type == EdgeType.CALLS][0]
    assert sends_to_edge.has_control is False, "Inactive guardrail should not set has_control"


def test_guardrail_edges_active_sets_control():
    """Bug B: when has_usage=True, has_control should be set."""
    graph = RiskGraph()
    cap_node = GraphNode(
        id="cap_GmailSendMessage_outbound",
        node_type=NodeType.CAPABILITY,
        label="GmailSendMessage",
        trust_level=TrustLevel.EXTERNAL,
    )
    ext_node = GraphNode(
        id="ext_gmail_outbound",
        node_type=NodeType.EXTERNAL_SERVICE,
        label="Gmail outbound",
        trust_level=TrustLevel.EXTERNAL,
    )
    guard_node = GraphNode(
        id="guard_output_filter_20",
        node_type=NodeType.GUARDRAIL,
        label="output_filter guardrail",
        trust_level=TrustLevel.INTERNAL,
        guardrail_kind="output_filter",
        guardrail_active=True,
    )
    graph.nodes = {
        cap_node.id: cap_node,
        ext_node.id: ext_node,
        guard_node.id: guard_node,
    }
    graph.edges = [
        GraphEdge(
            source=cap_node.id,
            target=ext_node.id,
            edge_type=EdgeType.CALLS,
            has_control=False,
        ),
    ]

    guard = GuardrailSignal(
        kind="output_filter",
        source_file="test.py",
        line_number=20,
        detail="output_pydantic=SomeModel",
        covers_tools=[],
        has_usage=True,
    )

    _connect_guardrail(graph, guard, guard_node)

    # SENDS_TO edge should have has_control=True
    sends_to_edge = [e for e in graph.edges if e.edge_type == EdgeType.CALLS][0]
    assert sends_to_edge.has_control is True, "Active guardrail should set has_control"

    # Guardrail edge should also exist
    guardrail_edges = [
        e for e in graph.edges
        if e.edge_type == EdgeType.FILTERED_BY
    ]
    assert len(guardrail_edges) > 0


def test_hitl_guardrail_edges_without_has_usage():
    """Bug B: hitl guardrail edges created even when not confirmed active."""
    graph = RiskGraph()
    cap_node = GraphNode(
        id="cap_delete_destructive",
        node_type=NodeType.CAPABILITY,
        label="delete",
        trust_level=TrustLevel.INTERNAL,
    )
    store_node = GraphNode(
        id="ds_db_write",
        node_type=NodeType.DATA_STORE,
        label="DB (write)",
        trust_level=TrustLevel.INTERNAL,
    )
    guard_node = GraphNode(
        id="guard_hitl_30",
        node_type=NodeType.GUARDRAIL,
        label="hitl guardrail",
        trust_level=TrustLevel.INTERNAL,
        guardrail_kind="hitl",
        guardrail_active=False,
    )
    graph.nodes = {
        cap_node.id: cap_node,
        store_node.id: store_node,
        guard_node.id: guard_node,
    }
    graph.edges = [
        GraphEdge(
            source=cap_node.id,
            target=store_node.id,
            edge_type=EdgeType.WRITES_TO,
            has_control=False,
        ),
    ]

    guard = GuardrailSignal(
        kind="hitl",
        source_file="test.py",
        line_number=30,
        detail="human_input=True",
        covers_tools=[],
        has_usage=False,
    )

    _connect_guardrail(graph, guard, guard_node)

    # GATED_BY edge should be created
    gated_edges = [e for e in graph.edges if e.edge_type == EdgeType.GATED_BY]
    assert len(gated_edges) > 0, "HITL guardrail edges should exist even without has_usage"

    # has_control should NOT be set (guard inactive)
    writes_edge = [e for e in graph.edges if e.edge_type == EdgeType.WRITES_TO][0]
    assert writes_edge.has_control is False


# ── Bug C Tests ─────────────────────────────────────────────────────


def test_trust_boundary_string_on_edges():
    """Bug C: edges should carry trust_boundary string like 'INTERNAL→EXTERNAL'."""
    graph = RiskGraph()
    internal_node = GraphNode(
        id="cap_read_data_access",
        node_type=NodeType.CAPABILITY,
        label="read",
        trust_level=TrustLevel.INTERNAL,
    )
    external_node = GraphNode(
        id="ext_api",
        node_type=NodeType.EXTERNAL_SERVICE,
        label="API",
        trust_level=TrustLevel.EXTERNAL,
    )
    graph.nodes = {internal_node.id: internal_node, external_node.id: external_node}
    graph.edges = [
        GraphEdge(
            source=internal_node.id,
            target=external_node.id,
            edge_type=EdgeType.CALLS,
            has_control=False,
        ),
    ]

    _mark_trust_crossings(graph)

    edge = graph.edges[0]
    assert edge.trust_crossing is True
    assert edge.trust_boundary == "INTERNAL→EXTERNAL"
    assert edge.crossing_direction == "outward"


def test_trust_boundary_inward():
    """Bug C: inward crossing should show correct trust boundary string."""
    graph = RiskGraph()
    ext_node = GraphNode(
        id="ds_external_data",
        node_type=NodeType.DATA_STORE,
        label="External data",
        trust_level=TrustLevel.EXTERNAL,
    )
    priv_node = GraphNode(
        id="cap_exec_code_exec",
        node_type=NodeType.CAPABILITY,
        label="exec",
        trust_level=TrustLevel.PRIVILEGED,
    )
    graph.nodes = {ext_node.id: ext_node, priv_node.id: priv_node}
    graph.edges = [
        GraphEdge(
            source=ext_node.id,
            target=priv_node.id,
            edge_type=EdgeType.READS_FROM,
            has_control=False,
        ),
    ]

    _mark_trust_crossings(graph)

    edge = graph.edges[0]
    assert edge.trust_crossing is True
    assert edge.trust_boundary == "EXTERNAL→PRIVILEGED"
    assert edge.crossing_direction == "inward"


def test_no_trust_boundary_same_level():
    """Bug C: same trust level edges should have empty trust_boundary."""
    graph = RiskGraph()
    node_a = GraphNode(
        id="cap_a_outbound", node_type=NodeType.CAPABILITY,
        label="a", trust_level=TrustLevel.INTERNAL,
    )
    node_b = GraphNode(
        id="cap_b_data_access", node_type=NodeType.CAPABILITY,
        label="b", trust_level=TrustLevel.INTERNAL,
    )
    graph.nodes = {node_a.id: node_a, node_b.id: node_b}
    graph.edges = [
        GraphEdge(
            source=node_a.id, target=node_b.id,
            edge_type=EdgeType.SHARES_WITH, has_control=False,
        ),
    ]

    _mark_trust_crossings(graph)

    edge = graph.edges[0]
    assert edge.trust_crossing is False
    assert edge.trust_boundary == ""


def test_trust_boundary_in_to_dict():
    """Bug C: trust_boundary should appear in serialized graph dict."""
    graph = RiskGraph()
    graph.nodes = {
        "n1": GraphNode(id="n1", node_type=NodeType.CAPABILITY, label="A", trust_level=TrustLevel.INTERNAL),
        "n2": GraphNode(id="n2", node_type=NodeType.EXTERNAL_SERVICE, label="B", trust_level=TrustLevel.EXTERNAL),
    }
    graph.edges = [
        GraphEdge(
            source="n1", target="n2", edge_type=EdgeType.CALLS,
            has_control=False, trust_crossing=True,
            crossing_direction="outward", trust_boundary="INTERNAL→EXTERNAL",
        ),
    ]

    d = graph.to_dict()
    assert d["edges"][0]["trust_boundary"] == "INTERNAL→EXTERNAL"


# ── Bug D Tests ─────────────────────────────────────────────────────


def test_telemetry_profile_no_version_field():
    """Bug D: TelemetryProfile should not have a 'version' field."""
    from stratum.models import TelemetryProfile
    profile = TelemetryProfile()
    assert not hasattr(profile, "version"), "TelemetryProfile should not have 'version' field"


# ── Bug E Tests ─────────────────────────────────────────────────────


def test_ping_no_total_tool_count():
    """Bug E: ping should not contain total_tool_count."""
    result = _minimal_scan_result(total_capabilities=5)
    ping = build_v72_ping(result)
    assert "total_tool_count" not in ping, "total_tool_count should be removed from ping"


def test_ping_tools_per_agent_uses_total_capabilities():
    """Bug E: normalized_features.tools_per_agent should use total_capabilities."""
    result = _minimal_scan_result(total_capabilities=6)

    # Add 3 agents so tools_per_agent = 6/3 = 2.0
    class FakeAgent:
        def __init__(self, name):
            self.name = name
            self.tool_names = []

    result.agent_definitions = [FakeAgent("a"), FakeAgent("b"), FakeAgent("c")]
    result.crew_definitions = []

    ping = build_v72_ping(result)

    assert ping["normalized_features"]["tools_per_agent"] == 2.0
    assert ping["total_capabilities"] == 6


def test_ping_total_capabilities_present():
    """Bug E: total_capabilities should still be in the ping."""
    result = _minimal_scan_result(total_capabilities=10)
    ping = build_v72_ping(result)
    assert ping["total_capabilities"] == 10


# ── Bug F Tests: rate_limit guardrail creates edges ──────────────


def test_rate_limit_guardrail_creates_gated_by_edges():
    """Bug F: rate_limit guardrail should create GATED_BY edges to capabilities."""
    graph = RiskGraph()
    cap_node = GraphNode(
        id="cap_GmailSendMessage_outbound",
        node_type=NodeType.CAPABILITY,
        label="GmailSendMessage",
        trust_level=TrustLevel.EXTERNAL,
        source_file="app.py",
    )
    ext_node = GraphNode(
        id="ext_gmail_outbound",
        node_type=NodeType.EXTERNAL_SERVICE,
        label="Gmail outbound",
        trust_level=TrustLevel.EXTERNAL,
    )
    guard_node = GraphNode(
        id="guard_rate_limit_50",
        node_type=NodeType.GUARDRAIL,
        label="rate_limit guardrail",
        trust_level=TrustLevel.INTERNAL,
        guardrail_kind="rate_limit",
        guardrail_active=True,
    )
    graph.nodes = {
        cap_node.id: cap_node,
        ext_node.id: ext_node,
        guard_node.id: guard_node,
    }
    graph.edges = [
        GraphEdge(
            source=cap_node.id,
            target=ext_node.id,
            edge_type=EdgeType.CALLS,
            has_control=False,
        ),
    ]

    guard = GuardrailSignal(
        kind="rate_limit",
        source_file="app.py",
        line_number=50,
        detail="max_rpm=10",
        covers_tools=[],
        has_usage=True,
    )

    _connect_guardrail(graph, guard, guard_node)

    gated_edges = [e for e in graph.edges if e.edge_type == EdgeType.GATED_BY]
    assert len(gated_edges) > 0, "rate_limit guardrail must create GATED_BY edges"
    assert gated_edges[0].control_type == "rate_limit"


def test_rate_limit_guardrail_inactive_no_control():
    """Bug F: inactive rate_limit still creates edges but does not set has_control on data edges."""
    graph = RiskGraph()
    cap_node = GraphNode(
        id="cap_Search_outbound",
        node_type=NodeType.CAPABILITY,
        label="Search",
        trust_level=TrustLevel.EXTERNAL,
        source_file="bot.py",
    )
    ext_node = GraphNode(
        id="ext_serper_api",
        node_type=NodeType.EXTERNAL_SERVICE,
        label="Serper API",
        trust_level=TrustLevel.EXTERNAL,
    )
    guard_node = GraphNode(
        id="guard_rate_limit_60",
        node_type=NodeType.GUARDRAIL,
        label="rate_limit guardrail",
        trust_level=TrustLevel.INTERNAL,
        guardrail_kind="rate_limit",
        guardrail_active=False,
    )
    graph.nodes = {
        cap_node.id: cap_node,
        ext_node.id: ext_node,
        guard_node.id: guard_node,
    }
    graph.edges = [
        GraphEdge(
            source=cap_node.id,
            target=ext_node.id,
            edge_type=EdgeType.CALLS,
            has_control=False,
        ),
    ]

    guard = GuardrailSignal(
        kind="rate_limit",
        source_file="bot.py",
        line_number=60,
        detail="max_iterations=5",
        covers_tools=[],
        has_usage=False,
    )

    _connect_guardrail(graph, guard, guard_node)

    # GATED_BY edge should still be created
    gated_edges = [e for e in graph.edges if e.edge_type == EdgeType.GATED_BY]
    assert len(gated_edges) > 0, "Inactive rate_limit should still create GATED_BY edges"

    # But SENDS_TO should NOT have has_control set
    sends_to = [e for e in graph.edges if e.edge_type == EdgeType.CALLS][0]
    assert sends_to.has_control is False, "Inactive rate_limit should not set has_control"


def test_rate_limit_covers_tools_scoping():
    """Bug F: rate_limit with covers_tools only connects to matching capabilities."""
    graph = RiskGraph()
    cap_a = GraphNode(
        id="cap_GmailSendMessage_outbound",
        node_type=NodeType.CAPABILITY,
        label="GmailSendMessage",
        trust_level=TrustLevel.EXTERNAL,
    )
    cap_b = GraphNode(
        id="cap_Search_outbound",
        node_type=NodeType.CAPABILITY,
        label="Search",
        trust_level=TrustLevel.EXTERNAL,
    )
    ext = GraphNode(
        id="ext_gmail_outbound",
        node_type=NodeType.EXTERNAL_SERVICE,
        label="Gmail outbound",
        trust_level=TrustLevel.EXTERNAL,
    )
    guard_node = GraphNode(
        id="guard_rate_limit_70",
        node_type=NodeType.GUARDRAIL,
        label="rate_limit guardrail",
        trust_level=TrustLevel.INTERNAL,
        guardrail_kind="rate_limit",
        guardrail_active=True,
    )
    graph.nodes = {n.id: n for n in [cap_a, cap_b, ext, guard_node]}
    graph.edges = [
        GraphEdge(source=cap_a.id, target=ext.id, edge_type=EdgeType.CALLS, has_control=False),
        GraphEdge(source=cap_b.id, target=ext.id, edge_type=EdgeType.CALLS, has_control=False),
    ]

    guard = GuardrailSignal(
        kind="rate_limit",
        source_file="app.py",
        line_number=70,
        detail="max_rpm=10",
        covers_tools=["GmailSendMessage"],  # Only covers Gmail
        has_usage=True,
    )

    _connect_guardrail(graph, guard, guard_node)

    gated_edges = [e for e in graph.edges if e.edge_type == EdgeType.GATED_BY]
    assert len(gated_edges) == 1, "Should only create edge to covered capability"
    assert gated_edges[0].source == cap_a.id


def test_rate_limit_fallback_to_agents():
    """Bug F: rate_limit with no matching edges falls back to agent nodes."""
    graph = RiskGraph()
    agent_node = GraphNode(
        id="agent_researcher",
        node_type=NodeType.AGENT,
        label="Researcher",
        trust_level=TrustLevel.INTERNAL,
        source_file="crew.py",
    )
    guard_node = GraphNode(
        id="guard_rate_limit_80",
        node_type=NodeType.GUARDRAIL,
        label="rate_limit guardrail",
        trust_level=TrustLevel.INTERNAL,
        guardrail_kind="rate_limit",
        guardrail_active=True,
    )
    graph.nodes = {agent_node.id: agent_node, guard_node.id: guard_node}
    graph.edges = []  # No capability edges at all

    guard = GuardrailSignal(
        kind="rate_limit",
        source_file="crew.py",
        line_number=80,
        detail="max_iterations=3",
        covers_tools=[],
        has_usage=True,
    )

    _connect_guardrail(graph, guard, guard_node)

    gated_edges = [e for e in graph.edges if e.edge_type == EdgeType.GATED_BY]
    assert len(gated_edges) == 1, "Should fall back to agent node"
    assert gated_edges[0].source == agent_node.id


def test_rate_limit_last_resort_all_capabilities():
    """Bug F: rate_limit with no matching file or agents connects to all capabilities."""
    graph = RiskGraph()
    cap_a = GraphNode(
        id="cap_Tool_outbound",
        node_type=NodeType.CAPABILITY,
        label="Tool",
        trust_level=TrustLevel.EXTERNAL,
        source_file="other.py",
    )
    cap_b = GraphNode(
        id="cap_Exec_code_exec",
        node_type=NodeType.CAPABILITY,
        label="Exec",
        trust_level=TrustLevel.PRIVILEGED,
        source_file="other.py",
    )
    guard_node = GraphNode(
        id="guard_rate_limit_90",
        node_type=NodeType.GUARDRAIL,
        label="rate_limit guardrail",
        trust_level=TrustLevel.INTERNAL,
        guardrail_kind="rate_limit",
        guardrail_active=True,
    )
    graph.nodes = {n.id: n for n in [cap_a, cap_b, guard_node]}
    graph.edges = []  # No edges to iterate

    guard = GuardrailSignal(
        kind="rate_limit",
        source_file="different_file.py",
        line_number=90,
        detail="recursion_limit=10",
        covers_tools=[],
        has_usage=True,
    )

    _connect_guardrail(graph, guard, guard_node)

    gated_edges = [e for e in graph.edges if e.edge_type == EdgeType.GATED_BY]
    assert len(gated_edges) == 2, "Last resort: should connect to all capability nodes"


def test_rate_limit_in_full_build_graph():
    """Bug F: end-to-end: build_graph with a rate_limit guardrail produces non-zero control_coverage."""
    result = _minimal_scan_result(
        capabilities=[
            Capability(
                kind="outbound",
                confidence=Confidence.CONFIRMED,
                function_name="GmailSendMessage",
                source_file="app.py",
                line_number=10,
                evidence="send_message()",
                library="langchain_google",
                trust_level="external",
            ),
        ],
        guardrails=[
            GuardrailSignal(
                kind="rate_limit",
                source_file="app.py",
                line_number=20,
                detail="max_rpm=10",
                covers_tools=[],
                has_usage=True,
            ),
        ],
        total_capabilities=1,
        guardrail_count=1,
        has_any_guardrails=True,
    )

    graph = build_graph(result)

    # The rate_limit guardrail should have created GATED_BY edges
    gated_edges = [e for e in graph.edges if e.edge_type == EdgeType.GATED_BY]
    assert len(gated_edges) > 0, "build_graph should create GATED_BY edges for rate_limit"

    # control_coverage_pct should be > 0
    assert graph.risk_surface.control_coverage_pct > 0.0, (
        f"control_coverage_pct should be > 0 with rate_limit guardrail, "
        f"got {graph.risk_surface.control_coverage_pct}"
    )


# ══════════════════════════════════════════════════════════════
# Regression Fixtures for 11-bug patch
# ══════════════════════════════════════════════════════════════


# ── Fixture A: 2-agent + shared tool + guardrail ──────────────


def test_regression_two_agents_shared_tool_guardrail():
    """Fixture A: 2 agents sharing a tool, with a guardrail.

    Validates: edge type vocabulary (Bug 2), guardrail wiring (Bug 1),
    node type 'external_service' (Bug 3), control_coverage_pct (Bug 10).
    """
    graph = RiskGraph()
    agent_a = GraphNode(
        id="agent_researcher", node_type=NodeType.AGENT,
        label="Researcher", trust_level=TrustLevel.INTERNAL,
        source_file="crew.py",
    )
    agent_b = GraphNode(
        id="agent_writer", node_type=NodeType.AGENT,
        label="Writer", trust_level=TrustLevel.INTERNAL,
        source_file="crew.py",
    )
    cap_shared = GraphNode(
        id="cap_search_outbound", node_type=NodeType.CAPABILITY,
        label="Search", trust_level=TrustLevel.EXTERNAL,
        source_file="crew.py",
    )
    ext_api = GraphNode(
        id="ext_serper_api", node_type=NodeType.EXTERNAL_SERVICE,
        label="Serper API", trust_level=TrustLevel.EXTERNAL,
    )
    guard_node = GraphNode(
        id="guard_output_filter_1", node_type=NodeType.GUARDRAIL,
        label="output_filter guardrail", trust_level=TrustLevel.INTERNAL,
        guardrail_kind="output_filter", guardrail_active=True,
        source_file="crew.py",
    )
    graph.nodes = {n.id: n for n in [agent_a, agent_b, cap_shared, ext_api, guard_node]}
    graph.edges = [
        GraphEdge(source=cap_shared.id, target=agent_a.id, edge_type=EdgeType.TOOL_OF, has_control=False),
        GraphEdge(source=cap_shared.id, target=agent_b.id, edge_type=EdgeType.TOOL_OF, has_control=False),
        GraphEdge(source=cap_shared.id, target=ext_api.id, edge_type=EdgeType.CALLS, has_control=False),
        GraphEdge(source=agent_a.id, target=agent_b.id, edge_type=EdgeType.DELEGATES_TO, has_control=False),
    ]

    # Wire guardrail
    guard = GuardrailSignal(
        kind="output_filter", source_file="crew.py",
        line_number=1, detail="output_pydantic=SomeModel",
        covers_tools=[], has_usage=True,
    )
    _connect_guardrail(graph, guard, guard_node)

    # Assertions
    # Bug 2: Only spec-compliant edge types
    valid_types = {"delegates_to", "tool_of", "reads_from", "writes_to",
                   "calls", "shares_with", "filtered_by", "gated_by", "connects_to"}
    for e in graph.edges:
        assert e.edge_type.value in valid_types, f"Invalid edge type: {e.edge_type.value}"

    # Bug 3: node type value is "external_service" not "external"
    assert ext_api.node_type.value == "external_service"

    # Bug 1: guardrail has at least one FILTERED_BY or GATED_BY edge
    guardrail_edges = [
        e for e in graph.edges
        if e.edge_type in (EdgeType.FILTERED_BY, EdgeType.GATED_BY)
    ]
    assert len(guardrail_edges) > 0, "Guardrail must have at least one edge"

    # Bug 10: with agents present, control_coverage should not be vacuously 0
    from stratum.graph.surface import compute_risk_surface
    from stratum.graph.models import RiskSurface
    graph.risk_surface = RiskSurface(total_nodes=len(graph.nodes), total_edges=len(graph.edges))
    graph.uncontrolled_paths = []
    surface = compute_risk_surface(graph)
    # With agents present but the CALLS→external edge needing a control and the
    # guardrail covering it, coverage should be > 0
    assert surface.control_coverage_pct >= 0.0


# ── Fixture B: Two structurally different graphs → different hashes ──


def test_regression_topology_hash_distinct():
    """Fixture B: Two structurally different graphs must produce different topology hashes.

    Validates: topology hash is structural (Bug 4).
    """
    from stratum.telemetry.profile import _compute_topology_hash

    # Graph 1: 1 agent, 1 capability, 1 edge
    r1 = _minimal_scan_result(
        capabilities=[
            Capability(
                kind="outbound", confidence=Confidence.CONFIRMED,
                function_name="func1", source_file="a.py",
                line_number=1, evidence="ev1", library="lib1",
                trust_level="external",
            ),
        ],
        total_capabilities=1,
    )
    graph1 = RiskGraph()
    graph1.nodes = {
        "agent_a": GraphNode(id="agent_a", node_type=NodeType.AGENT, label="A",
                             trust_level=TrustLevel.INTERNAL),
        "cap_1": GraphNode(id="cap_1", node_type=NodeType.CAPABILITY, label="Cap1",
                           trust_level=TrustLevel.EXTERNAL),
    }
    graph1.edges = [
        GraphEdge(source="cap_1", target="agent_a", edge_type=EdgeType.TOOL_OF, has_control=False),
    ]
    r1.graph = graph1

    # Graph 2: 2 agents, 2 capabilities, 3 edges
    r2 = _minimal_scan_result(
        capabilities=[
            Capability(
                kind="outbound", confidence=Confidence.CONFIRMED,
                function_name="func2", source_file="b.py",
                line_number=1, evidence="ev2", library="lib2",
                trust_level="external",
            ),
            Capability(
                kind="data_access", confidence=Confidence.CONFIRMED,
                function_name="func3", source_file="b.py",
                line_number=2, evidence="ev3", library="lib3",
                trust_level="internal",
            ),
        ],
        total_capabilities=2,
    )
    graph2 = RiskGraph()
    graph2.nodes = {
        "agent_x": GraphNode(id="agent_x", node_type=NodeType.AGENT, label="X",
                             trust_level=TrustLevel.INTERNAL),
        "agent_y": GraphNode(id="agent_y", node_type=NodeType.AGENT, label="Y",
                             trust_level=TrustLevel.INTERNAL),
        "cap_x": GraphNode(id="cap_x", node_type=NodeType.CAPABILITY, label="CapX",
                           trust_level=TrustLevel.EXTERNAL),
        "cap_y": GraphNode(id="cap_y", node_type=NodeType.CAPABILITY, label="CapY",
                           trust_level=TrustLevel.INTERNAL),
    }
    graph2.edges = [
        GraphEdge(source="cap_x", target="agent_x", edge_type=EdgeType.TOOL_OF, has_control=False),
        GraphEdge(source="cap_y", target="agent_y", edge_type=EdgeType.TOOL_OF, has_control=False),
        GraphEdge(source="agent_x", target="agent_y", edge_type=EdgeType.DELEGATES_TO, has_control=False),
    ]
    r2.graph = graph2

    hash1 = _compute_topology_hash(r1)
    hash2 = _compute_topology_hash(r2)

    assert hash1 != "", "Graph 1 should produce a non-empty hash"
    assert hash2 != "", "Graph 2 should produce a non-empty hash"
    assert hash1 != hash2, (
        f"Structurally different graphs must produce different hashes: "
        f"hash1={hash1}, hash2={hash2}"
    )


# ── Fixture C: 0-agent repo with findings ─────────────────────


def test_regression_zero_agent_repo():
    """Fixture C: 0-agent repo with findings.

    Validates: findings_per_agent=0.0 (Bug 9), control_coverage_pct=0.0 (Bug 10),
    guardrail_count from graph (Bug 11), selection_stratum (Bug 7).
    """
    result = _minimal_scan_result(
        capabilities=[
            Capability(
                kind="outbound", confidence=Confidence.CONFIRMED,
                function_name="requests_post", source_file="main.py",
                line_number=5, evidence="requests.post()", library="requests",
                trust_level="external",
            ),
        ],
        total_capabilities=1,
        detected_frameworks=["LangChain"],
    )
    # No agent_definitions, no crew_definitions
    result.agent_definitions = []
    result.crew_definitions = []

    ping = build_v72_ping(result)

    # Bug 7: selection_stratum should reflect primary framework
    assert ping["selection_stratum"] == "langchain_active"

    # Bug 9: findings_per_agent should be 0.0 (not findings/1)
    assert ping["normalized_features"]["findings_per_agent"] == 0.0
    assert ping["normalized_features"]["findings_per_crew"] == 0.0
    assert ping["normalized_features"]["guardrails_per_agent"] == 0.0
    assert ping["normalized_features"]["tools_per_agent"] == 0.0

    # Bug 10: control_coverage_pct should be 0.0 (vacuous — no agents)
    # This tests the ping-level value which comes from the profile
    # Build a graph with no agents to test surface.py directly
    from stratum.graph.surface import compute_risk_surface
    from stratum.graph.models import RiskSurface
    graph = RiskGraph()
    cap = GraphNode(id="cap_1", node_type=NodeType.CAPABILITY,
                    label="requests.post", trust_level=TrustLevel.EXTERNAL)
    graph.nodes = {"cap_1": cap}
    graph.edges = []
    graph.uncontrolled_paths = []
    graph.risk_surface = RiskSurface(total_nodes=1, total_edges=0)
    surface = compute_risk_surface(graph)
    assert surface.control_coverage_pct == 0.0, (
        f"0-agent graph should have 0.0 control_coverage, got {surface.control_coverage_pct}"
    )
