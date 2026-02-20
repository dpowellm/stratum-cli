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
            edge_type=EdgeType.SENDS_TO,
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
    sends_to_edge = [e for e in graph.edges if e.edge_type == EdgeType.SENDS_TO][0]
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
            edge_type=EdgeType.SENDS_TO,
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
    sends_to_edge = [e for e in graph.edges if e.edge_type == EdgeType.SENDS_TO][0]
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
            edge_type=EdgeType.SENDS_TO,
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
            source="n1", target="n2", edge_type=EdgeType.SENDS_TO,
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
