"""Tests for graph export functionality."""
import json
import os
import tempfile

import pytest

from stratum.graph.export import export_graph
from stratum.models import (
    Finding, Severity, Confidence, RiskCategory, TCMatch,
)


# ── Helpers ─────────────────────────────────────────────────────────


def _make_mock_graph():
    """Create a mock RiskGraph-like object for testing."""
    import networkx as nx

    G = nx.DiGraph()
    G.add_node("agent_1", type="agent", label="Agent 1", trust_level="internal",
               data_sensitivity="unknown")
    G.add_node("tool_1", type="capability", label="WebSearch", trust_level="external",
               data_sensitivity="unknown")
    G.add_node("api", type="external", label="Gmail API", trust_level="external",
               data_sensitivity="personal")
    G.add_edge("tool_1", "agent_1", type="tool_of", has_control=False,
               data_sensitivity="unknown", trust_crossing=False)
    G.add_edge("agent_1", "api", type="sends_to", has_control=False,
               data_sensitivity="personal", trust_crossing=True)
    return G


def _make_findings():
    """Create minimal test findings."""
    return [
        Finding(
            id="STRATUM-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            category=RiskCategory.SECURITY,
            title="Test finding",
            path="test → api",
            description="Test description",
        ),
    ]


def _make_tc_matches():
    """Create minimal TC matches."""
    return [
        TCMatch(
            tc_id="STRATUM-TC-001",
            name="Test TC",
            severity="CRITICAL",
            description="Test TC description",
            finding_components=["STRATUM-001"],
            owasp_ids=["LLM04"],
            matched_nodes={"agent": "agent_1"},
            matched_edges=[("agent_1", "api", "sends_to")],
            matched_path=["agent_1", "api"],
            remediation={"description": "Fix it", "effort": "low"},
        ),
    ]


# ── Tests ───────────────────────────────────────────────────────────


def test_export_creates_file():
    """Verify graph.json is created in output dir."""
    with tempfile.TemporaryDirectory() as tmpdir:
        graph = _make_mock_graph()
        findings = _make_findings()
        tc_matches = _make_tc_matches()

        result_path = export_graph(graph, findings, tc_matches, "test-scan-id", tmpdir)

        assert os.path.exists(result_path), f"Expected {result_path} to exist"
        assert str(result_path).endswith("graph.json")


def test_export_schema():
    """Verify exported JSON has required top-level keys."""
    with tempfile.TemporaryDirectory() as tmpdir:
        graph = _make_mock_graph()
        result_path = export_graph(graph, _make_findings(), _make_tc_matches(), "scan-123", tmpdir)

        with open(result_path) as f:
            data = json.load(f)

        assert "scan_id" in data
        assert data["scan_id"] == "scan-123"
        assert "schema_version" in data
        assert "graph" in data
        assert "nodes" in data["graph"]
        assert "edges" in data["graph"]
        assert "findings" in data
        assert "toxic_combinations" in data


def test_export_node_serialization():
    """Verify nodes have id, type, properties."""
    with tempfile.TemporaryDirectory() as tmpdir:
        graph = _make_mock_graph()
        result_path = export_graph(graph, [], [], "scan-456", tmpdir)

        with open(result_path) as f:
            data = json.load(f)

        nodes = data["graph"]["nodes"]
        assert len(nodes) == 3

        for node in nodes:
            assert "id" in node
            assert "type" in node
            assert "properties" in node


def test_export_edge_serialization():
    """Verify edges have source, target, type, properties."""
    with tempfile.TemporaryDirectory() as tmpdir:
        graph = _make_mock_graph()
        result_path = export_graph(graph, [], [], "scan-789", tmpdir)

        with open(result_path) as f:
            data = json.load(f)

        edges = data["graph"]["edges"]
        assert len(edges) == 2

        for edge in edges:
            assert "source" in edge
            assert "target" in edge
            assert "type" in edge
            assert "properties" in edge


def test_export_tc_matches_included():
    """Verify TC matches appear in export."""
    with tempfile.TemporaryDirectory() as tmpdir:
        graph = _make_mock_graph()
        tc_matches = _make_tc_matches()
        result_path = export_graph(graph, _make_findings(), tc_matches, "scan-tc", tmpdir)

        with open(result_path) as f:
            data = json.load(f)

        tcs = data["toxic_combinations"]
        assert len(tcs) == 1
        assert tcs[0]["tc_id"] == "STRATUM-TC-001"
        assert tcs[0]["severity"] == "CRITICAL"
        assert "matched_nodes" in tcs[0]
        assert "matched_path" in tcs[0]
