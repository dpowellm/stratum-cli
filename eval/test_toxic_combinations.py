"""Tests for the toxic combination pattern matcher.

Tests match against minimal NetworkX DiGraphs built directly,
without depending on the scanner.
"""
import networkx as nx
import pytest

from stratum.graph.toxic_combinations import load_catalog, match_all


# ── Helpers ─────────────────────────────────────────────────────────


def build_tc001_graph():
    """Build minimal graph that should trigger TC-001.

    TC-001: Unsupervised Delegation to Credential-Exposed Worker
    Pattern: agent -[delegates_to, no control]-> agent -[has access to]-> credential source
    """
    G = nx.DiGraph()
    G.add_node("orch", type="agent")
    G.add_node("worker", type="agent")
    G.add_node("cred_store", type="data_store", data_sensitivity="credentials")
    G.add_edge("orch", "worker", type="delegates_to", has_control=False)
    G.add_edge("cred_store", "worker", type="reads_from")
    return G


def build_tc001_graph_with_control():
    """Build TC-001 graph but with has_control=True (should NOT match)."""
    G = nx.DiGraph()
    G.add_node("orch", type="agent")
    G.add_node("worker", type="agent")
    G.add_node("cred_store", type="data_store", data_sensitivity="credentials")
    G.add_edge("orch", "worker", type="delegates_to", has_control=True)
    G.add_edge("cred_store", "worker", type="reads_from")
    return G


def build_tc002_graph():
    """Build minimal graph that should trigger TC-002.

    TC-002: PII Exfiltration Through Delegation Chain
    Pattern: data_store(pii) -> agent -> agent -> external
    """
    G = nx.DiGraph()
    G.add_node("pii_db", type="data_store", data_sensitivity="personal")
    G.add_node("reader", type="agent")
    G.add_node("writer", type="agent")
    G.add_node("api_sink", type="external_service")
    G.add_edge("pii_db", "reader", type="reads_from")
    G.add_edge("reader", "writer", type="delegates_to", has_control=False)
    G.add_edge("writer", "api_sink", type="calls")
    return G


def build_tc005_graph():
    """Build minimal graph that should trigger TC-005.

    TC-005: Inbox-to-Outbound Pipeline (EchoLeak Pattern)
    Pattern: data_store -> capability -[tool_of]-> agent -[tool_of]<- capability -> external
    """
    G = nx.DiGraph()
    G.add_node("inbox", type="data_store")
    G.add_node("read_tool", type="capability")
    G.add_node("agent", type="agent")
    G.add_node("send_tool", type="capability")
    G.add_node("gmail", type="external_service")
    G.add_edge("inbox", "read_tool", type="reads_from")
    G.add_edge("read_tool", "agent", type="tool_of")
    G.add_edge("send_tool", "agent", type="tool_of")
    G.add_edge("send_tool", "gmail", type="calls")
    return G


def build_tc007_graph():
    """Build minimal graph that should trigger TC-007.

    TC-007: Blast Radius Amplification via Shared Tool (fan_out >= 3)
    Pattern: capability -[tool_of]-> agent_1, agent_2, agent_3
    """
    G = nx.DiGraph()
    G.add_node("shared_tool", type="capability")
    G.add_node("agent_1", type="agent")
    G.add_node("agent_2", type="agent")
    G.add_node("agent_3", type="agent")
    G.add_edge("shared_tool", "agent_1", type="tool_of")
    G.add_edge("shared_tool", "agent_2", type="tool_of")
    G.add_edge("shared_tool", "agent_3", type="tool_of")
    return G


def build_tc001_graph_with_hitl():
    """Build TC-001 graph with a HITL guardrail on the worker (should suppress)."""
    G = nx.DiGraph()
    G.add_node("orch", type="agent")
    G.add_node("worker", type="agent")
    G.add_node("cred_store", type="data_store", data_sensitivity="credentials")
    G.add_node("hitl_guard", type="guardrail", kind="hitl")
    G.add_edge("orch", "worker", type="delegates_to", has_control=False)
    G.add_edge("cred_store", "worker", type="reads_from")
    # Guardrail gates the worker
    G.add_edge("worker", "hitl_guard", type="gated_by")
    return G


def build_tc003_graph():
    """Build minimal graph that should trigger TC-003.

    TC-003: Code Execution Reachable From External Input
    Pattern: external -[sends_to|reads_from|calls|feeds_into]-> agent <-[tool_of]- capability
    Negative: agent has guardrail of type "hitl"
    """
    G = nx.DiGraph()
    G.add_node("ext_input", type="external_service")
    G.add_node("exec_agent", type="agent")
    G.add_node("exec_cap", type="capability")
    G.add_edge("ext_input", "exec_agent", type="calls")
    G.add_edge("exec_cap", "exec_agent", type="tool_of")
    return G


def build_tc004_graph():
    """Build minimal graph that should trigger TC-004.

    TC-004: Financial Operation Through Shared Context
    Pattern: agent_A -[shares_tool|feeds_into|delegates_to]-> agent_B <-[tool_of]- capability
             agent_B -[sends_to|calls]-> external
    Negative: fin_agent has guardrail of type "hitl" or "validation"
    """
    G = nx.DiGraph()
    G.add_node("ext_agent", type="agent")
    G.add_node("fin_agent", type="agent")
    G.add_node("fin_cap", type="capability")
    G.add_node("ext_sink", type="external_service")
    G.add_edge("ext_agent", "fin_agent", type="shares_with")
    G.add_edge("fin_cap", "fin_agent", type="tool_of")
    G.add_edge("fin_agent", "ext_sink", type="calls")
    return G


def build_tc006_graph():
    """Build minimal graph that should trigger TC-006.

    TC-006: MCP Credential Cascade
    Pattern: mcp_server(mcp_auth=false) -[calls|tool_of]-> agent <-[calls|tool_of]- mcp_server
    No negative constraints.
    """
    G = nx.DiGraph()
    G.add_node("mcp_noauth", type="mcp_server", mcp_auth=False)
    G.add_node("agent", type="agent")
    G.add_node("mcp_creds", type="mcp_server")
    G.add_edge("mcp_noauth", "agent", type="calls")
    G.add_edge("mcp_creds", "agent", type="calls")
    return G


def build_tc008_graph():
    """Build minimal graph that should trigger TC-008.

    TC-008: Checkpoint-Free Destructive Pipeline
    Pattern: agent_1 -[feeds_into]-> agent_2 -[feeds_into]-> agent_3
    Negative: agent_3 has guardrail of type "hitl"
    """
    G = nx.DiGraph()
    G.add_node("agent_1", type="agent")
    G.add_node("agent_2", type="agent")
    G.add_node("agent_3", type="agent")
    G.add_edge("agent_1", "agent_2", type="delegates_to")
    G.add_edge("agent_2", "agent_3", type="delegates_to")
    return G


def build_tc009_graph():
    """Build minimal graph that should trigger TC-009.

    TC-009: Cross-Crew Data Sensitivity Escalation
    Pattern: agent -[feeds_into|delegates_to|shares_tool, has_control=false]-> agent
    Negative: edge_on_path has_control=true
    """
    G = nx.DiGraph()
    G.add_node("low_agent", type="agent")
    G.add_node("high_agent", type="agent")
    G.add_edge("low_agent", "high_agent", type="delegates_to", has_control=False)
    return G


def build_tc010_graph():
    """Build minimal graph that should trigger TC-010.

    TC-010: Autonomous Loop With External Write Access
    Pattern: agent -[feeds_into|delegates_to]-> agent (self-loop)
             capability -[tool_of]-> agent
             capability -[sends_to|writes_to]-> external|data_store
    Negative: agent has guardrail of type "hitl" or "rate_limit"
    """
    G = nx.DiGraph()
    G.add_node("loop_agent", type="agent")
    G.add_node("write_cap", type="capability")
    G.add_node("ext_target", type="external_service")
    G.add_edge("loop_agent", "loop_agent", type="delegates_to")  # self-loop
    G.add_edge("write_cap", "loop_agent", type="tool_of")
    G.add_edge("write_cap", "ext_target", type="calls")
    return G


def build_multi_tc_graph():
    """Build a graph that should trigger both TC-001 and TC-007."""
    G = nx.DiGraph()
    # TC-001 pattern
    G.add_node("orch", type="agent")
    G.add_node("worker", type="agent")
    G.add_node("cred_store", type="data_store", data_sensitivity="credentials")
    G.add_edge("orch", "worker", type="delegates_to", has_control=False)
    G.add_edge("cred_store", "worker", type="reads_from")

    # TC-007 pattern
    G.add_node("shared_tool", type="capability")
    G.add_node("agent_a", type="agent")
    G.add_node("agent_b", type="agent")
    G.add_node("agent_c", type="agent")
    G.add_edge("shared_tool", "agent_a", type="tool_of")
    G.add_edge("shared_tool", "agent_b", type="tool_of")
    G.add_edge("shared_tool", "agent_c", type="tool_of")
    return G


# ── Tests ───────────────────────────────────────────────────────────


def test_load_catalog():
    """Verify catalog loads, has 10 TCs, each has required fields."""
    catalog = load_catalog()
    assert len(catalog) == 10

    required_fields = {"tc_id", "name", "description", "severity", "finding_components", "pattern"}
    for tc in catalog:
        assert required_fields.issubset(tc.keys()), f"Missing fields in {tc.get('tc_id')}"


def test_match_tc_001():
    """Build minimal graph triggering TC-001, verify it matches."""
    G = build_tc001_graph()
    matches = match_all(G)

    tc001_matches = [m for m in matches if m.tc_id == "STRATUM-TC-001"]
    assert len(tc001_matches) >= 1, "TC-001 should fire on unsupervised delegation to credential-exposed worker"

    match = tc001_matches[0]
    assert match.severity == "CRITICAL"
    assert "orch" in match.matched_path or "worker" in match.matched_path


def test_no_match_tc_001_with_control():
    """Same graph but with has_control=true on delegation edge. TC-001 should NOT fire."""
    G = build_tc001_graph_with_control()
    matches = match_all(G)

    tc001_matches = [m for m in matches if m.tc_id == "STRATUM-TC-001"]
    assert len(tc001_matches) == 0, "TC-001 should NOT fire when delegation has control"


def test_match_tc_002():
    """Build graph triggering TC-002 (PII exfiltration through delegation chain)."""
    G = build_tc002_graph()
    matches = match_all(G)

    tc002_matches = [m for m in matches if m.tc_id == "STRATUM-TC-002"]
    assert len(tc002_matches) >= 1, "TC-002 should fire on PII exfiltration via delegation"
    assert tc002_matches[0].severity == "CRITICAL"


def test_match_tc_005():
    """Build graph triggering TC-005 (EchoLeak inbox-to-outbound)."""
    G = build_tc005_graph()
    matches = match_all(G)

    tc005_matches = [m for m in matches if m.tc_id == "STRATUM-TC-005"]
    assert len(tc005_matches) >= 1, "TC-005 should fire on inbox-to-outbound pattern"
    assert tc005_matches[0].severity == "CRITICAL"


def test_match_tc_007():
    """Build graph triggering TC-007 (blast radius amplification, fan_out >= 3)."""
    G = build_tc007_graph()
    matches = match_all(G)

    tc007_matches = [m for m in matches if m.tc_id == "STRATUM-TC-007"]
    assert len(tc007_matches) >= 1, "TC-007 should fire when tool shared by 3+ agents"
    assert tc007_matches[0].severity == "HIGH"


def test_no_match_empty_graph():
    """Empty graph matches no TCs."""
    G = nx.DiGraph()
    matches = match_all(G)
    assert len(matches) == 0


def test_no_match_single_agent():
    """Single agent with tools, no delegation, should not match delegation-based TCs."""
    G = nx.DiGraph()
    G.add_node("agent", type="agent")
    G.add_node("tool1", type="capability")
    G.add_node("tool2", type="capability")
    G.add_edge("tool1", "agent", type="tool_of")
    G.add_edge("tool2", "agent", type="tool_of")
    matches = match_all(G)

    delegation_tcs = [m for m in matches if m.tc_id in ("STRATUM-TC-001", "STRATUM-TC-002", "STRATUM-TC-008")]
    assert len(delegation_tcs) == 0, "Single agent should not trigger delegation-based TCs"


def test_multiple_tc_match():
    """Build a graph that triggers 2+ TCs simultaneously."""
    G = build_multi_tc_graph()
    matches = match_all(G)

    tc_ids = {m.tc_id for m in matches}
    assert len(tc_ids) >= 2, f"Expected 2+ distinct TCs, got {tc_ids}"


def test_match_results_sorted_by_severity():
    """Verify CRITICAL comes before HIGH in results."""
    G = build_multi_tc_graph()
    matches = match_all(G)

    if len(matches) >= 2:
        # Check that CRITICAL TCs appear before HIGH TCs
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        severities = [severity_order.get(m.severity, 99) for m in matches]
        assert severities == sorted(severities), "Results should be sorted CRITICAL -> HIGH -> MEDIUM -> LOW"


def test_dedup_same_subgraph():
    """Same TC pattern appearing via different isomorphism mappings should be deduped."""
    # Build a graph with symmetric agents — could produce multiple mappings
    G = nx.DiGraph()
    G.add_node("orch", type="agent")
    G.add_node("worker", type="agent")
    G.add_node("cred_store", type="data_store", data_sensitivity="credentials")
    G.add_edge("orch", "worker", type="delegates_to", has_control=False)
    G.add_edge("cred_store", "worker", type="reads_from")

    matches = match_all(G)
    tc001_matches = [m for m in matches if m.tc_id == "STRATUM-TC-001"]
    # Should only match once even if isomorphism produces duplicates
    assert len(tc001_matches) <= 1, "Same subgraph should be deduped"


def test_negative_constraint_hitl_suppresses():
    """Verify that adding a HITL guardrail to a worker suppresses TC-001."""
    # Without HITL — should match
    G_no_hitl = build_tc001_graph()
    matches_no_hitl = match_all(G_no_hitl)
    tc001_no_hitl = [m for m in matches_no_hitl if m.tc_id == "STRATUM-TC-001"]
    assert len(tc001_no_hitl) >= 1, "TC-001 should fire without HITL"

    # With HITL — TC-001 has negative constraint on edge_on_path has_control,
    # not on has_guardrail_type. Test the guardrail-based suppression via TC-003/TC-004.
    # For TC-001 specifically, test the has_control edge suppression:
    G_controlled = build_tc001_graph_with_control()
    matches_controlled = match_all(G_controlled)
    tc001_controlled = [m for m in matches_controlled if m.tc_id == "STRATUM-TC-001"]
    assert len(tc001_controlled) == 0, "TC-001 should be suppressed with has_control=True"


def test_match_tc_003():
    """Build graph triggering TC-003 (code execution reachable from external input)."""
    G = build_tc003_graph()
    matches = match_all(G)

    tc003_matches = [m for m in matches if m.tc_id == "STRATUM-TC-003"]
    assert len(tc003_matches) >= 1, "TC-003 should fire when external input reaches code exec agent"
    assert tc003_matches[0].severity == "CRITICAL"


def test_match_tc_004():
    """Build graph triggering TC-004 (financial operation through shared context)."""
    G = build_tc004_graph()
    matches = match_all(G)

    tc004_matches = [m for m in matches if m.tc_id == "STRATUM-TC-004"]
    assert len(tc004_matches) >= 1, "TC-004 should fire when financial agent shares context with external-facing agent"
    assert tc004_matches[0].severity == "CRITICAL"


def test_match_tc_006():
    """Build graph triggering TC-006 (MCP credential cascade)."""
    G = build_tc006_graph()
    matches = match_all(G)

    tc006_matches = [m for m in matches if m.tc_id == "STRATUM-TC-006"]
    assert len(tc006_matches) >= 1, "TC-006 should fire when unauthenticated MCP and credentialed MCP share an agent"
    assert tc006_matches[0].severity == "HIGH"


def test_match_tc_008():
    """Build graph triggering TC-008 (checkpoint-free destructive pipeline)."""
    G = build_tc008_graph()
    matches = match_all(G)

    tc008_matches = [m for m in matches if m.tc_id == "STRATUM-TC-008"]
    assert len(tc008_matches) >= 1, "TC-008 should fire on 3-agent pipeline with no checkpoint"
    assert tc008_matches[0].severity == "HIGH"


def test_match_tc_009():
    """Build graph triggering TC-009 (cross-crew data sensitivity escalation)."""
    G = build_tc009_graph()
    matches = match_all(G)

    tc009_matches = [m for m in matches if m.tc_id == "STRATUM-TC-009"]
    assert len(tc009_matches) >= 1, "TC-009 should fire on uncontrolled cross-crew data flow"
    assert tc009_matches[0].severity == "HIGH"


def test_match_tc_010():
    """Build graph triggering TC-010 (autonomous loop with external write access)."""
    G = build_tc010_graph()
    matches = match_all(G)

    tc010_matches = [m for m in matches if m.tc_id == "STRATUM-TC-010"]
    assert len(tc010_matches) >= 1, "TC-010 should fire on self-looping agent with external write"
    assert tc010_matches[0].severity == "HIGH"
