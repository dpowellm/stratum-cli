"""Tests for TC catalog integrity.

Validates that the toxic_combinations.json catalog is well-formed
and all TCs have the required structure.
"""
import pytest

from stratum.graph.toxic_combinations import load_catalog


@pytest.fixture
def catalog():
    """Load the TC catalog once for all tests."""
    return load_catalog()


def test_all_tcs_have_unique_ids(catalog):
    """No duplicate tc_ids."""
    ids = [tc["tc_id"] for tc in catalog]
    assert len(ids) == len(set(ids)), f"Duplicate tc_ids found: {[x for x in ids if ids.count(x) > 1]}"


def test_all_tcs_have_patterns(catalog):
    """Every TC has nodes, edges in pattern."""
    for tc in catalog:
        pattern = tc.get("pattern", {})
        assert "nodes" in pattern, f"{tc['tc_id']} missing pattern.nodes"
        assert "edges" in pattern, f"{tc['tc_id']} missing pattern.edges"
        assert len(pattern["nodes"]) >= 2, f"{tc['tc_id']} needs at least 2 pattern nodes"
        assert len(pattern["edges"]) >= 1, f"{tc['tc_id']} needs at least 1 pattern edge"


def test_all_tcs_have_remediation(catalog):
    """Every TC has remediation with description and effort."""
    for tc in catalog:
        remediation = tc.get("remediation", {})
        assert "description" in remediation, f"{tc['tc_id']} missing remediation.description"
        assert "effort" in remediation, f"{tc['tc_id']} missing remediation.effort"
        assert remediation["effort"] in ("low", "medium", "high"), \
            f"{tc['tc_id']} has invalid effort: {remediation['effort']}"


def test_all_tcs_have_severity(catalog):
    """Severity is CRITICAL, HIGH, or MEDIUM."""
    valid_severities = {"CRITICAL", "HIGH", "MEDIUM"}
    for tc in catalog:
        assert tc["severity"] in valid_severities, \
            f"{tc['tc_id']} has invalid severity: {tc['severity']}"


def test_all_tcs_have_finding_components(catalog):
    """Each TC references valid STRATUM rule IDs."""
    for tc in catalog:
        components = tc.get("finding_components", [])
        assert len(components) >= 1, f"{tc['tc_id']} has no finding_components"
        for comp in components:
            assert comp.startswith("STRATUM-"), \
                f"{tc['tc_id']} has invalid component: {comp}"


def test_pattern_nodes_have_vars(catalog):
    """Every pattern node has a var field."""
    for tc in catalog:
        pattern = tc.get("pattern", {})
        for node in pattern.get("nodes", []):
            assert "var" in node, \
                f"{tc['tc_id']} has pattern node without var field"
            assert isinstance(node["var"], str) and len(node["var"]) > 0, \
                f"{tc['tc_id']} has empty var field"


def test_pattern_edges_reference_valid_vars(catalog):
    """Every edge from/to references a defined node var."""
    for tc in catalog:
        pattern = tc.get("pattern", {})
        defined_vars = {n["var"] for n in pattern.get("nodes", [])}
        for edge in pattern.get("edges", []):
            assert edge["from"] in defined_vars, \
                f"{tc['tc_id']} edge references undefined var: {edge['from']}"
            assert edge["to"] in defined_vars, \
                f"{tc['tc_id']} edge references undefined var: {edge['to']}"


def test_catalog_version_present():
    """Catalog has catalog_version and schema_version fields."""
    import json
    from pathlib import Path

    catalog_path = Path(__file__).parent.parent / "stratum" / "data" / "toxic_combinations.json"
    with open(catalog_path) as f:
        raw = json.load(f)

    assert "catalog_version" in raw, "Missing catalog_version"
    assert "schema_version" in raw, "Missing schema_version"
    assert raw["schema_version"] == "1.0"
