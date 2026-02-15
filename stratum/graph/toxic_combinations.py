"""
Toxic combination pattern matcher.

Loads the TC catalog from data/toxic_combinations.json.
Matches each TC pattern against the scan graph using subgraph isomorphism.
Returns matched TCs with the specific subgraph paths highlighted.

This module has ONE job: given a graph and a catalog, return matches.
No scoring, no remediation, no output formatting.
"""
from __future__ import annotations

import json
import logging

import networkx as nx
from networkx.algorithms import isomorphism
from pathlib import Path

from stratum.models import TCMatch

logger = logging.getLogger(__name__)

EXPECTED_CATALOG_SCHEMA = "1.0"


def load_catalog() -> list[dict]:
    """Load TC catalog from package data."""
    catalog_path = Path(__file__).parent.parent / "data" / "toxic_combinations.json"
    with open(catalog_path) as f:
        catalog = json.load(f)

    # Version compatibility check
    schema_ver = catalog.get("schema_version", "")
    if schema_ver and schema_ver != EXPECTED_CATALOG_SCHEMA:
        logger.warning(
            "TC catalog version mismatch (have %s, expected %s). "
            "Run `pip install --upgrade stratum-cli` for latest toxic combination detection.",
            schema_ver, EXPECTED_CATALOG_SCHEMA,
        )

    return catalog["toxic_combinations"]


def riskgraph_to_networkx(risk_graph) -> nx.DiGraph:
    """Convert a RiskGraph (custom dataclass) to a NetworkX DiGraph.

    The scan graph uses RiskGraph with .nodes (dict[str, GraphNode]) and
    .edges (list[GraphEdge]). The TC pattern matcher needs a NetworkX DiGraph
    for subgraph isomorphism matching.
    """
    G = nx.DiGraph()

    for node_id, node in risk_graph.nodes.items():
        G.add_node(node_id,
            type=node.node_type.value,
            node_type=node.node_type.value,
            label=node.label,
            trust_level=node.trust_level.value,
            data_sensitivity=node.data_sensitivity,
            framework=node.framework,
            has_error_handling=node.has_error_handling,
            has_timeout=node.has_timeout,
            mcp_auth=node.mcp_auth,
            mcp_pinned=node.mcp_pinned,
            mcp_remote=node.mcp_remote,
            kind=node.guardrail_kind,
            guardrail_kind=node.guardrail_kind,
            guardrail_active=node.guardrail_active,
        )

    for edge in risk_graph.edges:
        G.add_edge(edge.source, edge.target,
            type=edge.edge_type.value,
            edge_type=edge.edge_type.value,
            has_control=edge.has_control,
            control_type=edge.control_type,
            data_sensitivity=edge.data_sensitivity,
            trust_crossing=edge.trust_crossing,
            crossing_direction=edge.crossing_direction,
        )

    return G


def match_all(scan_graph, catalog: list[dict] | None = None) -> list[TCMatch]:
    """Match all TCs in the catalog against the scan graph.

    Accepts either a RiskGraph (custom dataclass) or a NetworkX DiGraph.
    Returns list of TCMatch objects, sorted by severity (CRITICAL first).
    """
    # Convert RiskGraph to NetworkX if needed
    if not isinstance(scan_graph, nx.DiGraph):
        try:
            nx_graph = riskgraph_to_networkx(scan_graph)
        except Exception:
            logger.warning("Failed to convert scan graph to NetworkX, skipping TC matching")
            return []
    else:
        nx_graph = scan_graph

    if catalog is None:
        try:
            catalog = load_catalog()
        except Exception:
            logger.warning("Failed to load TC catalog, skipping TC matching")
            return []

    matches = []
    for tc_def in catalog:
        tc_matches = _match_single_tc(nx_graph, tc_def)
        matches.extend(tc_matches)

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    matches.sort(key=lambda m: severity_order.get(m.severity, 99))
    return matches


def _match_single_tc(scan_graph: nx.DiGraph, tc_def: dict) -> list[TCMatch]:
    """Match a single TC pattern against the scan graph.

    Returns one TCMatch per distinct matching subgraph.
    Deduplicates by the set of matched node IDs.
    """
    pattern = tc_def["pattern"]
    template = _build_template_graph(pattern)

    matcher = isomorphism.DiGraphMatcher(
        scan_graph,
        template,
        node_match=_make_node_matcher(pattern["nodes"]),
        edge_match=_make_edge_matcher(pattern["edges"]),
    )

    seen = set()
    results = []

    for mapping in matcher.subgraph_isomorphisms_iter():
        # mapping is {scan_graph_node: template_node}
        # Invert to {template_node: scan_graph_node}
        inv_mapping = {v: k for k, v in mapping.items()}

        # Dedup by frozenset of matched scan graph nodes
        key = frozenset(inv_mapping.values())
        if key in seen:
            continue
        seen.add(key)

        # Check negative constraints
        if _any_negative_constraint_satisfied(
            scan_graph, inv_mapping, pattern.get("negative_constraints", [])
        ):
            continue

        # Build the matched path (ordered by pattern edge chain)
        var_to_node = {
            node_def["var"]: inv_mapping[node_def["var"]]
            for node_def in pattern["nodes"]
        }
        matched_path = _extract_path(scan_graph, var_to_node, pattern["edges"])
        matched_edges = _extract_matched_edges(scan_graph, var_to_node, pattern["edges"])

        results.append(TCMatch(
            tc_id=tc_def["tc_id"],
            name=tc_def["name"],
            severity=tc_def["severity"],
            description=tc_def["description"],
            finding_components=tc_def["finding_components"],
            owasp_ids=tc_def.get("owasp_ids", []),
            matched_nodes=var_to_node,
            matched_edges=matched_edges,
            matched_path=matched_path,
            remediation=tc_def.get("remediation", {}),
        ))

    return results


def _build_template_graph(pattern: dict) -> nx.DiGraph:
    """Build a NetworkX DiGraph from a TC pattern definition."""
    G = nx.DiGraph()
    for node_def in pattern["nodes"]:
        G.add_node(node_def["var"], **{"_pattern": node_def})
    for edge_def in pattern["edges"]:
        G.add_edge(edge_def["from"], edge_def["to"], **{"_pattern": edge_def})
    return G


def _make_node_matcher(node_defs: list[dict]):
    """Create a node matching function for DiGraphMatcher."""
    def node_match(scan_attrs, template_attrs):
        pattern_def = template_attrs.get("_pattern")
        if not pattern_def:
            return True

        # Type check
        required_type = pattern_def.get("type")
        if required_type:
            scan_type = scan_attrs.get("type", scan_attrs.get("node_type", ""))
            if isinstance(required_type, list):
                if scan_type not in required_type:
                    return False
            elif scan_type != required_type:
                return False

        # Property constraints
        for key, value in pattern_def.get("constraints", {}).items():
            if scan_attrs.get(key) != value:
                return False

        return True

    return node_match


def _make_edge_matcher(edge_defs: list[dict]):
    """Create an edge matching function for DiGraphMatcher."""
    def edge_match(scan_attrs, template_attrs):
        pattern_def = template_attrs.get("_pattern")
        if not pattern_def:
            return True

        # Type check
        required_type = pattern_def.get("type")
        if required_type:
            scan_type = scan_attrs.get("type", scan_attrs.get("edge_type", ""))
            if isinstance(required_type, list):
                if scan_type not in required_type:
                    return False
            elif scan_type != required_type:
                return False

        # Property constraints
        for key, value in pattern_def.get("constraints", {}).items():
            if scan_attrs.get(key) != value:
                return False

        return True

    return edge_match


def _any_negative_constraint_satisfied(
    scan_graph: nx.DiGraph,
    var_to_node: dict[str, str],
    negative_constraints: list[dict],
) -> bool:
    """Return True if any negative constraint is satisfied (meaning the TC should NOT fire)."""
    for nc in negative_constraints:
        if "edge_on_path" in nc:
            # Check if any edge on the path between two matched nodes has the property
            src = var_to_node.get(nc["edge_on_path"][0])
            tgt = var_to_node.get(nc["edge_on_path"][1])
            if src and tgt:
                try:
                    for path in nx.all_simple_paths(scan_graph, src, tgt, cutoff=10):
                        for i in range(len(path) - 1):
                            edge_data = scan_graph.get_edge_data(path[i], path[i + 1], default={})
                            # Check all constraint properties on this edge
                            # (excluding edge_on_path which is structural)
                            constraint_keys = {
                                k for k in nc.keys()
                                if k != "edge_on_path"
                            }
                            for prop in constraint_keys:
                                expected_val = nc[prop]
                                if edge_data.get(prop) == expected_val:
                                    return True  # Negative constraint satisfied -> suppress TC
                except nx.NetworkXError:
                    pass

        if "node" in nc and "has_guardrail_type" in nc:
            # Check if the matched node has a guardrail of the specified type
            node_id = var_to_node.get(nc["node"])
            if node_id:
                for _, neighbor, edge_data in scan_graph.edges(node_id, data=True):
                    if edge_data.get("type") in ("gated_by", "filtered_by"):
                        neighbor_data = scan_graph.nodes.get(neighbor, {})
                        if neighbor_data.get("kind") == nc["has_guardrail_type"]:
                            return True  # Negative constraint satisfied -> suppress TC
                # Also check incoming edges (guardrails can gate from either direction)
                for neighbor, _, edge_data in scan_graph.in_edges(node_id, data=True):
                    if edge_data.get("type") in ("gated_by", "filtered_by"):
                        neighbor_data = scan_graph.nodes.get(neighbor, {})
                        if neighbor_data.get("kind") == nc["has_guardrail_type"]:
                            return True

    return False


def _extract_path(scan_graph, var_to_node, edge_defs):
    """Extract the ordered risk path from matched nodes."""
    if not edge_defs:
        return list(var_to_node.values())

    # Follow edge definitions to build ordered path
    path = []
    visited = set()

    # Start from the first edge's source
    current_var = edge_defs[0]["from"]
    path.append(var_to_node[current_var])
    visited.add(current_var)

    for edge_def in edge_defs:
        target_var = edge_def["to"]
        if target_var not in visited:
            path.append(var_to_node[target_var])
            visited.add(target_var)

    # Add any unvisited nodes at the end
    for var, node_id in var_to_node.items():
        if var not in visited:
            path.append(node_id)

    return path


def _extract_matched_edges(scan_graph, var_to_node, edge_defs):
    """Extract the matched edges as (source, target, type) tuples."""
    edges = []
    for edge_def in edge_defs:
        src = var_to_node.get(edge_def["from"])
        tgt = var_to_node.get(edge_def["to"])
        if src and tgt:
            edge_data = scan_graph.get_edge_data(src, tgt, default={})
            edges.append((
                src, tgt,
                edge_data.get("type", edge_def.get("type", "unknown")),
            ))
    return edges
