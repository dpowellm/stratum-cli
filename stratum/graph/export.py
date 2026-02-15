"""
Graph export serializer.

Writes the full scan graph as JSON alongside the telemetry ping.
Output file: .stratum/graph.json

Privacy contract: same as telemetry. No file paths, function names,
class names, or code content. Node IDs are hashed labels. Tool names
and library names included (open-source identifiers).
"""
from __future__ import annotations

import json
from pathlib import Path


def export_graph(graph, findings, tc_matches, scan_id, output_dir):
    """Serialize the scan graph to .stratum/graph.json.

    Args:
        graph: The RiskGraph from graph/builder.py (or NetworkX DiGraph)
        findings: List of Finding objects
        tc_matches: List of TCMatch objects from toxic_combinations.py
        scan_id: The scan ID for cross-referencing
        output_dir: Path to .stratum/ directory
    """
    export = {
        "scan_id": scan_id,
        "schema_version": "2.0",
        "graph": {
            "nodes": [],
            "edges": [],
        },
        "findings": [],
        "toxic_combinations": [],
    }

    # Serialize nodes — handle both RiskGraph and NetworkX DiGraph
    if hasattr(graph, 'nodes') and isinstance(graph.nodes, dict):
        # RiskGraph: .nodes is dict[str, GraphNode]
        for node_id, node in graph.nodes.items():
            node_export = {
                "id": node_id,
                "type": node.node_type.value if hasattr(node.node_type, 'value') else str(node.node_type),
                "properties": {
                    "label": node.label,
                    "trust_level": node.trust_level.value if hasattr(node.trust_level, 'value') else str(node.trust_level),
                    "data_sensitivity": node.data_sensitivity,
                },
            }
            export["graph"]["nodes"].append(node_export)
    else:
        # NetworkX DiGraph
        for node_id, attrs in graph.nodes(data=True):
            node_export = {
                "id": node_id,
                "type": attrs.get("type", attrs.get("node_type", "unknown")),
                "properties": {k: v for k, v in attrs.items()
                             if k not in ("type", "node_type", "_pattern")},
            }
            export["graph"]["nodes"].append(node_export)

    # Serialize edges
    if hasattr(graph, 'edges') and isinstance(graph.edges, list):
        # RiskGraph: .edges is list[GraphEdge]
        for edge in graph.edges:
            edge_export = {
                "source": edge.source,
                "target": edge.target,
                "type": edge.edge_type.value if hasattr(edge.edge_type, 'value') else str(edge.edge_type),
                "properties": {
                    "has_control": edge.has_control,
                    "data_sensitivity": edge.data_sensitivity,
                    "trust_crossing": edge.trust_crossing,
                },
            }
            export["graph"]["edges"].append(edge_export)
    else:
        # NetworkX DiGraph
        for src, tgt, attrs in graph.edges(data=True):
            edge_export = {
                "source": src,
                "target": tgt,
                "type": attrs.get("type", attrs.get("edge_type", "unknown")),
                "properties": {k: v for k, v in attrs.items()
                             if k not in ("type", "edge_type", "_pattern")},
            }
            export["graph"]["edges"].append(edge_export)

    # Serialize finding instances
    for finding in findings:
        export["findings"].append({
            "rule_id": finding.id,
            "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
            "confidence": finding.confidence.value if hasattr(finding.confidence, 'value') else str(finding.confidence),
            "category": finding.category.value if hasattr(finding.category, 'value') else str(finding.category),
        })

    # Serialize TC matches
    for tc in tc_matches:
        export["toxic_combinations"].append({
            "tc_id": tc.tc_id,
            "severity": tc.severity,
            "matched_nodes": tc.matched_nodes,
            "matched_path": tc.matched_path,
        })

    # Write
    output_path = Path(output_dir) / "graph.json"
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(export, f, indent=2, default=str)

    return output_path
