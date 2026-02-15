"""Generate all 9 eval outputs from the simple_crew test fixture."""
from __future__ import annotations

import dataclasses
import json
import os
import sys

# Add stratum to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from stratum.scanner import scan
from stratum.reliability.metrics_compute import classify_gap

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "test_fixtures", "simple_crew")
OUTPUT_DIR = os.path.dirname(__file__)


def main():
    print("Scanning fixture:", FIXTURE_DIR)
    result = scan(FIXTURE_DIR)

    # Collect data
    rel_findings = getattr(result, "reliability_findings", [])
    comp_findings = getattr(result, "composite_findings", [])
    rel_metrics = getattr(result, "reliability_metrics", {})
    per_node = getattr(result, "per_node_metrics", [])
    rel_score = getattr(result, "reliability_score", 0)
    obs_points = getattr(result, "observation_points", [])
    motifs = getattr(result, "graph_motifs", [])
    repo_profile = getattr(result, "repo_profile", {})
    sec_findings = result.top_paths + result.signals

    print(f"  Security findings: {len(sec_findings)}")
    print(f"  Reliability findings: {len(rel_findings)}")
    print(f"  Composite findings: {len(comp_findings)}")
    print(f"  Observation points: {len(obs_points)}")
    print(f"  Security score: {result.risk_score}")
    print(f"  Reliability score: {rel_score}")

    # --- 3. dry_run_simple.json ---
    simple = {
        "scan_id": result.scan_id,
        "directory": result.directory,
        "security_score": result.risk_score,
        "reliability_score": rel_score,
        "gap_classification": classify_gap(float(result.risk_score), float(rel_score)),
        "security_finding_count": len(sec_findings),
        "reliability_finding_count": len(rel_findings),
        "composite_finding_count": len(comp_findings),
        "security_findings": [
            {"id": f.id, "severity": f.severity.value, "title": f.title}
            for f in sec_findings
        ],
        "reliability_findings": [
            {"id": f.id, "severity": f.severity.value, "title": f.title, "path": f.path}
            for f in rel_findings
            if not f.id.startswith("STRAT-ANOMALY")
        ],
        "composite_findings": [
            {"id": f.id, "severity": f.severity.value, "title": f.title}
            for f in comp_findings
        ],
    }
    _write_json("dry_run_simple.json", simple)

    # --- 4. dry_run_full_graph.json ---
    graph_dict = {}
    if result.graph:
        graph_dict = {
            "nodes": [
                {
                    "id": nid,
                    "label": n.label,
                    "node_type": n.node_type.value if hasattr(n.node_type, 'value') else str(n.node_type),
                    "source_file": n.source_file or "",
                    "makes_decisions": getattr(n, "makes_decisions", False),
                    "error_handling_pattern": getattr(n, "error_handling_pattern", ""),
                    "betweenness_centrality": getattr(n, "betweenness_centrality", 0.0),
                    "reversibility": getattr(n, "reversibility", ""),
                }
                for nid, n in result.graph.nodes.items()
            ],
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "edge_type": e.edge_type.value if hasattr(e.edge_type, 'value') else str(e.edge_type),
                    "trust_crossing": getattr(e, "trust_crossing", False),
                    "schema_validated": getattr(e, "schema_validated", False),
                }
                for e in result.graph.edges
            ],
        }

    full = {
        "scan_id": result.scan_id,
        "graph": graph_dict,
        "structural_metrics": {
            "global": rel_metrics,
            "per_node": per_node,
        },
        "preconditions": [
            {
                "id": f.id, "severity": f.severity.value, "title": f.title,
                "path": f.path, "description": f.description,
                "evidence": f.evidence[:5], "remediation": f.remediation,
            }
            for f in rel_findings
            if not f.id.startswith("STRAT-ANOMALY")
        ],
        "compositions": [
            {
                "id": f.id, "severity": f.severity.value, "title": f.title,
                "description": f.description,
            }
            for f in comp_findings
        ],
        "structural_anomalies": [
            {"id": f.id, "severity": f.severity.value, "title": f.title, "description": f.description}
            for f in rel_findings
            if f.id.startswith("STRAT-ANOMALY")
        ],
        "graph_motifs": motifs,
        "observation_points": obs_points,
        "security_risk_score": result.risk_score,
        "reliability_risk_score": rel_score,
        "gap_classification": classify_gap(float(result.risk_score), float(rel_score)),
        "repo_profile": repo_profile,
    }
    _write_json("dry_run_full_graph.json", full)

    # --- 8. metrics_sample.json ---
    metrics_sample = {
        "global_metrics": rel_metrics,
        "per_node_metrics": per_node,
        "security_score": result.risk_score,
        "reliability_score": rel_score,
        "gap_classification": classify_gap(float(result.risk_score), float(rel_score)),
    }
    _write_json("metrics_sample.json", metrics_sample)

    # --- 5. terminal_output.txt ---
    _capture_terminal_output(result)

    # --- 6. finding_coverage.md ---
    _generate_finding_coverage(rel_findings)

    # --- 7. composition_coverage.md ---
    _generate_composition_coverage(comp_findings)

    # --- 9. enrichment_proof.md ---
    _generate_enrichment_proof(result)

    print("\nAll eval outputs generated in:", OUTPUT_DIR)


def _write_json(filename: str, data: dict):
    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"  Written: {filename}")


def _capture_terminal_output(result):
    """Capture Rich terminal output to text file."""
    import io
    from rich.console import Console

    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=80)

    # Simple text-based output for eval
    lines = []
    lines.append("=" * 60)
    lines.append("STRATUM SCAN — simple_crew fixture")
    lines.append("=" * 60)
    lines.append("")

    # Security
    sec_findings = result.top_paths + result.signals
    lines.append(f"Security Score: {result.risk_score}/100")
    lines.append(f"Security Findings: {len(sec_findings)}")
    for f in sec_findings[:5]:
        lines.append(f"  {f.severity.value:<8}  {f.id}  {f.title}")
    lines.append("")

    # Reliability
    rel_findings = getattr(result, "reliability_findings", [])
    comp_findings = getattr(result, "composite_findings", [])
    rel_score = getattr(result, "reliability_score", 0)
    rel_metrics = getattr(result, "reliability_metrics", {})

    main_rel = [f for f in rel_findings if not f.id.startswith("STRAT-ANOMALY")]
    anomalies = [f for f in rel_findings if f.id.startswith("STRAT-ANOMALY")]

    lines.append("-" * 60)
    lines.append("RELIABILITY ANALYSIS")
    lines.append("-" * 60)
    lines.append("")

    if rel_metrics:
        lines.append(
            f"Graph Topology: {rel_metrics.get('total_agents', 0)} agents | "
            f"{rel_metrics.get('total_capabilities', 0)} capabilities | "
            f"{rel_metrics.get('total_data_stores', 0)} data stores | "
            f"{rel_metrics.get('total_edges', 0)} edges"
        )
        lines.append(
            f"Delegation Depth: {rel_metrics.get('max_delegation_depth', 0)} | "
            f"Feedback Loops: {rel_metrics.get('feedback_loops_detected', 0)} | "
            f"Trust Crossings: {rel_metrics.get('trust_boundary_crossings', 0)}"
        )
        lines.append("")

    lines.append(f"Reliability Risk Score: {rel_score}/100")
    lines.append("")

    for f in main_rel:
        lines.append(f"  {f.severity.value:<8}  {f.id}  {f.title}")
        if f.path:
            lines.append(f"           {f.path[:60]}")

    if comp_findings:
        lines.append("")
        lines.append("COMPOSITIONS")
        for f in comp_findings:
            lines.append(f"  {f.severity.value}+     {f.id}  {f.title}")

    if anomalies:
        lines.append("")
        lines.append(f"  {len(anomalies)} structural anomalies detected (advisory)")

    lines.append("")
    lines.append("-" * 60)
    lines.append("DUAL-AXIS SUMMARY")
    lines.append("-" * 60)

    from stratum.reliability.metrics_compute import classify_gap
    gap = classify_gap(float(result.risk_score), float(rel_score))
    gap_labels = {
        "both_clean": "Both axes clean",
        "security_clean_reliability_poor": "BLIND SPOT — passes security, fails reliability",
        "security_poor_reliability_clean": "Security gaps, reliability OK",
        "both_poor": "Both axes need attention",
    }

    lines.append(f"Security Score:    {result.risk_score}/100")
    lines.append(f"Reliability Score: {rel_score}/100")
    lines.append(f"Classification:    {gap_labels.get(gap, gap)}")
    lines.append("")

    path = os.path.join(OUTPUT_DIR, "terminal_output.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print("  Written: terminal_output.txt")


def _generate_finding_coverage(rel_findings):
    """Generate finding_coverage.md showing which rules fired."""
    # All 27 Bucket A + 2 partial Bucket B
    all_rules = [
        "STRAT-DC-001", "STRAT-DC-002", "STRAT-DC-003", "STRAT-DC-004",
        "STRAT-DC-005", "STRAT-DC-006", "STRAT-DC-007", "STRAT-DC-008",
        "STRAT-OC-001", "STRAT-OC-002", "STRAT-OC-003", "STRAT-OC-004",
        "STRAT-SI-001", "STRAT-SI-002", "STRAT-SI-003", "STRAT-SI-004",
        "STRAT-SI-005", "STRAT-SI-006", "STRAT-SI-007",
        "STRAT-EA-001", "STRAT-EA-002", "STRAT-EA-003", "STRAT-EA-004", "STRAT-EA-006",
        "STRAT-AB-001", "STRAT-AB-003", "STRAT-AB-004", "STRAT-AB-006", "STRAT-AB-007",
    ]
    fired_ids = {f.id for f in rel_findings if not f.id.startswith("STRAT-ANOMALY")}

    lines = ["# Finding Coverage Report", ""]
    lines.append(f"**Fixture:** simple_crew (3-agent crewAI project)")
    lines.append(f"**Total rules:** {len(all_rules)}")
    lines.append(f"**Fired:** {len(fired_ids)}")
    lines.append(f"**Coverage:** {len(fired_ids)}/{len(all_rules)} ({100*len(fired_ids)/len(all_rules):.0f}%)")
    lines.append("")
    lines.append("| Rule ID | Status | Severity |")
    lines.append("|---------|--------|----------|")

    for rule in all_rules:
        if rule in fired_ids:
            f = next(f for f in rel_findings if f.id == rule)
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            lines.append(f"| {rule} | FIRED | {sev} |")
        else:
            lines.append(f"| {rule} | not fired | - |")

    lines.append("")
    lines.append("## Fired Findings Detail")
    lines.append("")
    for f in rel_findings:
        if f.id.startswith("STRAT-ANOMALY"):
            continue
        sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
        lines.append(f"### {f.id} — {f.title}")
        lines.append(f"- **Severity:** {sev}")
        lines.append(f"- **Path:** {f.path}")
        lines.append(f"- **Description:** {f.description}")
        if f.evidence:
            lines.append(f"- **Evidence:** {'; '.join(f.evidence[:3])}")
        lines.append("")

    path = os.path.join(OUTPUT_DIR, "finding_coverage.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print("  Written: finding_coverage.md")


def _generate_composition_coverage(comp_findings):
    """Generate composition_coverage.md."""
    all_comps = [
        "STRAT-COMP-001", "STRAT-COMP-002", "STRAT-COMP-003", "STRAT-COMP-004",
        "STRAT-COMP-005", "STRAT-COMP-006", "STRAT-COMP-007",
    ]
    all_xcomps = [
        "STRAT-XCOMP-001", "STRAT-XCOMP-002", "STRAT-XCOMP-003",
        "STRAT-XCOMP-004", "STRAT-XCOMP-005", "STRAT-XCOMP-006",
    ]

    fired_ids = {f.id for f in comp_findings}

    lines = ["# Composition Coverage Report", ""]
    lines.append(f"**Total COMP rules:** {len(all_comps)}")
    lines.append(f"**Total XCOMP rules:** {len(all_xcomps)}")
    lines.append(f"**Fired:** {len(fired_ids)}")
    lines.append("")
    lines.append("## Within-Reliability Compositions (STRAT-COMP)")
    lines.append("")
    lines.append("| ID | Status | Title |")
    lines.append("|----|--------|-------|")

    for comp_id in all_comps:
        if comp_id in fired_ids:
            f = next(f for f in comp_findings if f.id == comp_id)
            lines.append(f"| {comp_id} | FIRED | {f.title} |")
        else:
            lines.append(f"| {comp_id} | not fired | - |")

    lines.append("")
    lines.append("## Cross-Dataset Compositions (STRAT-XCOMP)")
    lines.append("")
    lines.append("| ID | Status | Title |")
    lines.append("|----|--------|-------|")

    for xcomp_id in all_xcomps:
        if xcomp_id in fired_ids:
            f = next(f for f in comp_findings if f.id == xcomp_id)
            lines.append(f"| {xcomp_id} | FIRED | {f.title} |")
        else:
            lines.append(f"| {xcomp_id} | not fired | - |")

    if comp_findings:
        lines.append("")
        lines.append("## Fired Compositions Detail")
        lines.append("")
        for f in comp_findings:
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            lines.append(f"### {f.id} — {f.title}")
            lines.append(f"- **Severity:** {sev}")
            lines.append(f"- **Description:** {f.description}")
            if f.evidence:
                lines.append(f"- **Evidence:** {'; '.join(f.evidence[:3])}")
            lines.append("")

    path = os.path.join(OUTPUT_DIR, "composition_coverage.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print("  Written: composition_coverage.md")


def _generate_enrichment_proof(result):
    """Generate enrichment_proof.md showing enrichment fields are populated."""
    lines = ["# Enrichment Proof", ""]
    lines.append("Evidence that the enrichment layer populated expected fields.")
    lines.append("")

    if not result.graph:
        lines.append("**No graph available.**")
        path = os.path.join(OUTPUT_DIR, "enrichment_proof.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return

    from stratum.graph.models import NodeType, EdgeType

    # Agent enrichment
    lines.append("## Agent Enrichment")
    lines.append("")
    for nid, node in result.graph.nodes.items():
        if node.node_type != NodeType.AGENT:
            continue
        lines.append(f"### {node.label}")
        lines.append(f"- `makes_decisions`: {getattr(node, 'makes_decisions', 'N/A')}")
        lines.append(f"- `error_handling_pattern`: {getattr(node, 'error_handling_pattern', 'N/A')}")
        lines.append(f"- `betweenness_centrality`: {getattr(node, 'betweenness_centrality', 'N/A')}")
        lines.append(f"- `delegation_enabled`: {getattr(node, 'delegation_enabled', 'N/A')}")
        lines.append(f"- `human_input_enabled`: {getattr(node, 'human_input_enabled', 'N/A')}")
        lines.append(f"- `objective_tag`: {getattr(node, 'objective_tag', 'N/A')}")
        lines.append(f"- `domain`: {getattr(node, 'domain', 'N/A')}")
        lines.append("")

    # Capability enrichment
    lines.append("## Capability Enrichment")
    lines.append("")
    for nid, node in result.graph.nodes.items():
        if node.node_type != NodeType.CAPABILITY:
            continue
        lines.append(f"### {node.label}")
        lines.append(f"- `reversibility`: {getattr(node, 'reversibility', 'N/A')}")
        lines.append(f"- `subtype`: {getattr(node, 'subtype', 'N/A')}")
        lines.append(f"- `external_service`: {getattr(node, 'external_service', 'N/A')}")
        lines.append(f"- `data_mutation`: {getattr(node, 'data_mutation', 'N/A')}")
        lines.append(f"- `human_visible`: {getattr(node, 'human_visible', 'N/A')}")
        lines.append(f"- `idempotent`: {getattr(node, 'idempotent', 'N/A')}")
        lines.append("")

    # Data store enrichment
    lines.append("## Data Store Enrichment")
    lines.append("")
    for nid, node in result.graph.nodes.items():
        if node.node_type != NodeType.DATA_STORE:
            continue
        lines.append(f"### {node.label}")
        lines.append(f"- `concurrency_control`: {getattr(node, 'concurrency_control', 'N/A')}")
        lines.append(f"- `persistence`: {getattr(node, 'persistence', 'N/A')}")
        lines.append(f"- `schema_defined`: {getattr(node, 'schema_defined', 'N/A')}")
        lines.append("")

    # Edge enrichment
    lines.append("## Edge Enrichment")
    lines.append("")
    edge_types_seen = set()
    for edge in result.graph.edges:
        etype = edge.edge_type.value if hasattr(edge.edge_type, 'value') else str(edge.edge_type)
        if etype not in edge_types_seen:
            edge_types_seen.add(etype)
            src = result.graph.nodes.get(edge.source)
            tgt = result.graph.nodes.get(edge.target)
            src_label = src.label if src else edge.source
            tgt_label = tgt.label if tgt else edge.target
            lines.append(f"- `{etype}`: {src_label} → {tgt_label}")
            if hasattr(edge, 'trust_crossing') and edge.trust_crossing:
                lines.append(f"  - `trust_crossing`: True")
            if hasattr(edge, 'schema_validated') and edge.schema_validated:
                lines.append(f"  - `schema_validated`: True")
    lines.append("")

    # Computed edges
    lines.append("## Computed Edges")
    lines.append("")
    computed_types = {
        EdgeType.IMPLICIT_AUTHORITY_OVER, EdgeType.ERROR_PROPAGATION_PATH,
    }
    # Also check for SHARED_STATE_CONFLICT if it exists
    for edge in result.graph.edges:
        etype_str = edge.edge_type.value if hasattr(edge.edge_type, 'value') else str(edge.edge_type)
        if edge.edge_type in computed_types or etype_str == "shared_state_conflict":
            src = result.graph.nodes.get(edge.source)
            tgt = result.graph.nodes.get(edge.target)
            src_label = src.label if src else edge.source
            tgt_label = tgt.label if tgt else edge.target
            lines.append(f"- `{etype_str}`: {src_label} → {tgt_label}")

    path = os.path.join(OUTPUT_DIR, "enrichment_proof.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print("  Written: enrichment_proof.md")


if __name__ == "__main__":
    main()
