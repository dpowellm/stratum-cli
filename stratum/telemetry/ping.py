"""Build v7.2 schema-compliant ping from scanner internals.

Flattens data from ScanResult, TelemetryProfile, and ScanProfile into a single
dict with all ~102 v7.2 telemetry fields at the top level.
"""
from __future__ import annotations

import os
import statistics
from collections import Counter
from typing import Any

from stratum import __version__

SCHEMA_ID = 5
SCHEMA_VERSION = "0.3.2"

# Severity weights for fix_impact_estimates (negative integers)
_SEVERITY_WEIGHT = {
    "CRITICAL": -25,
    "HIGH": -15,
    "MEDIUM": -8,
    "LOW": -3,
}


def _g(obj, attr, default=None):
    """Safely get an attribute from an object that may be None."""
    if obj is None:
        return default
    return getattr(obj, attr, default)


def build_v72_ping(
    result,
    telemetry_profile=None,
    scan_profile=None,
    scan_duration_ms: int | None = None,
    repo_full_name: str | None = None,
    repo_url: str | None = None,
) -> dict[str, Any]:
    """Build a flat v7.2 schema-compliant ping dict.

    Args:
        result: ScanResult from the scanner
        telemetry_profile: TelemetryProfile from build_profile()
        scan_profile: ScanProfile from build_scan_profile()
        scan_duration_ms: wall-clock scan duration in milliseconds
        repo_full_name: Repository full name (e.g. 'owner/repo') for identity
        repo_url: Repository URL for identity

    Returns:
        Flat dict with all v7.2 fields. Never raises — uses defaults on failure.
    """
    ping: dict[str, Any] = {}

    # Collect all findings once
    all_findings = []
    try:
        all_findings = list(getattr(result, "top_paths", []) or []) + \
                       list(getattr(result, "signals", []) or [])
    except Exception:
        pass

    # Pre-compute unique rules and instance counts
    unique_rules: dict[str, Any] = {}  # rule_id -> Finding (first instance)
    instance_counter: Counter = Counter()
    for f in all_findings:
        fid = _finding_id(f)
        instance_counter[fid] += 1
        if fid not in unique_rules:
            unique_rules[fid] = f

    finding_rules_list = sorted(unique_rules.keys())
    finding_rule_count = len(finding_rules_list)

    # Severity counts of UNIQUE rules (not instances) so that
    # finding_rule_count == sum(finding_severities.values())
    sev_counts: dict[str, int] = {}
    conf_counts: dict[str, int] = {}
    for fid, f in unique_rules.items():
        sev = _finding_severity(f)
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        conf = _finding_confidence(f)
        conf_counts[conf] = conf_counts.get(conf, 0) + 1

    finding_instance_counts = dict(instance_counter)
    total_finding_instances = sum(instance_counter.values())

    # Pre-compute crew/agent lists
    crews = list(getattr(result, "crew_definitions", []) or [])
    agents = list(getattr(result, "agent_definitions", []) or [])
    crew_count = len(crews)
    agent_count = len(agents)

    # Frameworks
    frameworks = list(getattr(result, "detected_frameworks", []) or [])

    # ── A) IDENTITY & VERSIONING ──────────────────────────────────────
    try:
        ping["scan_id"] = result.scan_id
        ping["timestamp"] = result.timestamp
        ping["scanner_version"] = __version__
        ping["repo_hash"] = _g(telemetry_profile, "topology_signature_hash", "")
        ping["schema_id"] = SCHEMA_ID
        ping["schema_version"] = SCHEMA_VERSION
    except Exception:
        ping.setdefault("scan_id", "")
        ping.setdefault("timestamp", "")
        ping.setdefault("scanner_version", __version__)
        ping.setdefault("repo_hash", "")
        ping.setdefault("schema_id", SCHEMA_ID)
        ping.setdefault("schema_version", SCHEMA_VERSION)

    # ── A2) REPO IDENTITY (from CLI flags) ───────────────────────────
    if repo_full_name:
        ping["repo_full_name"] = repo_full_name
    if repo_url:
        ping["repo_url"] = repo_url

    # ── B) SCAN METADATA ─────────────────────────────────────────────
    try:
        files_scanned = getattr(result, "files_scanned", 0)
        if files_scanned == 0 and not all_findings:
            scan_status = "empty"
        else:
            scan_status = "success"
        ping["scan_status"] = scan_status
        ping["scan_duration_ms"] = scan_duration_ms or 0
        ping["files_scanned"] = files_scanned
        ping["files_total"] = files_scanned  # same for now
        ping["parser_errors"] = 0  # not tracked yet
        ping["failure_reason"] = None
    except Exception:
        ping.setdefault("scan_status", "success")
        ping.setdefault("scan_duration_ms", 0)
        ping.setdefault("files_scanned", 0)
        ping.setdefault("files_total", 0)
        ping.setdefault("parser_errors", 0)
        ping.setdefault("failure_reason", None)

    # ── C) PROMOTE NESTED FIELDS from TelemetryProfile ────────────────
    try:
        # Architecture
        ping["archetype_class"] = _g(telemetry_profile, "archetype_class", "")
        ping["total_capabilities"] = getattr(result, "total_capabilities", 0)
        ping["capability_distribution"] = _g(telemetry_profile, "capability_distribution", {})
        ping["trust_level_distribution"] = _g(telemetry_profile, "trust_level_distribution", {})
        ping["trust_crossings"] = _g(telemetry_profile, "trust_crossings", {})
        ping["total_trust_crossings"] = _g(telemetry_profile, "total_trust_crossings", 0)
        ping["topology_signature_hash"] = _g(telemetry_profile, "topology_signature_hash", "")
        ping["trust_crossing_adjacency"] = _g(telemetry_profile, "trust_crossing_adjacency", {})

        # Graph topology
        ping["graph_node_count"] = _g(telemetry_profile, "graph_node_count", 0)
        ping["graph_edge_count"] = _g(telemetry_profile, "graph_edge_count", 0)
        ping["graph_node_type_distribution"] = _g(telemetry_profile, "graph_node_type_distribution", {})
        ping["graph_edge_type_distribution"] = _g(telemetry_profile, "graph_edge_type_distribution", {})
        ping["edge_density"] = _g(telemetry_profile, "edge_density", 0.0)

        # Guardrails & Controls
        ping["guardrail_count"] = getattr(result, "guardrail_count", 0)
        ping["has_any_guardrails"] = getattr(result, "has_any_guardrails", False)
        ping["guardrail_types"] = _g(telemetry_profile, "guardrail_types", [])
        ping["guardrail_linked_count"] = _g(telemetry_profile, "guardrail_linked_count", 0)
        ping["control_bypass_count"] = _g(telemetry_profile, "control_bypass_count", 0)
        ping["control_coverage_pct"] = _g(telemetry_profile, "control_coverage_pct", 0.0)
        ping["has_hitl_anywhere"] = _g(telemetry_profile, "has_hitl_anywhere", False)

        # MCP
        ping["mcp_server_count"] = getattr(result, "mcp_server_count", 0)
        ping["mcp_remote_count"] = _g(telemetry_profile, "mcp_remote_count", 0)
        ping["mcp_auth_ratio"] = _g(telemetry_profile, "mcp_auth_ratio", 0.0)
        ping["mcp_pinned_ratio"] = _g(telemetry_profile, "mcp_pinned_ratio", 0.0)

        # Risk score
        ping["risk_score"] = getattr(result, "risk_score", 0)
        ping["blast_radius_distribution"] = _g(telemetry_profile, "blast_radius_distribution", [])
        ping["max_blast_radius"] = _g(telemetry_profile, "max_blast_radius", 0)

        # Environment
        ping["has_env_in_gitignore"] = _g(telemetry_profile, "has_env_in_gitignore", False)
        ping["error_handling_rate"] = _g(telemetry_profile, "error_handling_rate", 0.0)
        ping["timeout_rate"] = _g(telemetry_profile, "timeout_rate", 0.0)
        ping["checkpoint_type"] = getattr(result, "checkpoint_type", "none")

        # Data & Privacy
        ping["has_pii"] = _g(telemetry_profile, "has_pii", False)
        ping["has_financial_data"] = _g(telemetry_profile, "has_financial_data", False)
        ping["has_financial_tools"] = _g(telemetry_profile, "has_financial_tools", False)
        ping["financial_validation_rate"] = _g(telemetry_profile, "financial_validation_rate", 0.0)
        ping["data_sensitivity_types"] = _g(telemetry_profile, "data_sensitivity_types", [])
        ping["has_shared_credentials"] = _g(telemetry_profile, "has_shared_credentials", False)

        # Security posture
        ping["mitigation_coverage"] = _g(telemetry_profile, "mitigation_coverage", {})
        ping["uncontrolled_path_count"] = _g(telemetry_profile, "uncontrolled_path_count", 0)
        ping["max_path_hops"] = _g(telemetry_profile, "max_path_hops", 0)
        ping["downward_trust_crossings"] = _g(telemetry_profile, "downward_trust_crossings", 0)
        ping["external_sink_count"] = _g(telemetry_profile, "external_sink_count", 0)
        ping["shared_tool_max_agents"] = _g(telemetry_profile, "shared_tool_max_agents", 0)
        ping["incident_match_count"] = _g(telemetry_profile, "incident_match_count", 0)
        ping["incident_ids"] = _g(telemetry_profile, "incident_ids", [])
        ping["regulatory_framework_count"] = _g(telemetry_profile, "regulatory_framework_count", 0)
        ping["regulatory_surface"] = _g(telemetry_profile, "regulatory_surface", [])

        # Agent properties
        ping["has_agent_identity"] = _g(telemetry_profile, "has_agent_identity", False)
        ping["has_shared_context"] = getattr(result, "has_shared_context", False)
        ping["has_context_provenance"] = _g(telemetry_profile, "has_context_provenance", False)
        ping["has_context_rollback"] = _g(telemetry_profile, "has_context_rollback", False)
        ping["has_memory_store"] = _g(telemetry_profile, "has_memory_store", False)
        ping["memory_store_types"] = _g(telemetry_profile, "memory_store_types", [])
        ping["has_learning_loop"] = getattr(result, "has_learning_loop", False)
        ping["learning_type"] = getattr(result, "learning_type", None)
        ping["has_eval_framework"] = _g(telemetry_profile, "has_eval_framework", False)
        ping["has_eval_conflict"] = getattr(result, "has_eval_conflict", False)
        ping["has_observability"] = _g(telemetry_profile, "has_observability", False)

    except Exception:
        # Defaults already set via setdefault pattern; skip remaining promotes
        pass

    # ── D) RENAMED FIELDS ─────────────────────────────────────────────
    ping["frameworks"] = frameworks

    # selection_stratum: derived from primary framework
    _FRAMEWORK_TO_STRATUM = {
        "CrewAI": "crewai",
        "LangGraph": "langgraph",
        "LangChain": "langchain_active",
        "AutoGen": "autogen",
    }
    primary_fw = frameworks[0] if frameworks else None
    ping["selection_stratum"] = _FRAMEWORK_TO_STRATUM.get(
        primary_fw, primary_fw.lower() if primary_fw else ""
    )

    # ── E) COMPUTED FIELDS from raw ScanResult ────────────────────────
    try:
        ping["agent_count"] = agent_count
        ping["crew_count"] = crew_count
        ping["finding_rules"] = finding_rules_list
        ping["finding_rule_count"] = finding_rule_count
        ping["finding_severities"] = sev_counts
        ping["finding_confidences"] = conf_counts
        ping["finding_instance_counts"] = finding_instance_counts
        ping["total_finding_instances"] = total_finding_instances
        ping["env_var_count"] = len(getattr(result, "env_vars", []) or [])
        ping["telemetry_destination_count"] = len(
            getattr(result, "telemetry_destinations", []) or []
        )

        # crew_size_distribution: sorted agents-per-crew (descending)
        crew_sizes = sorted(
            [len(_get_attr_or_key(c, "agent_names", [])) for c in crews],
            reverse=True,
        )
        ping["crew_size_distribution"] = crew_sizes

        # agent_tool_count_distribution: sorted tools-per-agent (descending)
        agent_tool_counts = sorted(
            [len(_get_attr_or_key(a, "tool_names", [])) for a in agents],
            reverse=True,
        )
        ping["agent_tool_count_distribution"] = agent_tool_counts

        # Rescan-only fields (empty on initial scan)
        ping["finding_coverages"] = {}
        ping["severity_downgrades"] = {}
        ping["crews_clean"] = 0
        ping["crews_with_findings"] = crew_count

    except Exception:
        ping.setdefault("agent_count", agent_count)
        ping.setdefault("crew_count", crew_count)
        ping.setdefault("finding_rules", finding_rules_list)
        ping.setdefault("finding_rule_count", finding_rule_count)
        ping.setdefault("finding_severities", sev_counts)
        ping.setdefault("finding_confidences", conf_counts)
        ping.setdefault("finding_instance_counts", finding_instance_counts)
        ping.setdefault("total_finding_instances", total_finding_instances)
        ping.setdefault("env_var_count", 0)
        ping.setdefault("telemetry_destination_count", 0)
        ping.setdefault("crew_size_distribution", [])
        ping.setdefault("agent_tool_count_distribution", [])
        ping.setdefault("finding_coverages", {})
        ping.setdefault("severity_downgrades", {})
        ping.setdefault("crews_clean", 0)
        ping.setdefault("crews_with_findings", 0)

    # ── F) FINDINGS by class/category ─────────────────────────────────
    try:
        ping["findings_by_class"] = _g(telemetry_profile, "findings_by_class", {})
        ping["findings_by_category"] = _g(telemetry_profile, "findings_by_category", {})
    except Exception:
        ping.setdefault("findings_by_class", {})
        ping.setdefault("findings_by_category", {})

    # ── G) NEW COMPUTED FIELDS ────────────────────────────────────────

    # G1: normalized_features
    try:
        raw_ac = ping.get("agent_count", 0)
        raw_cc = ping.get("crew_count", 0)
        trust_dist = ping.get("trust_level_distribution", {})
        total_caps = max(sum(trust_dist.values()), 1) if trust_dist else 1
        external_caps = trust_dist.get("external", 0) + trust_dist.get("public", 0)
        ping["normalized_features"] = {
            "findings_per_agent": round(finding_rule_count / raw_ac, 2) if raw_ac > 0 else 0.0,
            "findings_per_crew": round(finding_rule_count / raw_cc, 2) if raw_cc > 0 else 0.0,
            "guardrails_per_agent": round(ping.get("guardrail_count", 0) / raw_ac, 2) if raw_ac > 0 else 0.0,
            "tools_per_agent": round(ping.get("total_capabilities", 0) / raw_ac, 2) if raw_ac > 0 else 0.0,
            "external_exposure_ratio": round(external_caps / total_caps, 2),
            "guardrail_coverage_ratio": round(
                ping.get("control_coverage_pct", 0.0) / 100.0, 2
            ),
        }
    except Exception:
        ping.setdefault("normalized_features", {
            "findings_per_agent": 0.0, "findings_per_crew": 0.0,
            "guardrails_per_agent": 0.0, "tools_per_agent": 0.0,
            "external_exposure_ratio": 0.0, "guardrail_coverage_ratio": 0.0,
        })

    # G2: framework_versions (must match frameworks keys exactly)
    try:
        fv_source = _g(scan_profile, "framework_versions", None) or {}
        fw_versions = {}
        for fw in frameworks:
            fw_versions[fw] = fv_source.get(fw, None)
        ping["framework_versions"] = fw_versions
    except Exception:
        ping.setdefault("framework_versions", {fw: None for fw in frameworks})

    # G3: LLM providers & models
    try:
        raw_models = getattr(result, "llm_models", []) or []
        providers_set: set[str] = set()
        model_names: list[str] = []
        for m in raw_models:
            if isinstance(m, dict):
                prov = m.get("provider", m.get("vendor", "unknown"))
                model = m.get("model", m.get("name", ""))
                providers_set.add(prov)
                if model:
                    model_names.append(str(model))
            elif isinstance(m, str):
                model_names.append(m)
            elif hasattr(m, "provider"):
                providers_set.add(str(m.provider))
                if hasattr(m, "model"):
                    model_names.append(str(m.model))
        # Also pull from scan_profile if available
        sp_providers = _g(scan_profile, "llm_providers", [])
        if sp_providers:
            for p in sp_providers:
                providers_set.add(str(p))
        ping["llm_providers"] = sorted(providers_set) if providers_set else []
        ping["llm_models"] = model_names
        if providers_set:
            ping["provider_confidence"] = "detected"
        else:
            ping["provider_confidence"] = "unknown"
    except Exception:
        ping.setdefault("llm_providers", [])
        ping.setdefault("llm_models", [])
        ping.setdefault("provider_confidence", "unknown")

    # G4: deployment_signals (file existence checks)
    try:
        directory = getattr(result, "directory", "")
        dep: dict[str, Any] = {
            "has_dockerfile": False,
            "has_ci_config": False,
            "has_tests": False,
            "has_lockfile": False,
            "has_env_example": False,
        }
        if directory and os.path.isdir(directory):
            dep["has_dockerfile"] = os.path.exists(
                os.path.join(directory, "Dockerfile")
            )
            dep["has_ci_config"] = any(
                os.path.exists(os.path.join(directory, p))
                for p in [".github", ".gitlab-ci.yml", ".circleci", "Jenkinsfile"]
            )
            dep["has_tests"] = any(
                os.path.exists(os.path.join(directory, p))
                for p in ["tests", "test", "pytest.ini", "tox.ini"]
            )
            dep["has_lockfile"] = any(
                os.path.exists(os.path.join(directory, p))
                for p in ["poetry.lock", "Pipfile.lock", "uv.lock",
                          "requirements.txt", "package-lock.json"]
            )
            dep["has_env_example"] = any(
                os.path.exists(os.path.join(directory, p))
                for p in [".env.example", ".env.template", ".env.sample"]
            )
        dep["deployment_score"] = sum(
            1 for k, v in dep.items() if k != "deployment_score" and v is True
        )
        ping["deployment_signals"] = dep
    except Exception:
        ping.setdefault("deployment_signals", {
            "has_dockerfile": False, "has_ci_config": False,
            "has_tests": False, "has_lockfile": False,
            "has_env_example": False, "deployment_score": 0,
        })

    # G5: repo_metadata
    try:
        ping["repo_metadata"] = {
            "python_file_count": ping.get("files_scanned", 0),
            "yaml_config_count": 0,  # placeholder
            "total_loc": getattr(result, "total_loc", 0),
            "primary_framework": frameworks[0] if frameworks else None,
            "framework_count": len(frameworks),
        }
    except Exception:
        ping.setdefault("repo_metadata", {
            "python_file_count": 0, "yaml_config_count": 0,
            "total_loc": 0, "primary_framework": None, "framework_count": 0,
        })

    # G6: inter_crew_edges (default 0 — requires graph cross-crew analysis)
    ping["inter_crew_edges"] = 0

    # G7: graph_topology_metrics
    try:
        metrics: dict[str, Any] = {
            "diameter": 0,
            "avg_degree": 0.0,
            "max_degree": 0,
            "clustering_coefficient": 0.0,
            "connected_components": 1,
            "longest_chain": 0,
            "hub_score": 0,
        }
        if scan_profile is not None:
            metrics["avg_degree"] = round(
                _g(scan_profile, "avg_node_degree", 0.0), 2
            )
            metrics["max_degree"] = _g(scan_profile, "max_node_degree", 0)
            metrics["longest_chain"] = _g(scan_profile, "max_chain_depth", 0)
            metrics["hub_score"] = _g(scan_profile, "max_node_degree", 0)

        # Compute diameter from graph via BFS
        graph = getattr(result, "graph", None)
        if graph is not None and graph.edges:
            metrics["diameter"] = _compute_diameter(graph)
        ping["graph_topology_metrics"] = metrics
    except Exception:
        ping.setdefault("graph_topology_metrics", {
            "diameter": 0, "avg_degree": 0.0, "max_degree": 0,
            "clustering_coefficient": 0.0, "connected_components": 1,
            "longest_chain": 0, "hub_score": 0,
        })

    # G8: fix_impact_estimates (severity-based approximation, all negative ints)
    try:
        fix_impact: dict[str, int] = {}
        for fid, f in unique_rules.items():
            sev = _finding_severity(f)
            fix_impact[fid] = _SEVERITY_WEIGHT.get(sev, -1)
        ping["fix_impact_estimates"] = fix_impact
    except Exception:
        ping.setdefault("fix_impact_estimates", {})

    # G9: finding_co_occurrence (pairs of rules co-occurring in same crew)
    try:
        co_occ: list[list[str]] = []
        if crews:
            for crew in crews:
                cname = _get_attr_or_key(crew, "name", "")
                crew_rules = sorted(set(
                    _finding_id(f) for f in all_findings
                    if _get_attr_or_key(f, "crew_id", "") == cname
                ))
                for i, a in enumerate(crew_rules):
                    for b in crew_rules[i + 1:]:
                        pair = [a, b]
                        if pair not in co_occ:
                            co_occ.append(pair)
        ping["finding_co_occurrence"] = co_occ
    except Exception:
        ping.setdefault("finding_co_occurrence", [])

    # G10: per_crew_finding_density
    try:
        if crews:
            counts_per_crew = []
            for crew in crews:
                cname = _get_attr_or_key(crew, "name", "")
                ct = sum(
                    1 for f in all_findings
                    if _get_attr_or_key(f, "crew_id", "") == cname
                )
                counts_per_crew.append(ct)
            if counts_per_crew:
                ping["per_crew_finding_density"] = {
                    "max": max(counts_per_crew),
                    "min": min(counts_per_crew),
                    "mean": round(statistics.mean(counts_per_crew), 1),
                    "median": round(statistics.median(counts_per_crew), 1),
                    "stddev": round(
                        statistics.stdev(counts_per_crew), 1
                    ) if len(counts_per_crew) > 1 else 0.0,
                }
            else:
                ping["per_crew_finding_density"] = _default_density()
        else:
            ping["per_crew_finding_density"] = _default_density()
    except Exception:
        ping.setdefault("per_crew_finding_density", _default_density())

    # ── H) RESCAN FIELDS ─────────────────────────────────────────────
    try:
        diff = getattr(result, "diff", None)
        if diff is not None:
            ping["is_rescan"] = True
            ping["prev_score"] = getattr(diff, "previous_risk_score", 0)
            ping["score_delta"] = getattr(diff, "risk_score_delta", 0)
            ping["resolved_count"] = len(
                getattr(diff, "resolved_finding_ids", [])
            )
            ping["new_count"] = len(getattr(diff, "new_finding_ids", []))
            ping["pre_scan_id"] = ""  # not tracked in ScanDiff
        # is_rescan omitted on initial scans (per schema note)
    except Exception:
        pass

    return ping


def _compute_diameter(graph) -> int:
    """Compute the diameter of the largest connected component via BFS.

    Treats the graph as undirected for diameter calculation.
    Returns 0 only if the graph has no edges.
    """
    # Build undirected adjacency list
    adj: dict[str, set[str]] = {}
    for edge in graph.edges:
        adj.setdefault(edge.source, set()).add(edge.target)
        adj.setdefault(edge.target, set()).add(edge.source)

    if not adj:
        return 0

    all_nodes = set(adj.keys())

    def _bfs_eccentricity(start: str) -> int:
        visited = {start}
        queue = [(start, 0)]
        max_dist = 0
        while queue:
            node, dist = queue.pop(0)
            max_dist = max(max_dist, dist)
            for neighbor in adj.get(node, set()):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, dist + 1))
        return max_dist

    # Find connected components, compute diameter of the largest
    visited_global: set[str] = set()
    max_diameter = 0
    for start in all_nodes:
        if start in visited_global:
            continue
        # BFS to find component
        component = set()
        queue = [start]
        while queue:
            node = queue.pop(0)
            if node in component:
                continue
            component.add(node)
            for neighbor in adj.get(node, set()):
                if neighbor not in component:
                    queue.append(neighbor)
        visited_global.update(component)

        # Compute diameter of this component (max eccentricity)
        # For efficiency, sample up to 20 nodes
        sample = list(component)[:20]
        comp_diameter = max(_bfs_eccentricity(n) for n in sample)
        max_diameter = max(max_diameter, comp_diameter)

    return max_diameter


# ── Helpers ───────────────────────────────────────────────────────────────


def _finding_id(f) -> str:
    """Extract finding rule ID from a Finding object or dict."""
    if hasattr(f, "id"):
        return f.id
    if isinstance(f, dict):
        return f.get("id", "")
    return ""


def _finding_severity(f) -> str:
    """Extract severity string from a Finding object or dict."""
    if hasattr(f, "severity"):
        sev = f.severity
        return sev.value if hasattr(sev, "value") else str(sev)
    if isinstance(f, dict):
        return f.get("severity", "LOW")
    return "LOW"


def _finding_confidence(f) -> str:
    """Extract confidence string from a Finding object or dict."""
    if hasattr(f, "confidence"):
        conf = f.confidence
        return conf.value if hasattr(conf, "value") else str(conf)
    if isinstance(f, dict):
        return f.get("confidence", "heuristic")
    return "heuristic"


def _get_attr_or_key(obj, name: str, default=None):
    """Get attribute from dataclass or key from dict."""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _default_density() -> dict:
    """Default per_crew_finding_density."""
    return {"max": 0, "min": 0, "mean": 0.0, "median": 0, "stddev": 0.0}
