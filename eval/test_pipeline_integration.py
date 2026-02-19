"""Integration test for the scan pipeline identity propagation.

Verifies the full flow: manifest entry → scan_single_repo → output JSONL
with non-empty repo_full_name and repo_url in every row.

Uses mock subprocess to avoid needing real git clones or stratum installs.
"""

import json
import os
import sys
import tempfile
import unittest.mock as mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

from scan_runner import scan_single_repo, run_scan_pipeline, load_manifest


# Realistic v7.2 ping output that the scanner would produce (without identity)
SCANNER_OUTPUT_TEMPLATE = {
    "scan_id": "test-{idx}",
    "timestamp": "2026-02-14T12:00:00+00:00",
    "scanner_version": "0.3.1",
    "repo_hash": "abc123def456{idx:04d}",
    "schema_id": 5,
    "schema_version": "0.3.2",
    "scan_status": "success",
    "scan_duration_ms": 250,
    "files_scanned": 10,
    "files_total": 10,
    "parser_errors": 0,
    "failure_reason": None,
    "archetype_class": "code_agent",
    "total_capabilities": 1,
    "capability_distribution": {"code_exec": 1},
    "trust_level_distribution": {"privileged": 1},
    "trust_crossings": {},
    "total_trust_crossings": 0,
    "topology_signature_hash": "abc123def456{idx:04d}",
    "trust_crossing_adjacency": {},
    "graph_node_count": 5,
    "graph_edge_count": 2,
    "graph_node_type_distribution": {"agent": 3, "guardrail": 2},
    "graph_edge_type_distribution": {"feeds_into": 2},
    "edge_density": 0.1,
    "guardrail_count": 2,
    "has_any_guardrails": True,
    "guardrail_types": ["validation"],
    "guardrail_linked_count": 0,
    "control_bypass_count": 0,
    "control_coverage_pct": 50.0,
    "has_hitl_anywhere": False,
    "mcp_server_count": 0,
    "mcp_remote_count": 0,
    "mcp_auth_ratio": 0.0,
    "mcp_pinned_ratio": 0.0,
    "risk_score": 35,
    "blast_radius_distribution": [],
    "max_blast_radius": 0,
    "has_env_in_gitignore": False,
    "error_handling_rate": 0.0,
    "timeout_rate": 0.0,
    "checkpoint_type": "none",
    "has_pii": False,
    "has_financial_data": False,
    "has_financial_tools": False,
    "financial_validation_rate": 0.0,
    "data_sensitivity_types": [],
    "has_shared_credentials": False,
    "mitigation_coverage": {},
    "uncontrolled_path_count": 0,
    "max_path_hops": 0,
    "downward_trust_crossings": 0,
    "external_sink_count": 0,
    "shared_tool_max_agents": 0,
    "incident_match_count": 0,
    "incident_ids": [],
    "regulatory_framework_count": 0,
    "regulatory_surface": [],
    "has_agent_identity": True,
    "has_shared_context": False,
    "has_context_provenance": True,
    "has_context_rollback": True,
    "has_memory_store": False,
    "memory_store_types": [],
    "has_learning_loop": False,
    "learning_type": None,
    "has_eval_framework": False,
    "has_eval_conflict": False,
    "has_observability": False,
    "frameworks": ["LangChain"],
    "agent_count": 3,
    "crew_count": 1,
    "finding_rules": ["STRATUM-003", "TELEMETRY-003"],
    "finding_rule_count": 2,
    "finding_severities": {"MEDIUM": 1, "LOW": 1},
    "finding_confidences": {"probable": 2},
    "finding_instance_counts": {"STRATUM-003": 1, "TELEMETRY-003": 1},
    "total_finding_instances": 2,
    "env_var_count": 0,
    "telemetry_destination_count": 0,
    "total_tool_count": 1,
    "crew_size_distribution": [3],
    "agent_tool_count_distribution": [1, 0, 0],
    "finding_coverages": {},
    "severity_downgrades": {},
    "crews_clean": 0,
    "crews_with_findings": 1,
    "findings_by_class": {"architecture": 1, "hygiene": 1},
    "findings_by_category": {"security": 1, "operational": 1},
    "normalized_features": {
        "findings_per_agent": 0.67,
        "findings_per_crew": 2.0,
        "guardrails_per_agent": 0.67,
        "tools_per_agent": 0.33,
        "external_exposure_ratio": 0.0,
        "guardrail_coverage_ratio": 0.5,
    },
    "framework_versions": {"LangChain": None},
    "llm_providers": [],
    "llm_models": [],
    "provider_confidence": "unknown",
    "deployment_signals": {
        "has_dockerfile": False,
        "has_ci_config": True,
        "has_tests": True,
        "has_lockfile": True,
        "has_env_example": False,
        "deployment_score": 3,
    },
    "repo_metadata": {
        "python_file_count": 10,
        "yaml_config_count": 0,
        "total_loc": 0,
        "primary_framework": "LangChain",
        "framework_count": 1,
    },
    "inter_crew_edges": 0,
    "graph_topology_metrics": {
        "diameter": 0,
        "avg_degree": 1.0,
        "max_degree": 2,
        "clustering_coefficient": 0.0,
        "connected_components": 1,
        "longest_chain": 2,
        "hub_score": 2,
    },
    "fix_impact_estimates": {"STRATUM-003": -8, "TELEMETRY-003": -3},
    "finding_co_occurrence": [],
    "per_crew_finding_density": {
        "max": 0,
        "min": 0,
        "mean": 0,
        "median": 0,
        "stddev": 0.0,
    },
}

MINI_MANIFEST = [
    {
        "repo_full_name": "langchain-ai/langchain",
        "repo_url": "https://github.com/langchain-ai/langchain",
        "clone_url": "https://github.com/langchain-ai/langchain.git",
        "selection_stratum": "langchain_active",
        "scan_status": "pending",
    },
    {
        "repo_full_name": "crewAIInc/crewAI",
        "repo_url": "https://github.com/crewAIInc/crewAI",
        "clone_url": "https://github.com/crewAIInc/crewAI.git",
        "selection_stratum": "crewai",
        "scan_status": "pending",
    },
    {
        "repo_full_name": "microsoft/autogen",
        "repo_url": "https://github.com/microsoft/autogen",
        "clone_url": "https://github.com/microsoft/autogen.git",
        "selection_stratum": "autogen",
        "scan_status": "pending",
    },
]


def _make_scanner_output(idx):
    """Generate a unique scanner output for a given repo index."""
    output = {}
    for k, v in SCANNER_OUTPUT_TEMPLATE.items():
        if isinstance(v, str) and "{idx" in v:
            output[k] = v.format(idx=idx)
        else:
            output[k] = v
    return output


def _mock_subprocess_run(cmd, **kwargs):
    """Mock subprocess.run that handles both git clone and stratum scan."""
    result = mock.Mock()

    if cmd[0] == "git":
        # git clone: succeed and create the directory
        dest = cmd[-1]
        os.makedirs(dest, exist_ok=True)
        result.returncode = 0
        result.stdout = ""
        result.stderr = ""
        return result

    if cmd[0] == "stratum":
        # stratum scan: return a realistic v7.2 ping
        # Determine which repo by looking at --repo-name flag
        repo_name = ""
        for i, arg in enumerate(cmd):
            if arg == "--repo-name" and i + 1 < len(cmd):
                repo_name = cmd[i + 1]
                break

        idx = 0
        for i, m in enumerate(MINI_MANIFEST):
            if m["repo_full_name"] == repo_name:
                idx = i
                break

        output = _make_scanner_output(idx)
        # Include identity in output (simulating the fixed scanner)
        if repo_name:
            output["repo_full_name"] = repo_name
        for i, arg in enumerate(cmd):
            if arg == "--repo-url" and i + 1 < len(cmd):
                output["repo_url"] = cmd[i + 1]
                break

        result.returncode = 0
        result.stdout = json.dumps(output)
        result.stderr = ""
        return result

    result.returncode = 1
    result.stdout = ""
    result.stderr = "Unknown command"
    return result


def test_full_pipeline_identity_propagation():
    """Full pipeline integration: manifest → scan → output JSONL with identity."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Write manifest
        manifest_path = os.path.join(tmpdir, "manifest.jsonl")
        with open(manifest_path, "w") as f:
            for entry in MINI_MANIFEST:
                f.write(json.dumps(entry) + "\n")

        results_path = os.path.join(tmpdir, "scan_results.jsonl")
        quarantine_path = os.path.join(tmpdir, "quarantine.jsonl")
        log_path = os.path.join(tmpdir, "pipeline_log.json")

        # Run pipeline with mocked subprocess
        with mock.patch("subprocess.run", side_effect=_mock_subprocess_run):
            with mock.patch("shutil.rmtree"):
                run_scan_pipeline(
                    manifest_path=manifest_path,
                    results_path=results_path,
                    quarantine_path=quarantine_path,
                    log_path=log_path,
                    workers=1,
                    limit=3,
                    resume=False,
                )

        # Read output
        results = []
        with open(results_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    results.append(json.loads(line))

        # Assertions
        assert len(results) == 3, f"Expected 3 results, got {len(results)}"

        manifest_names = {m["repo_full_name"] for m in MINI_MANIFEST}
        manifest_urls = {m["repo_url"] for m in MINI_MANIFEST}

        for i, result in enumerate(results):
            # Every row must have non-empty repo_full_name
            assert result.get("repo_full_name"), (
                f"Row {i}: repo_full_name is empty/missing: {result.get('repo_full_name')}"
            )

            # Every row must have non-empty repo_url
            assert result.get("repo_url"), (
                f"Row {i}: repo_url is empty/missing: {result.get('repo_url')}"
            )

            # repo_full_name must be from the manifest
            assert result["repo_full_name"] in manifest_names, (
                f"Row {i}: repo_full_name '{result['repo_full_name']}' not in manifest"
            )

            # repo_url must be from the manifest
            assert result["repo_url"] in manifest_urls, (
                f"Row {i}: repo_url '{result['repo_url']}' not in manifest"
            )

            # Scan data should still be valid
            assert result.get("risk_score") is not None, f"Row {i}: missing risk_score"
            assert result.get("scan_status") == "success", f"Row {i}: bad scan_status"
            assert result.get("finding_rule_count", 0) >= 0, f"Row {i}: bad finding_rule_count"
            assert result.get("selection_stratum"), f"Row {i}: missing selection_stratum"


def test_single_repo_identity_propagation():
    """scan_single_repo should produce a result with identity fields."""
    repo_record = MINI_MANIFEST[0].copy()

    with mock.patch("subprocess.run", side_effect=_mock_subprocess_run):
        with mock.patch("shutil.rmtree"):
            result = scan_single_repo(repo_record)

    assert result["repo_full_name"] == "langchain-ai/langchain"
    assert result["repo_url"] == "https://github.com/langchain-ai/langchain"
    assert result["selection_stratum"] == "langchain_active"
    assert result["risk_score"] == 35


def test_failed_clone_preserves_identity():
    """When clone fails, the failure ping should still have repo identity."""

    def failing_clone(cmd, **kwargs):
        result = mock.Mock()
        if cmd[0] == "git":
            result.returncode = 1
            result.stdout = ""
            result.stderr = "fatal: repository not found"
            return result
        result.returncode = 0
        result.stdout = "{}"
        result.stderr = ""
        return result

    repo_record = MINI_MANIFEST[1].copy()

    with mock.patch("subprocess.run", side_effect=failing_clone):
        with mock.patch("shutil.rmtree"):
            result = scan_single_repo(repo_record)

    assert result["scan_status"] == "failed"
    assert result["repo_full_name"] == "crewAIInc/crewAI"
    assert result["repo_url"] == "https://github.com/crewAIInc/crewAI"


def test_scanner_crash_preserves_identity():
    """When the scanner crashes, the failure ping should still have repo identity."""

    def scanner_crash(cmd, **kwargs):
        result = mock.Mock()
        if cmd[0] == "git":
            dest = cmd[-1]
            os.makedirs(dest, exist_ok=True)
            result.returncode = 0
            result.stdout = ""
            result.stderr = ""
            return result
        if cmd[0] == "stratum":
            result.returncode = 1
            result.stdout = ""
            result.stderr = "Traceback: some internal error"
            return result
        result.returncode = 1
        result.stdout = ""
        result.stderr = ""
        return result

    repo_record = MINI_MANIFEST[2].copy()

    with mock.patch("subprocess.run", side_effect=scanner_crash):
        with mock.patch("shutil.rmtree"):
            result = scan_single_repo(repo_record)

    assert result["scan_status"] == "failed"
    assert result["repo_full_name"] == "microsoft/autogen"
    assert result["repo_url"] == "https://github.com/microsoft/autogen"
