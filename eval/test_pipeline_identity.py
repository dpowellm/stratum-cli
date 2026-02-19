"""Tests for the repo identity propagation fix in the scan pipeline.

Verifies that:
1. build_v72_ping includes repo_full_name/repo_url when passed
2. failure_ping includes repo_full_name AND repo_url
3. validate_ping warns (but doesn't reject) when repo_full_name is empty
4. scan_runner._run_scan enriches output with identity from manifest
"""

import json
import os
import sys
import warnings

# Ensure pipeline/ is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))


# ── build_v72_ping identity tests ──────────────────────────────────────────


def _make_stub_result():
    """Create a minimal stub that build_v72_ping can consume."""
    from types import SimpleNamespace

    return SimpleNamespace(
        scan_id="test-001",
        timestamp="2026-01-01T00:00:00Z",
        files_scanned=5,
        top_paths=[],
        signals=[],
        crew_definitions=[],
        agent_definitions=[],
        detected_frameworks=["LangChain"],
        total_capabilities=0,
        guardrail_count=0,
        has_any_guardrails=False,
        mcp_server_count=0,
        risk_score=42,
        has_shared_context=False,
        has_learning_loop=False,
        learning_type=None,
        has_eval_conflict=False,
        checkpoint_type="none",
        env_vars=[],
        telemetry_destinations=[],
        directory="",
        diff=None,
        graph=None,
        llm_models=[],
    )


def test_build_v72_ping_includes_repo_identity():
    """build_v72_ping should include repo_full_name and repo_url when passed."""
    from stratum.telemetry.ping import build_v72_ping

    result = _make_stub_result()
    ping = build_v72_ping(
        result,
        repo_full_name="langchain-ai/langchain",
        repo_url="https://github.com/langchain-ai/langchain",
    )

    assert ping["repo_full_name"] == "langchain-ai/langchain"
    assert ping["repo_url"] == "https://github.com/langchain-ai/langchain"


def test_build_v72_ping_omits_identity_when_not_passed():
    """build_v72_ping should not include repo_full_name/repo_url when not passed."""
    from stratum.telemetry.ping import build_v72_ping

    result = _make_stub_result()
    ping = build_v72_ping(result)

    assert "repo_full_name" not in ping
    assert "repo_url" not in ping


def test_build_v72_ping_includes_only_name_when_url_not_passed():
    """build_v72_ping with only repo_full_name should include name but not url."""
    from stratum.telemetry.ping import build_v72_ping

    result = _make_stub_result()
    ping = build_v72_ping(result, repo_full_name="owner/repo")

    assert ping["repo_full_name"] == "owner/repo"
    assert "repo_url" not in ping


# ── failure_ping identity tests ────────────────────────────────────────────


def test_failure_ping_includes_repo_url():
    """failure_ping should include repo_url from the repo_record."""
    from validation import failure_ping

    record = {
        "repo_full_name": "owner/repo",
        "repo_url": "https://github.com/owner/repo",
        "selection_stratum": "crewai",
    }
    ping = failure_ping(record, "clone_timeout")

    assert ping["repo_full_name"] == "owner/repo"
    assert ping["repo_url"] == "https://github.com/owner/repo"
    assert ping["selection_stratum"] == "crewai"
    assert ping["scan_status"] == "failed"
    assert ping["failure_reason"] == "clone_timeout"


def test_failure_ping_handles_missing_url():
    """failure_ping should return None for repo_url when not in record."""
    from validation import failure_ping

    record = {"repo_full_name": "owner/repo"}
    ping = failure_ping(record, "clone_error")

    assert ping["repo_full_name"] == "owner/repo"
    assert ping["repo_url"] is None


# ── validate_ping identity warning tests ───────────────────────────────────


def test_validate_ping_warns_on_empty_repo_full_name():
    """validate_ping should emit a warning when repo_full_name is empty."""
    from validation import validate_ping

    ping = {
        "scan_status": "success",
        "schema_id": 5,
        "schema_version": "0.3.2",
        "scanner_version": "0.3.1",
        "finding_rule_count": 0,
        "finding_severities": {},
        "finding_instance_counts": {},
        "total_finding_instances": 0,
        "crew_count": 0,
        "crew_size_distribution": [],
        "agent_count": 0,
        "agent_tool_count_distribution": [],
        "frameworks": [],
        "framework_versions": {},
        "deployment_signals": {"deployment_score": 0},
        "inter_crew_edges": 0,
        "graph_edge_count": 0,
        "fix_impact_estimates": {},
        "repo_full_name": "",  # empty!
    }

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        errors = validate_ping(ping)
        # Should NOT be an error (warn only, don't reject)
        assert not any("repo_full_name" in e for e in errors)
        # Should have emitted a warning
        assert any("repo_full_name" in str(warning.message) for warning in w)


def test_validate_ping_no_warning_when_repo_full_name_present():
    """validate_ping should not warn when repo_full_name is present."""
    from validation import validate_ping

    ping = {
        "scan_status": "success",
        "schema_id": 5,
        "schema_version": "0.3.2",
        "scanner_version": "0.3.1",
        "finding_rule_count": 0,
        "finding_severities": {},
        "finding_instance_counts": {},
        "total_finding_instances": 0,
        "crew_count": 0,
        "crew_size_distribution": [],
        "agent_count": 0,
        "agent_tool_count_distribution": [],
        "frameworks": [],
        "framework_versions": {},
        "deployment_signals": {"deployment_score": 0},
        "inter_crew_edges": 0,
        "graph_edge_count": 0,
        "fix_impact_estimates": {},
        "repo_full_name": "owner/repo",
    }

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        errors = validate_ping(ping)
        assert not any("repo_full_name" in str(warning.message) for warning in w)


# ── scan_runner enrichment tests ───────────────────────────────────────────


def test_scan_runner_builds_identity_flags():
    """_run_scan should include --repo-name and --repo-url in the subprocess command."""
    import unittest.mock as mock
    from scan_runner import _run_scan

    repo_record = {
        "repo_full_name": "crewAIInc/crewAI",
        "repo_url": "https://github.com/crewAIInc/crewAI.git",
        "selection_stratum": "crewai",
    }

    fake_ping = {
        "scan_id": "abc",
        "scan_status": "success",
        "risk_score": 42,
    }

    fake_result = mock.Mock()
    fake_result.returncode = 0
    fake_result.stdout = json.dumps(fake_ping)
    fake_result.stderr = ""

    with mock.patch("subprocess.run", return_value=fake_result) as mock_run:
        result = _run_scan(repo_record, "/tmp/fake-clone")

    # Verify the subprocess command included identity flags
    call_args = mock_run.call_args
    cmd = call_args[0][0]
    assert "--repo-name" in cmd
    assert "crewAIInc/crewAI" in cmd
    assert "--repo-url" in cmd
    assert "https://github.com/crewAIInc/crewAI.git" in cmd

    # Verify belt-and-suspenders enrichment
    assert result["repo_full_name"] == "crewAIInc/crewAI"
    assert result["repo_url"] == "https://github.com/crewAIInc/crewAI.git"
    assert result["selection_stratum"] == "crewai"


def test_scan_runner_backfills_missing_identity():
    """_run_scan should backfill identity even if scanner didn't include it."""
    import unittest.mock as mock
    from scan_runner import _run_scan

    repo_record = {
        "repo_full_name": "microsoft/autogen",
        "repo_url": "https://github.com/microsoft/autogen.git",
        "selection_stratum": "autogen",
    }

    # Scanner output without identity fields (the old bug scenario)
    scanner_output = {
        "scan_id": "xyz",
        "scan_status": "success",
        "risk_score": 55,
    }

    fake_result = mock.Mock()
    fake_result.returncode = 0
    fake_result.stdout = json.dumps(scanner_output)
    fake_result.stderr = ""

    with mock.patch("subprocess.run", return_value=fake_result):
        result = _run_scan(repo_record, "/tmp/fake-clone")

    assert result["repo_full_name"] == "microsoft/autogen"
    assert result["repo_url"] == "https://github.com/microsoft/autogen.git"
    assert result["selection_stratum"] == "autogen"


# ── CLI flag tests ─────────────────────────────────────────────────────────


def test_cli_scan_cmd_accepts_repo_name_and_url():
    """The scan CLI command should accept --repo-name and --repo-url flags."""
    from click.testing import CliRunner
    from stratum.cli import scan_cmd

    runner = CliRunner()
    # Invoke with --help to verify the flags are registered
    result = runner.invoke(scan_cmd, ["--help"])
    assert result.exit_code == 0
    assert "--repo-name" in result.output
    assert "--repo-url" in result.output
