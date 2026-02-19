"""Tests for pipeline/repair_scan_results.py identity recovery."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

from repair_scan_results import repair_scan_results, compute_manifest_hash


def _make_manifest(entries):
    """Write manifest entries to a temp JSONL file."""
    path = tempfile.mktemp(suffix=".jsonl")
    with open(path, "w") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")
    return path


def _make_scan_results(rows):
    """Write scan result rows to a temp JSONL file."""
    path = tempfile.mktemp(suffix=".jsonl")
    with open(path, "w") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
    return path


def test_repair_backfills_repo_url():
    """Rows with repo_full_name but no repo_url should get URL backfilled."""
    manifest = [
        {
            "repo_full_name": "owner/repo-a",
            "repo_url": "https://github.com/owner/repo-a",
            "selection_stratum": "crewai",
        },
    ]
    results = [
        {
            "scan_id": "aaa",
            "scan_status": "success",
            "risk_score": 42,
            "finding_rule_count": 3,
            "frameworks": ["CrewAI"],
            "agent_count": 1,
            "crew_count": 1,
            "repo_full_name": "owner/repo-a",
            "selection_stratum": "crewai",
            # repo_url is MISSING — this is the bug
        },
    ]

    manifest_path = _make_manifest(manifest)
    results_path = _make_scan_results(results)
    output_path = tempfile.mktemp(suffix=".jsonl")

    try:
        stats = repair_scan_results(results_path, manifest_path, output_path)

        assert stats["url_repaired"] == 1

        with open(output_path) as f:
            repaired = [json.loads(line) for line in f if line.strip()]

        assert repaired[0]["repo_url"] == "https://github.com/owner/repo-a"
        assert repaired[0]["risk_score"] == 42  # data unchanged
    finally:
        for p in (manifest_path, results_path, output_path):
            if os.path.exists(p):
                os.unlink(p)


def test_repair_hash_matching():
    """Rows with repo_hash matching SHA-256(full_name)[:16] should get identity."""
    name = "langchain-ai/langchain"
    expected_hash = compute_manifest_hash(name)

    manifest = [
        {
            "repo_full_name": name,
            "repo_url": "https://github.com/langchain-ai/langchain",
            "selection_stratum": "langchain_active",
        },
    ]
    results = [
        {
            "scan_id": "bbb",
            "scan_status": "success",
            "risk_score": 55,
            "finding_rule_count": 5,
            "frameworks": ["LangChain"],
            "agent_count": 2,
            "crew_count": 1,
            "repo_hash": expected_hash,
            # repo_full_name is MISSING
        },
    ]

    manifest_path = _make_manifest(manifest)
    results_path = _make_scan_results(results)
    output_path = tempfile.mktemp(suffix=".jsonl")

    try:
        stats = repair_scan_results(results_path, manifest_path, output_path)

        assert stats["hash_repaired"] == 1

        with open(output_path) as f:
            repaired = [json.loads(line) for line in f if line.strip()]

        assert repaired[0]["repo_full_name"] == name
        assert repaired[0]["repo_url"] == "https://github.com/langchain-ai/langchain"
        assert repaired[0]["risk_score"] == 55  # data unchanged
    finally:
        for p in (manifest_path, results_path, output_path):
            if os.path.exists(p):
                os.unlink(p)


def test_repair_anonymous_fallback():
    """Rows with no hash and no name should be marked anonymous."""
    manifest = [
        {
            "repo_full_name": "some/repo",
            "repo_url": "https://github.com/some/repo",
            "selection_stratum": "crewai",
        },
    ]
    results = [
        {
            "scan_id": "ccc",
            "scan_status": "success",
            "risk_score": 30,
            "finding_rule_count": 2,
            "frameworks": ["LangGraph"],
            "agent_count": 1,
            "crew_count": 0,
            # NO repo_hash, NO repo_full_name
            "selection_stratum": "langgraph",  # Different stratum, so order alignment fails
        },
    ]

    manifest_path = _make_manifest(manifest)
    results_path = _make_scan_results(results)
    output_path = tempfile.mktemp(suffix=".jsonl")

    try:
        stats = repair_scan_results(results_path, manifest_path, output_path)

        assert stats["anonymous"] == 1

        with open(output_path) as f:
            repaired = [json.loads(line) for line in f if line.strip()]

        assert repaired[0].get("_anonymous") is True
        assert repaired[0]["risk_score"] == 30  # data unchanged
    finally:
        for p in (manifest_path, results_path, output_path):
            if os.path.exists(p):
                os.unlink(p)


def test_repair_no_data_corruption():
    """Repair should never modify core scan data fields."""
    manifest = [
        {
            "repo_full_name": "test/repo",
            "repo_url": "https://github.com/test/repo",
            "selection_stratum": "autogen",
        },
    ]
    results = [
        {
            "scan_id": "ddd",
            "scan_status": "success",
            "risk_score": 77,
            "finding_rule_count": 8,
            "frameworks": ["AutoGen", "LangChain"],
            "agent_count": 5,
            "crew_count": 2,
            "repo_full_name": "test/repo",
            "selection_stratum": "autogen",
        },
    ]

    manifest_path = _make_manifest(manifest)
    results_path = _make_scan_results(results)
    output_path = tempfile.mktemp(suffix=".jsonl")

    try:
        repair_scan_results(results_path, manifest_path, output_path)

        with open(output_path) as f:
            repaired = [json.loads(line) for line in f if line.strip()]

        row = repaired[0]
        assert row["scan_id"] == "ddd"
        assert row["risk_score"] == 77
        assert row["finding_rule_count"] == 8
        assert row["frameworks"] == ["AutoGen", "LangChain"]
        assert row["agent_count"] == 5
        assert row["crew_count"] == 2
    finally:
        for p in (manifest_path, results_path, output_path):
            if os.path.exists(p):
                os.unlink(p)


def test_repair_mixed_scenario():
    """Mix of already-identified, hash-matchable, and anonymous rows."""
    manifest = [
        {
            "repo_full_name": "org/repo-1",
            "repo_url": "https://github.com/org/repo-1",
            "selection_stratum": "crewai",
        },
        {
            "repo_full_name": "org/repo-2",
            "repo_url": "https://github.com/org/repo-2",
            "selection_stratum": "langchain_active",
        },
    ]

    hash_for_repo2 = compute_manifest_hash("org/repo-2")

    results = [
        # Row 0: Already identified
        {
            "scan_id": "r1",
            "scan_status": "success",
            "risk_score": 10,
            "finding_rule_count": 1,
            "frameworks": ["CrewAI"],
            "agent_count": 1,
            "crew_count": 1,
            "repo_full_name": "org/repo-1",
            "selection_stratum": "crewai",
        },
        # Row 1: Has hash matching repo-2
        {
            "scan_id": "r2",
            "scan_status": "success",
            "risk_score": 20,
            "finding_rule_count": 2,
            "frameworks": ["LangChain"],
            "agent_count": 2,
            "crew_count": 1,
            "repo_hash": hash_for_repo2,
            "selection_stratum": "langchain_active",
        },
        # Row 2: Completely anonymous
        {
            "scan_id": "r3",
            "scan_status": "success",
            "risk_score": 30,
            "finding_rule_count": 3,
            "frameworks": ["LangGraph"],
            "agent_count": 3,
            "crew_count": 0,
        },
    ]

    manifest_path = _make_manifest(manifest)
    results_path = _make_scan_results(results)
    output_path = tempfile.mktemp(suffix=".jsonl")

    try:
        stats = repair_scan_results(results_path, manifest_path, output_path)

        assert stats["pre_identified"] == 1
        assert stats["post_identified"] == 2  # repo-1 + repo-2
        assert stats["hash_repaired"] == 1
        assert stats["anonymous"] == 1

        with open(output_path) as f:
            repaired = [json.loads(line) for line in f if line.strip()]

        # Row 0: already had identity
        assert repaired[0]["repo_full_name"] == "org/repo-1"
        # Row 1: repaired via hash
        assert repaired[1]["repo_full_name"] == "org/repo-2"
        assert repaired[1]["repo_url"] == "https://github.com/org/repo-2"
        # Row 2: anonymous
        assert repaired[2].get("_anonymous") is True
    finally:
        for p in (manifest_path, results_path, output_path):
            if os.path.exists(p):
                os.unlink(p)
