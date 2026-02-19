#!/usr/bin/env python
"""REAL end-to-end test: runs actual stratum scan CLI against real repos.

NO MOCKS. Tests that --repo-name and --repo-url propagate into JSON output
using repos already cloned in batch-repos/ and test directories.
"""

import json
import os
import subprocess
import sys
import tempfile

# Workspace root (parent of stratum-cli/)
WORKSPACE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
STRATUM_CLI_DIR = os.path.join(WORKSPACE, "stratum-cli")

# Real repos to scan — these are already cloned in the workspace
REAL_REPOS = [
    {
        "path": os.path.join(WORKSPACE, "batch-repos", "alexfazio-viral-clips-crew"),
        "repo_full_name": "alexfazio/viral-clips-crew",
        "repo_url": "https://github.com/alexfazio/viral-clips-crew.git",
        "expected_frameworks": ["CrewAI"],
    },
    {
        "path": os.path.join(WORKSPACE, "batch-repos", "langchain-ai-streamlit-agent"),
        "repo_full_name": "langchain-ai/streamlit-agent",
        "repo_url": "https://github.com/langchain-ai/streamlit-agent.git",
        "expected_frameworks": ["LangChain"],
    },
    {
        "path": os.path.join(WORKSPACE, "batch-repos", "lightninglabs-LangChainBitcoin"),
        "repo_full_name": "lightninglabs/LangChainBitcoin",
        "repo_url": "https://github.com/lightninglabs/LangChainBitcoin.git",
        "expected_frameworks": ["LangChain"],
    },
    {
        "path": os.path.join(WORKSPACE, "batch-repos", "bytedance-deer-flow"),
        "repo_full_name": "bytedance/deer-flow",
        "repo_url": "https://github.com/bytedance/deer-flow.git",
        "expected_frameworks": [],  # may or may not detect frameworks
    },
    {
        "path": os.path.join(WORKSPACE, "crewAI-examples"),
        "repo_full_name": "crewAIInc/crewAI-examples",
        "repo_url": "https://github.com/crewAIInc/crewAI-examples.git",
        "expected_frameworks": ["CrewAI"],
    },
]


def run_stratum_scan(path, repo_name=None, repo_url=None, timeout=120):
    """Run stratum scan --json on a real directory. Returns (returncode, parsed_json_or_None, stderr)."""
    cmd = ["stratum", "scan", path, "--json", "--no-telemetry", "--offline"]
    if repo_name:
        cmd.extend(["--repo-name", repo_name])
    if repo_url:
        cmd.extend(["--repo-url", repo_url])

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=STRATUM_CLI_DIR,
    )

    parsed = None
    if result.stdout.strip():
        try:
            parsed = json.loads(result.stdout.strip())
        except json.JSONDecodeError:
            pass

    return result.returncode, parsed, result.stderr


class TestResults:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []

    def check(self, condition, msg):
        if condition:
            self.passed += 1
            print(f"  PASS: {msg}")
        else:
            self.failed += 1
            self.errors.append(msg)
            print(f"  FAIL: {msg}")


def main():
    results = TestResults()

    print("=" * 70)
    print("REAL END-TO-END IDENTITY TEST — NO MOCKS")
    print("=" * 70)

    # ── Test 1-5: Scan real repos with --repo-name and --repo-url ────

    for i, repo in enumerate(REAL_REPOS):
        path = repo["path"]
        name = repo["repo_full_name"]
        url = repo["repo_url"]

        print(f"\n--- Test {i+1}: {name} ---")

        if not os.path.isdir(path):
            print(f"  SKIP: Directory not found: {path}")
            continue

        try:
            returncode, ping, stderr = run_stratum_scan(path, repo_name=name, repo_url=url)
        except subprocess.TimeoutExpired:
            results.check(False, f"{name}: scan timed out")
            continue

        if returncode != 0 and ping is None:
            results.check(False, f"{name}: scan returned exit code {returncode}, stderr: {stderr[:200]}")
            continue

        # Core assertion: repo_full_name is present and matches
        results.check(
            ping.get("repo_full_name") == name,
            f"{name}: repo_full_name == '{ping.get('repo_full_name')}' (expected '{name}')"
        )

        # Core assertion: repo_url is present and matches
        results.check(
            ping.get("repo_url") == url,
            f"{name}: repo_url == '{ping.get('repo_url')}' (expected '{url}')"
        )

        # Verify scan data is valid (not corrupted by identity injection)
        results.check(
            ping.get("scan_id") and len(ping.get("scan_id", "")) > 0,
            f"{name}: scan_id present"
        )
        results.check(
            ping.get("schema_id") == 5,
            f"{name}: schema_id == 5"
        )
        results.check(
            isinstance(ping.get("risk_score"), (int, float)),
            f"{name}: risk_score is numeric ({ping.get('risk_score')})"
        )
        results.check(
            isinstance(ping.get("frameworks"), list),
            f"{name}: frameworks is a list ({ping.get('frameworks')})"
        )
        results.check(
            isinstance(ping.get("finding_rule_count"), int),
            f"{name}: finding_rule_count is int ({ping.get('finding_rule_count')})"
        )

    # ── Test 6: Scan WITHOUT --repo-name/--repo-url (baseline) ───────

    print(f"\n--- Test 6: Scan without identity flags (baseline) ---")
    baseline_path = REAL_REPOS[0]["path"]
    if os.path.isdir(baseline_path):
        try:
            returncode, ping, stderr = run_stratum_scan(baseline_path)
            results.check(
                "repo_full_name" not in ping or not ping.get("repo_full_name"),
                f"baseline: repo_full_name absent or empty when no flag passed (got '{ping.get('repo_full_name')}')"
            )
            results.check(
                "repo_url" not in ping or not ping.get("repo_url"),
                f"baseline: repo_url absent or empty when no flag passed (got '{ping.get('repo_url')}')"
            )
            results.check(
                isinstance(ping.get("risk_score"), (int, float)),
                f"baseline: scan still produces valid risk_score without identity flags"
            )
        except subprocess.TimeoutExpired:
            results.check(False, "baseline: scan timed out")
    else:
        print(f"  SKIP: {baseline_path} not found")

    # ── Test 7: Scan nonexistent path with --repo-name (failure case) ─

    print(f"\n--- Test 7: Nonexistent path with --repo-name (failure case) ---")
    fake_path = os.path.join(tempfile.gettempdir(), "stratum-nonexistent-test-dir-xyz")
    # stratum scan requires path to exist (click.Path(exists=True)), so this should fail
    try:
        cmd = [
            "stratum", "scan", fake_path, "--json", "--no-telemetry",
            "--repo-name", "test/nonexistent-repo",
            "--repo-url", "https://github.com/test/nonexistent-repo",
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=STRATUM_CLI_DIR,
        )
        # Click should reject the nonexistent path with exit code 2
        results.check(
            result.returncode != 0,
            f"nonexistent path: scan fails (exit code {result.returncode})"
        )
        results.check(
            "does not exist" in result.stderr.lower() or "invalid" in result.stderr.lower() or "error" in result.stderr.lower() or "no such" in result.stderr.lower() or "usage" in result.stderr.lower(),
            f"nonexistent path: error message mentions path issue"
        )
    except subprocess.TimeoutExpired:
        results.check(False, "nonexistent path: timed out")

    # ── Test 8: Scan with ONLY --repo-name (no --repo-url) ───────────

    print(f"\n--- Test 8: Only --repo-name, no --repo-url ---")
    partial_path = REAL_REPOS[0]["path"]
    if os.path.isdir(partial_path):
        try:
            returncode, ping, stderr = run_stratum_scan(
                partial_path, repo_name="alexfazio/viral-clips-crew"
            )
            results.check(
                ping.get("repo_full_name") == "alexfazio/viral-clips-crew",
                f"partial: repo_full_name present when only --repo-name passed"
            )
            results.check(
                "repo_url" not in ping or not ping.get("repo_url"),
                f"partial: repo_url absent when --repo-url not passed (got '{ping.get('repo_url')}')"
            )
        except subprocess.TimeoutExpired:
            results.check(False, "partial: timed out")
    else:
        print(f"  SKIP: {partial_path} not found")

    # ── Summary ──────────────────────────────────────────────────────

    print(f"\n{'=' * 70}")
    print(f"RESULTS: {results.passed} passed, {results.failed} failed")
    print(f"{'=' * 70}")
    if results.errors:
        print(f"\nFailed checks:")
        for e in results.errors:
            print(f"  - {e}")
        sys.exit(1)
    else:
        print("\nAll checks passed.")
        sys.exit(0)


if __name__ == "__main__":
    main()
