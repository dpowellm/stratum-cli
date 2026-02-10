"""Bulk scan open-source agent projects for aggregate analysis.

Usage:
    python scripts/bulk_scan.py repos.txt --output results/

Reads a list of GitHub repo URLs, clones each to a temp directory,
runs `stratum scan . --json`, and aggregates results.

Output:
    results/
    ├── individual/          # Per-repo JSON scan results (anonymized)
    ├── aggregate.json       # Aggregate statistics
    └── report.md            # Human-readable summary for blog post
"""

import json
import subprocess
import tempfile
import os
import sys
from pathlib import Path
from datetime import datetime


def clone_repo(url: str, dest: str) -> bool:
    """Shallow clone a repo. Returns True on success."""
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", url, dest],
            capture_output=True, timeout=60, check=True
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def scan_repo(path: str) -> dict | None:
    """Run stratum scan --json on a directory. Returns parsed JSON or None."""
    try:
        result = subprocess.run(
            ["stratum", "scan", path, "--json", "--no-telemetry"],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode in (0, 1, 2):  # 0=clean, 1=critical, 2=high
            return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        pass
    return None


def anonymize_result(result: dict, repo_index: int) -> dict:
    """Strip identifying info. Keep only aggregate-safe fields."""
    return {
        "index": repo_index,
        "risk_score": result.get("risk_score", 0),
        "total_capabilities": result.get("total_capabilities", 0),
        "outbound_count": result.get("outbound_count", 0),
        "data_access_count": result.get("data_access_count", 0),
        "code_exec_count": result.get("code_exec_count", 0),
        "destructive_count": result.get("destructive_count", 0),
        "financial_count": result.get("financial_count", 0),
        "mcp_server_count": result.get("mcp_server_count", 0),
        "guardrail_count": result.get("guardrail_count", 0),
        "has_any_guardrails": result.get("has_any_guardrails", False),
        "checkpoint_type": result.get("checkpoint_type", "none"),
        "finding_count": len(result.get("top_paths", [])) + len(result.get("signals", [])),
        "finding_severities": {},
        "finding_ids": [],
        # Learning & governance (from SPEC-PATCH-2)
        "has_learning_loop": result.get("has_learning_loop", False),
        "learning_type": result.get("learning_type"),
        "has_shared_context": result.get("has_shared_context", False),
        "telemetry_destinations": result.get("telemetry_destinations", []),
        "has_eval_conflict": result.get("has_eval_conflict", False),
    }


def aggregate_results(results: list[dict]) -> dict:
    """Compute aggregate statistics from anonymized results."""
    n = len(results)
    if n == 0:
        return {}

    return {
        "total_repos_scanned": n,
        "scan_date": datetime.utcnow().isoformat(),

        # Risk scores
        "avg_risk_score": sum(r["risk_score"] for r in results) / n,
        "median_risk_score": sorted(r["risk_score"] for r in results)[n // 2],
        "max_risk_score": max(r["risk_score"] for r in results),
        "pct_score_above_50": sum(1 for r in results if r["risk_score"] > 50) / n * 100,
        "pct_score_above_75": sum(1 for r in results if r["risk_score"] > 75) / n * 100,

        # Guardrails
        "pct_no_guardrails": sum(1 for r in results if not r["has_any_guardrails"]) / n * 100,

        # Capabilities
        "pct_with_code_exec": sum(1 for r in results if r["code_exec_count"] > 0) / n * 100,
        "pct_with_outbound": sum(1 for r in results if r["outbound_count"] > 0) / n * 100,
        "pct_with_data_access": sum(1 for r in results if r["data_access_count"] > 0) / n * 100,
        "pct_with_destructive": sum(1 for r in results if r["destructive_count"] > 0) / n * 100,
        "pct_with_financial": sum(1 for r in results if r["financial_count"] > 0) / n * 100,

        # MCP
        "pct_with_mcp": sum(1 for r in results if r["mcp_server_count"] > 0) / n * 100,
        "avg_mcp_servers": sum(r["mcp_server_count"] for r in results) / n,

        # Learning (SPEC-PATCH-2)
        "pct_with_learning_loop": sum(1 for r in results if r["has_learning_loop"]) / n * 100,
        "pct_with_shared_context": sum(1 for r in results if r["has_shared_context"]) / n * 100,

        # Findings
        "avg_finding_count": sum(r["finding_count"] for r in results) / n,
        "pct_with_critical": 0,  # compute from finding_severities
        "pct_with_zero_findings": sum(1 for r in results if r["finding_count"] == 0) / n * 100,
    }


def generate_report(aggregate: dict, results: list[dict]) -> str:
    """Generate human-readable markdown report for blog post."""
    n = aggregate["total_repos_scanned"]

    return f"""# AI Agent Security Audit: {n} Open-Source Projects Scanned

*Scanned on {aggregate['scan_date'][:10]} using [Stratum](https://github.com/stratum-systems/stratum-cli) v0.1*

## Key Findings

**{aggregate['pct_no_guardrails']:.0f}% of projects have zero guardrails.** No input filters, no output filters, no human-in-the-loop gates. The agent can do anything its tools allow, with no safety controls.

**Average risk score: {aggregate['avg_risk_score']:.0f}/100.** {aggregate['pct_score_above_75']:.0f}% scored above 75 (high risk). {aggregate['pct_score_above_50']:.0f}% scored above 50 (medium risk).

**{aggregate['pct_with_code_exec']:.0f}% include code execution capabilities.** Subprocess calls, exec(), eval() — reachable from agent tool functions.

**{aggregate['pct_with_outbound']:.0f}% have outbound network capabilities.** HTTP requests, email sending, messaging APIs — potential exfiltration paths when combined with data access.

## Methodology

Every project was scanned using `stratum scan . --json`. Stratum performs static analysis via AST parsing — it reads Python source files, MCP JSON configs, and .env files. No code is executed. No network calls are made during scanning. All findings are mapped to the [OWASP Top 10 for Agentic AI](https://genai.owasp.org).

Projects were selected from public GitHub repositories with the topics `ai-agent`, `langchain`, `crewai`, `autogen`, and `mcp`. Selection criteria: >10 stars, Python-based, contains agent or tool definitions.

Results are anonymized — no project names, no code snippets, no file paths. Individual results are not published.

## Distribution

| Risk Score | Count | Percentage |
|-----------|-------|------------|
| 0-25 (low) | - | - |
| 26-50 (medium) | - | - |
| 51-75 (high) | - | - |
| 76-100 (critical) | - | - |

*Fill in from results*

## Try It Yourself

```bash
pip install stratum-cli
stratum scan .
```

Stratum is open source and fully local. Your code never leaves your machine.

> [GitHub](https://github.com/stratum-systems/stratum-cli)
"""


def main():
    if len(sys.argv) < 2:
        print("Usage: python bulk_scan.py repos.txt [--output results/]")
        sys.exit(1)

    repos_file = sys.argv[1]
    output_dir = "results"
    if "--output" in sys.argv:
        output_dir = sys.argv[sys.argv.index("--output") + 1]

    os.makedirs(f"{output_dir}/individual", exist_ok=True)

    with open(repos_file) as f:
        repos = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print(f"Scanning {len(repos)} repositories...")

    results = []
    for i, repo_url in enumerate(repos):
        print(f"  [{i+1}/{len(repos)}] {repo_url}")

        with tempfile.TemporaryDirectory() as tmpdir:
            clone_path = os.path.join(tmpdir, "repo")

            if not clone_repo(repo_url, clone_path):
                print(f"    x Clone failed")
                continue

            scan_result = scan_repo(clone_path)
            if scan_result is None:
                print(f"    x Scan failed")
                continue

            anon = anonymize_result(scan_result, i)
            results.append(anon)

            # Save individual result
            with open(f"{output_dir}/individual/{i:03d}.json", "w") as out:
                json.dump(anon, out, indent=2)

            print(f"    ok Score: {anon['risk_score']}, Findings: {anon['finding_count']}")

    # Aggregate
    agg = aggregate_results(results)
    with open(f"{output_dir}/aggregate.json", "w") as f:
        json.dump(agg, f, indent=2)

    # Report
    report = generate_report(agg, results)
    with open(f"{output_dir}/report.md", "w") as f:
        f.write(report)

    print(f"\nDone. {len(results)}/{len(repos)} repos scanned successfully.")
    print(f"Results: {output_dir}/")


if __name__ == "__main__":
    main()
