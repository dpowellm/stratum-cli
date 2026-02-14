#!/usr/bin/env python
"""Generate synthetic scan_results.jsonl for testing the audit system.

Creates 200 pings with realistic distributions:
- 150 success, 20 failed, 15 empty, 15 partial
- Multiple frameworks, finding rules, deployment scores
- Some duplicate topology_signature_hash clusters
"""

import hashlib
import json
import os
import random
import sys

random.seed(42)

STRATA = [
    "langchain_active", "crewai", "langgraph", "autogen",
    "llamaindex", "agno_smolagents_other", "high_maturity", "discovery_pool",
]

FRAMEWORKS = ["LangChain", "CrewAI", "LangGraph", "AutoGen", "LlamaIndex", "Agno", "SmolAgents"]

FINDING_RULES = [
    "unrestricted-tool-access", "missing-input-validation", "hardcoded-api-key",
    "unbounded-context-window", "no-output-filtering", "insecure-deserialization",
    "prompt-injection-surface", "unrestricted-code-execution", "missing-rate-limit",
    "excessive-permissions", "no-audit-logging", "insecure-memory-storage",
    "unvalidated-tool-output", "missing-guardrails", "credential-in-environment",
    "unsafe-yaml-load", "sql-injection-surface", "path-traversal-risk",
    "no-timeout-on-llm-call", "over-privileged-agent",
]

FAILURE_REASONS = [
    "clone_timeout", "clone_error", "parse_crash",
    "parse_timeout", "invalid_json",
]

# Generate some topology hashes — some will be reused for duplicate clusters
TOPO_HASHES = [hashlib.sha256(f"topo-{i}".encode()).hexdigest()[:16] for i in range(50)]
# Create a cluster hash that will have 15+ members
CLUSTER_HASH_A = "aaaa1111bbbb2222"
CLUSTER_HASH_B = "cccc3333dddd4444"


def gen_scan_id():
    return hashlib.sha256(os.urandom(16)).hexdigest()[:8]


def gen_success_ping(idx, force_cluster_hash=None):
    stratum = random.choice(STRATA)
    num_frameworks = random.randint(1, 3)
    frameworks = random.sample(FRAMEWORKS, num_frameworks)
    fw_versions = {fw: f"{random.randint(0, 2)}.{random.randint(0, 9)}.{random.randint(0, 20)}" for fw in frameworks}

    num_rules = random.randint(2, 12)
    rules = random.sample(FINDING_RULES, min(num_rules, len(FINDING_RULES)))
    severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    instance_counts = {}
    fix_impacts = {}

    for rule in rules:
        sev = random.choice(["critical", "high", "medium", "low"])
        severities[sev] += 1
        instances = random.randint(1, 15)
        instance_counts[rule] = instances
        fix_impacts[rule] = -random.randint(1, 20)

    finding_rule_count = sum(severities.values())
    total_instances = sum(instance_counts.values())
    risk_score = random.randint(0, 100)
    agent_count = random.randint(1, 30)
    crew_count = random.randint(0, 5)
    files_total = random.randint(10, 200)
    files_scanned = int(files_total * random.uniform(0.6, 1.0))
    dep_score = random.randint(0, 5)

    dep_signals = {
        "has_dockerfile": random.random() < 0.4,
        "has_ci": random.random() < 0.3,
        "has_tests": random.random() < 0.5,
        "has_requirements": random.random() < 0.6,
        "has_readme": random.random() < 0.8,
    }
    # Make deployment_score match the count of true booleans
    true_count = sum(1 for v in dep_signals.values() if v is True)
    dep_signals["deployment_score"] = true_count

    # Override to also test specific deployment_score values
    if idx < 30:
        # Force high maturity for some
        for k in dep_signals:
            if k != "deployment_score":
                dep_signals[k] = True
        dep_signals["deployment_score"] = sum(1 for k, v in dep_signals.items() if k != "deployment_score" and v is True)

    topo_hash = force_cluster_hash or random.choice(TOPO_HASHES)

    edge_count = random.randint(0, 50)
    inter_crew = random.randint(0, min(edge_count, 10))

    return {
        "scan_id": gen_scan_id(),
        "timestamp": f"2026-02-14T{random.randint(0,23):02d}:{random.randint(0,59):02d}:00+00:00",
        "scanner_version": "0.3.1",
        "schema_id": 5,
        "schema_version": "0.3.2",
        "scan_status": "success",
        "scan_duration_ms": random.randint(500, 15000),
        "risk_score": risk_score,
        "repo_full_name": f"test-org/repo-{idx}",
        "repo_hash": hashlib.sha256(f"repo-{idx}".encode()).hexdigest()[:16],
        "selection_stratum": stratum,
        "files_scanned": files_scanned,
        "files_total": files_total,
        "parser_errors": random.randint(0, 3),
        "agent_count": agent_count,
        "crew_count": crew_count,
        "crew_size_distribution": [random.randint(1, 5) for _ in range(crew_count)],
        "agent_tool_count_distribution": [random.randint(0, 8) for _ in range(agent_count)],
        "frameworks": frameworks,
        "framework_versions": fw_versions,
        "finding_rule_count": finding_rule_count,
        "finding_severities": severities,
        "finding_instance_counts": instance_counts,
        "total_finding_instances": total_instances,
        "fix_impact_estimates": fix_impacts,
        "deployment_signals": dep_signals,
        "topology_signature_hash": topo_hash,
        "graph_node_count": agent_count + crew_count,
        "graph_edge_count": edge_count,
        "inter_crew_edges": inter_crew,
    }


def gen_failed_ping(idx):
    return {
        "scan_id": gen_scan_id(),
        "timestamp": f"2026-02-14T{random.randint(0,23):02d}:{random.randint(0,59):02d}:00+00:00",
        "scanner_version": "0.3.1",
        "schema_id": 5,
        "schema_version": "0.3.2",
        "scan_status": "failed",
        "scan_duration_ms": 0,
        "risk_score": None,
        "repo_full_name": f"test-org/failed-repo-{idx}",
        "repo_hash": None,
        "selection_stratum": random.choice(STRATA),
        "files_scanned": 0,
        "files_total": 0,
        "parser_errors": 0,
        "agent_count": 0,
        "crew_count": 0,
        "finding_rule_count": 0,
        "frameworks": [],
        "failure_reason": random.choice(FAILURE_REASONS),
        "failure_detail": "synthetic test failure",
    }


def gen_empty_ping(idx):
    return {
        "scan_id": gen_scan_id(),
        "timestamp": f"2026-02-14T{random.randint(0,23):02d}:{random.randint(0,59):02d}:00+00:00",
        "scanner_version": "0.3.1",
        "schema_id": 5,
        "schema_version": "0.3.2",
        "scan_status": "empty",
        "scan_duration_ms": random.randint(100, 2000),
        "risk_score": 0,
        "repo_full_name": f"test-org/empty-repo-{idx}",
        "repo_hash": hashlib.sha256(f"empty-{idx}".encode()).hexdigest()[:16],
        "selection_stratum": random.choice(STRATA),
        "files_scanned": random.randint(1, 10),
        "files_total": random.randint(10, 50),
        "parser_errors": 0,
        "agent_count": 0,
        "crew_count": 0,
        "finding_rule_count": 0,
        "frameworks": [],
    }


def gen_partial_ping(idx):
    p = gen_success_ping(idx + 1000)
    p["scan_status"] = "partial"
    p["repo_full_name"] = f"test-org/partial-repo-{idx}"
    p["parser_errors"] = random.randint(3, 15)
    # Reduce files_scanned to show incomplete coverage
    p["files_scanned"] = int(p["files_total"] * random.uniform(0.3, 0.7))
    return p


def main():
    output_path = "pipeline/data/test_scan_results.jsonl"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    pings = []

    # 150 success pings
    for i in range(150):
        # First 16 go into cluster A, next 16 into cluster B (to trigger G5)
        if i < 16:
            p = gen_success_ping(i, force_cluster_hash=CLUSTER_HASH_A)
        elif i < 32:
            p = gen_success_ping(i, force_cluster_hash=CLUSTER_HASH_B)
        else:
            p = gen_success_ping(i)
        pings.append(p)

    # 20 failed
    for i in range(20):
        pings.append(gen_failed_ping(i))

    # 15 empty
    for i in range(15):
        pings.append(gen_empty_ping(i))

    # 15 partial
    for i in range(15):
        pings.append(gen_partial_ping(i))

    random.shuffle(pings)

    with open(output_path, "w") as f:
        for p in pings:
            f.write(json.dumps(p) + "\n")

    print(f"Generated {len(pings)} synthetic pings -> {output_path}")
    status_counts = {}
    for p in pings:
        s = p.get("scan_status", "unknown")
        status_counts[s] = status_counts.get(s, 0) + 1
    for s, c in sorted(status_counts.items()):
        print(f"  {s}: {c}")


if __name__ == "__main__":
    main()
