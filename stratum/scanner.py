"""Orchestrator: walks directory, runs parsers, evaluates rules, computes score."""
from __future__ import annotations

import fnmatch
import logging
import os

from stratum.models import (
    Capability, Confidence, GuardrailSignal, MCPServer,
    ScanResult, Severity,
)
from stratum.parsers import capabilities as cap_parser
from stratum.parsers import mcp as mcp_parser
from stratum.parsers import env as env_parser
from stratum.rules.engine import Engine

logger = logging.getLogger(__name__)

SKIP_DIRS = {".git", "node_modules", ".venv", "__pycache__", ".stratum"}
SKIP_EXTENSIONS = {".pyc"}


def scan(path: str) -> ScanResult:
    """Scan a project directory and return a ScanResult."""
    abs_path = os.path.abspath(path)

    # Load .gitignore patterns
    gitignore_patterns = _load_gitignore(abs_path)

    # Walk directory
    py_files: list[tuple[str, str]] = []  # (abs_path, content)
    py_file_paths: list[str] = []
    json_files: list[str] = []

    for root, dirs, files in os.walk(abs_path):
        # Filter directories in-place
        dirs[:] = [
            d for d in dirs
            if d not in SKIP_DIRS
            and not _matches_gitignore(
                os.path.relpath(os.path.join(root, d), abs_path) + "/",
                gitignore_patterns,
            )
        ]

        for fname in files:
            full = os.path.join(root, fname)
            rel = os.path.relpath(full, abs_path)
            _, ext = os.path.splitext(fname)

            if ext in SKIP_EXTENSIONS:
                continue
            if _matches_gitignore(rel, gitignore_patterns):
                continue

            if ext == ".py":
                try:
                    with open(full, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    py_files.append((full, content))
                    py_file_paths.append(full)
                except OSError:
                    pass
            elif ext == ".json":
                json_files.append(full)

    # Parse capabilities and guardrails
    all_capabilities: list[Capability] = []
    all_guardrails: list[GuardrailSignal] = []

    for file_path, content in py_files:
        rel = os.path.relpath(file_path, abs_path)
        caps, guards = cap_parser.scan_python_file(rel, content)
        all_capabilities.extend(caps)
        all_guardrails.extend(guards)

    # Parse MCP configs
    all_mcp_servers: list[MCPServer] = mcp_parser.parse_mcp_configs(abs_path)

    # Scan env
    env_var_names, env_findings = env_parser.scan_env(abs_path, py_file_paths)

    # Checkpoint detection
    checkpoint_type = "none"
    for _, content in py_files:
        if "langgraph.checkpoint" in content:
            if any(kw in content for kw in ("PostgresSaver", "SqliteSaver", "RedisSaver")):
                checkpoint_type = "durable"
                break
            elif "MemorySaver" in content and checkpoint_type != "durable":
                checkpoint_type = "memory_only"

    # Build relative-path py_files for governance rules
    rel_py_files = [(os.path.relpath(fp, abs_path), content) for fp, content in py_files]

    # Run engine
    engine = Engine()
    top_paths, signals, governance_context = engine.evaluate(
        all_capabilities, all_mcp_servers, all_guardrails,
        env_var_names, env_findings, checkpoint_type,
        py_files=rel_py_files,
    )

    # Calculate risk score
    all_findings = top_paths + signals
    score = _calculate_risk_score(
        all_findings, all_capabilities, all_guardrails, all_mcp_servers,
        governance_context,
    )

    # Count capabilities
    has_any_guardrails = len(all_guardrails) > 0
    outbound = sum(1 for c in all_capabilities if c.kind == "outbound")
    data_access = sum(1 for c in all_capabilities if c.kind == "data_access")
    code_exec = sum(1 for c in all_capabilities if c.kind == "code_exec")
    destructive = sum(1 for c in all_capabilities if c.kind == "destructive")
    financial = sum(1 for c in all_capabilities if c.kind == "financial")

    # Extract governance metadata
    learning_ctx = governance_context.get("learning", {})
    telemetry_ctx = governance_context.get("telemetry", {})
    eval_ctx = governance_context.get("eval", {})
    identity_ctx = governance_context.get("identity", {})

    # Count files scanned
    n_py = len(py_files)
    n_mcp_configs = len({s.source_file for s in all_mcp_servers})
    n_env = len([
        f for f in os.listdir(abs_path)
        if f == ".env" or f.startswith(".env.")
    ]) if os.path.isdir(abs_path) else 0

    return ScanResult(
        directory=abs_path,
        capabilities=all_capabilities,
        mcp_servers=all_mcp_servers,
        guardrails=all_guardrails,
        env_vars=env_var_names,
        top_paths=top_paths,
        signals=signals,
        risk_score=score,
        files_scanned=n_py,
        mcp_configs_scanned=n_mcp_configs,
        env_files_scanned=n_env,
        total_capabilities=len(all_capabilities),
        outbound_count=outbound,
        data_access_count=data_access,
        code_exec_count=code_exec,
        destructive_count=destructive,
        financial_count=financial,
        mcp_server_count=len(all_mcp_servers),
        guardrail_count=len(all_guardrails),
        has_any_guardrails=has_any_guardrails,
        checkpoint_type=checkpoint_type,
        # Learning & Governance
        learning_type=learning_ctx.get("learning_type"),
        has_learning_loop=learning_ctx.get("has_learning_loop", False),
        has_shared_context=learning_ctx.get("has_shared_context", False),
        telemetry_destinations=telemetry_ctx.get("telemetry_destinations", []),
        has_eval_conflict=eval_ctx.get("has_eval_conflict", False),
    )


def _calculate_risk_score(
    all_findings: list,
    capabilities: list[Capability],
    guardrails: list[GuardrailSignal],
    mcp_servers: list[MCPServer],
    governance_context: dict | None = None,
) -> int:
    """Calculate the risk score from findings and context."""
    score = 0

    # Per finding
    for f in all_findings:
        if f.severity == Severity.CRITICAL:
            score += 25
        elif f.severity == Severity.HIGH:
            score += 15
        elif f.severity == Severity.MEDIUM:
            score += 8
        elif f.severity == Severity.LOW:
            score += 3

    # Bonus: zero guardrails with >= 3 capabilities
    has_any = len(guardrails) > 0
    if not has_any and len(capabilities) >= 3:
        score += 15

    # Bonus: Known CVE MCP
    if any(f.id == "STRATUM-004" for f in all_findings):
        score += 20

    # Bonus: financial tools + no HITL + no validation
    financial_caps = [c for c in capabilities if c.kind == "financial"]
    if financial_caps and not any(c.has_input_validation for c in financial_caps):
        financial_names = {c.function_name for c in financial_caps}
        has_financial_hitl = any(
            g.kind == "hitl" and (
                not g.covers_tools or bool(set(g.covers_tools) & financial_names)
            )
            for g in guardrails
        )
        if not has_financial_hitl:
            score += 10

    # Bonus: zero error handling across >= 3 external calls
    external_caps = [
        c for c in capabilities
        if c.kind in ("outbound", "data_access", "financial")
        and c.confidence != Confidence.HEURISTIC
    ]
    if len(external_caps) >= 3 and not any(c.has_error_handling for c in external_caps):
        score += 5

    # Learning & governance bonuses
    if governance_context:
        learning_ctx = governance_context.get("learning", {})
        telemetry_ctx = governance_context.get("telemetry", {})
        eval_ctx = governance_context.get("eval", {})
        identity_ctx = governance_context.get("identity", {})

        has_learning_loop = learning_ctx.get("has_learning_loop", False)
        has_provenance = any(
            w.get("has_provenance") for w in learning_ctx.get("write_ops", [])
        )
        has_rollback = any(
            f.id == "CONTEXT-002" for f in all_findings
        ) is False  # No CONTEXT-002 means rollback exists
        # Actually: if CONTEXT-002 is NOT in findings, rollback exists
        has_rollback = not any(f.id == "CONTEXT-002" for f in all_findings)

        # Learning loop with no integrity controls
        if has_learning_loop and not has_provenance and not has_rollback:
            score += 12

        # Shared context with no write scoping
        has_shared = learning_ctx.get("has_shared_context", False)
        has_scoped_writes = any(
            w.get("has_provenance") for w in learning_ctx.get("write_ops", [])
        )
        if has_shared and not has_scoped_writes:
            score += 15

        # Trajectory RL from production data
        if learning_ctx.get("learning_type") == "trajectory_rl":
            score += 20

        # Trace data flowing to model provider
        if telemetry_ctx.get("has_trace_to_model_provider", False):
            score += 8

        # Eval provider conflict
        if eval_ctx.get("has_eval_conflict", False):
            score += 5

        # Shared agent credentials
        if identity_ctx.get("has_shared_credentials", False):
            score += 10

        # No agent identity across >1 agent
        agent_count = identity_ctx.get("agent_count", 0)
        all_have_identity = identity_ctx.get("all_have_identity", True)
        if agent_count > 1 and not all_have_identity:
            score += 8

    return min(score, 100)


def _load_gitignore(directory: str) -> list[str]:
    """Load .gitignore patterns from directory."""
    gitignore_path = os.path.join(directory, ".gitignore")
    patterns: list[str] = []
    try:
        with open(gitignore_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line)
    except OSError:
        pass
    return patterns


def _matches_gitignore(rel_path: str, patterns: list[str]) -> bool:
    """Check if a relative path matches any gitignore pattern."""
    # Normalize separators
    rel_path = rel_path.replace("\\", "/")
    for pattern in patterns:
        pattern = pattern.replace("\\", "/")
        # Directory patterns (trailing /)
        if pattern.endswith("/"):
            dir_pat = pattern.rstrip("/")
            if rel_path.startswith(dir_pat + "/") or rel_path == dir_pat + "/":
                return True
        # Glob match
        if fnmatch.fnmatch(rel_path, pattern):
            return True
        # Match against basename
        basename = os.path.basename(rel_path.rstrip("/"))
        if fnmatch.fnmatch(basename, pattern):
            return True
    return False
