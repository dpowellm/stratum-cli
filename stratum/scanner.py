"""Orchestrator: walks directory, runs parsers, evaluates rules, computes score."""
from __future__ import annotations

import ast
import fnmatch
import logging
import os

from stratum.models import (
    Capability, Confidence, Finding, GuardrailSignal, MCPServer,
    RiskCategory, ScanResult, Severity, TrustLevel,
)
from stratum.parsers import capabilities as cap_parser
from stratum.parsers import mcp as mcp_parser
from stratum.parsers import env as env_parser
from stratum.parsers.capabilities import detect_framework
from stratum.parsers.langgraph_parser import parse_langgraph
from stratum.parsers.langchain_parser import parse_langchain_agents
from stratum.parsers.surfaces import detect_llm_models, detect_env_var_names, detect_vector_stores
from stratum.rules.engine import Engine
from stratum.graph.builder import build_graph
from stratum.graph.models import NodeType, RiskPath
from stratum.graph.traversal import find_blast_radii, find_control_bypasses
from stratum.graph.remediation import framework_remediation, framework_remediation_008, framework_remediation_010
from stratum.rules.helpers import limit_evidence
from stratum.graph.agents import extract_agents_from_yaml, extract_agents_from_python

logger = logging.getLogger(__name__)

SKIP_DIRS = {".git", "node_modules", ".venv", "__pycache__", ".stratum"}
SKIP_EXTENSIONS = {".pyc"}

# ---------------------------------------------------------------------------
# Finding classification and score calibration (v4)
# ---------------------------------------------------------------------------

FINDING_CLASS: dict[str, str] = {
    # Architecture — specific to this project's code structure
    "STRATUM-001": "architecture",
    "STRATUM-002": "architecture",
    "STRATUM-003": "architecture",
    "STRATUM-CR01": "architecture",
    "STRATUM-CR02": "architecture",
    "STRATUM-CR05": "architecture",
    "STRATUM-CR06": "architecture",
    "STRATUM-BR01": "architecture",
    "STRATUM-BR02": "architecture",
    # Operational — code-specific but lower urgency
    "STRATUM-007": "operational",
    "STRATUM-008": "operational",
    "STRATUM-009": "operational",
    "STRATUM-010": "operational",
    "STRATUM-BR03": "operational",
    "STRATUM-BR04": "operational",
    "STRATUM-OP01": "operational",
    "STRATUM-OP02": "operational",
    # Hygiene — fire on almost every project
    "ENV-001": "hygiene",
    "ENV-002": "hygiene",
    "CONTEXT-001": "hygiene",
    "CONTEXT-002": "hygiene",
    "TELEMETRY-003": "hygiene",
    "IDENTITY-001": "hygiene",
    "IDENTITY-002": "hygiene",
    # Meta — scanner observations, not risks
    "EVAL-001": "meta",
    "EVAL-002": "meta",
    "LEARNING-001": "meta",
    "PORTABILITY-001": "meta",
}

# Severity weights by finding class — architecture gets full weight, hygiene minimal
SCORE_WEIGHTS: dict[tuple[str, str], int] = {
    ("CRITICAL", "architecture"): 12,
    ("HIGH", "architecture"): 8,
    ("MEDIUM", "architecture"): 5,
    ("LOW", "architecture"): 2,
    ("CRITICAL", "operational"): 8,
    ("HIGH", "operational"): 5,
    ("MEDIUM", "operational"): 3,
    ("LOW", "operational"): 1,
    ("CRITICAL", "hygiene"): 3,
    ("HIGH", "hygiene"): 2,
    ("MEDIUM", "hygiene"): 1,
    ("LOW", "hygiene"): 0,
    ("CRITICAL", "meta"): 0,
    ("HIGH", "meta"): 0,
    ("MEDIUM", "meta"): 0,
    ("LOW", "meta"): 0,
}

# Per-crew severity weights
CREW_SEVERITY_WEIGHT = {
    Severity.CRITICAL: 15,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
}


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

    # Collect YAML files
    yaml_files: list[tuple[str, str]] = []
    for root, dirs, files in os.walk(abs_path):
        dirs[:] = [
            d for d in dirs
            if d not in SKIP_DIRS
            and not _matches_gitignore(
                os.path.relpath(os.path.join(root, d), abs_path) + "/",
                gitignore_patterns,
            )
        ]
        for fname in files:
            _, ext = os.path.splitext(fname)
            if ext in (".yaml", ".yml"):
                full = os.path.join(root, fname)
                rel = os.path.relpath(full, abs_path)
                if _matches_gitignore(rel, gitignore_patterns):
                    continue
                try:
                    with open(full, "r", encoding="utf-8", errors="ignore") as f:
                        yaml_files.append((rel, f.read()))
                except OSError:
                    pass

    # Parse capabilities and guardrails
    all_capabilities: list[Capability] = []
    all_guardrails: list[GuardrailSignal] = []
    all_frameworks: set[str] = set()

    for file_path, content in py_files:
        rel = os.path.relpath(file_path, abs_path)
        caps, guards = cap_parser.scan_python_file(rel, content)
        all_capabilities.extend(caps)
        all_guardrails.extend(guards)

        # Framework detection
        try:
            tree = ast.parse(content)
            file_imports: set[str] = set()
            file_alias_map: dict[str, str] = {}
            cap_parser._collect_imports(tree.body, file_imports, file_alias_map)
            fws = detect_framework(file_imports, file_alias_map)
            all_frameworks.update(fws)
        except SyntaxError:
            pass

    # YAML config scanning (for framework tool references)
    yaml_caps = _scan_yaml_configs(yaml_files)
    all_capabilities.extend(yaml_caps)

    # ── Step 4: Framework-specific parsing (dispatcher) ──────────
    # Build (file_path, content, ast_tree) triples and AST dict for parsers
    py_files_with_ast: list[tuple[str, str, ast.Module]] = []
    ast_dict: dict[str, ast.Module] = {}
    for file_path, content in py_files:
        rel = os.path.relpath(file_path, abs_path)
        try:
            tree = ast.parse(content)
            py_files_with_ast.append((rel, content, tree))
            ast_dict[rel] = tree
        except SyntaxError:
            pass

    # Collect all file paths (absolute) for surface detectors
    all_file_paths: list[str] = [fp for fp, _ in py_files]
    _surface_names = {".env.example", ".env.template", ".env.sample"}
    for root, dirs, files in os.walk(abs_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            full = os.path.join(root, fname)
            _, ext = os.path.splitext(fname)
            if ext in (".yaml", ".yml") or fname in _surface_names:
                if full not in all_file_paths:
                    all_file_paths.append(full)

    # Extract agent definitions from YAML files
    all_agent_defs = []
    for file_path, content in yaml_files:
        all_agent_defs.extend(extract_agents_from_yaml(content, file_path))

    # Extract agent definitions from Python files (use relative paths)
    for file_path, content in py_files:
        rel = os.path.relpath(file_path, abs_path)
        all_agent_defs.extend(extract_agents_from_python(content, rel))

    # Deduplicate agent definitions by (name, framework), merge tool_names
    agent_dedup: dict[tuple[str, str], object] = {}
    for ad in all_agent_defs:
        key = (ad.name, ad.framework)
        if key not in agent_dedup:
            agent_dedup[key] = ad
        else:
            existing = agent_dedup[key]
            for t in ad.tool_names:
                if t not in existing.tool_names:
                    existing.tool_names.append(t)
    all_agent_defs = list(agent_dedup.values())

    # ── Framework dispatch: CrewAI ──
    from stratum.parsers.agents import (
        extract_crew_definitions, detect_shared_tools, detect_cross_crew_flows,
    )
    crew_definitions = []
    all_agent_relationships = []

    if "CrewAI" in all_frameworks:
        crewai_crews = extract_crew_definitions(py_files_with_ast)
        crew_definitions.extend(crewai_crews)
        shared_tool_rels = detect_shared_tools(all_agent_defs, crewai_crews)
        cross_crew_rels = detect_cross_crew_flows(
            crewai_crews, [(os.path.relpath(fp, abs_path), c) for fp, c in py_files],
        )
        all_agent_relationships.extend(shared_tool_rels + cross_crew_rels)

    # ── Framework dispatch: LangGraph ──
    if "LangGraph" in all_frameworks:
        lg_crews, lg_agents, lg_rels = parse_langgraph(ast_dict, all_file_paths)
        crew_definitions.extend(lg_crews)
        all_agent_defs.extend(lg_agents)
        all_agent_relationships.extend(lg_rels)

    # ── Framework dispatch: LangChain ──
    if "LangChain" in all_frameworks:
        lc_crews, lc_agents, lc_rels = parse_langchain_agents(ast_dict, all_file_paths)
        crew_definitions.extend(lc_crews)
        all_agent_defs.extend(lc_agents)
        all_agent_relationships.extend(lc_rels)

    # ── Connectable surfaces: detect during same AST walk ──
    llm_models = detect_llm_models(ast_dict, all_file_paths)
    detected_env_var_names = detect_env_var_names(ast_dict, all_file_paths)
    detected_vector_stores = detect_vector_stores(ast_dict)

    # ── Determine parse quality ──
    if crew_definitions:
        framework_parse_quality = "full"
    elif all_agent_defs:
        framework_parse_quality = "partial"
    elif all_capabilities:
        framework_parse_quality = "tools_only"
    else:
        framework_parse_quality = "empty"

    # Resolve guardrail covers_tools
    from stratum.parsers.capabilities import resolve_guardrail_coverage
    ast_trees: dict[str, ast.Module] = {}
    for rel, _content, tree in py_files_with_ast:
        ast_trees[rel] = tree
    for guard in all_guardrails:
        if not guard.covers_tools:
            guard.covers_tools = resolve_guardrail_coverage(
                guard, ast_trees, all_capabilities,
            )

    # Deduplicate capabilities
    all_capabilities = _deduplicate_capabilities(all_capabilities)

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

    # Post-process findings with framework-aware remediation
    fw_list = sorted(all_frameworks)
    for f in top_paths + signals:
        if f.id == "STRATUM-002":
            f.remediation = framework_remediation(
                "STRATUM-002", fw_list, [], None,
            )
        elif f.id == "STRATUM-008":
            f.remediation = framework_remediation_008(fw_list)
        elif f.id == "STRATUM-010":
            f.remediation = framework_remediation_010(fw_list)

    # Calculate risk score
    all_findings = top_paths + signals
    score_result = _calculate_risk_score(
        all_findings, all_capabilities, all_guardrails, all_mcp_servers,
        governance_context, crew_definitions,
    )
    per_crew_scores: dict[str, int] | None = None
    if isinstance(score_result, tuple):
        score, per_crew_scores = score_result
    else:
        score = score_result

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

    # Count lines of code (non-empty, non-comment lines across all .py files)
    total_loc = 0
    for _, content in py_files:
        for line in content.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                total_loc += 1

    # Count files scanned
    n_py = len(py_files)
    n_mcp_configs = len({s.source_file for s in all_mcp_servers})
    n_env = len([
        f for f in os.listdir(abs_path)
        if f == ".env" or f.startswith(".env.")
    ]) if os.path.isdir(abs_path) else 0

    result = ScanResult(
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
        total_loc=total_loc,
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
        detected_frameworks=sorted(all_frameworks),
        # Learning & Governance
        learning_type=learning_ctx.get("learning_type"),
        has_learning_loop=learning_ctx.get("has_learning_loop", False),
        has_shared_context=learning_ctx.get("has_shared_context", False),
        telemetry_destinations=telemetry_ctx.get("telemetry_destinations", []),
        has_eval_conflict=eval_ctx.get("has_eval_conflict", False),
        agent_definitions=all_agent_defs,
        crew_definitions=crew_definitions,
        agent_relationships=all_agent_relationships,
        # Connectable surfaces
        llm_models=llm_models,
        env_var_names_detected=detected_env_var_names,
        vector_stores_detected=detected_vector_stores,
        framework_parse_quality=framework_parse_quality,
    )

    # Store per-crew scores if computed
    if per_crew_scores:
        result._per_crew_scores = per_crew_scores

    # Build risk graph
    result.graph = build_graph(result)

    # Derive guardrail_count from graph nodes (Bug 11: match graph state)
    if result.graph:
        result.guardrail_count = sum(
            1 for n in result.graph.nodes.values()
            if n.node_type == NodeType.GUARDRAIL
        )
        result.has_any_guardrails = result.guardrail_count > 0

    # Compute blast radii and control bypasses
    result.blast_radii = find_blast_radii(result.graph, crew_definitions, all_agent_defs)
    result._control_bypasses = find_control_bypasses(result.graph, crew_definitions)

    # Re-compute risk surface with blast_radii and crew data
    from stratum.graph.surface import compute_risk_surface
    result.graph.risk_surface = compute_risk_surface(
        result.graph, blast_radii=result.blast_radii, crews=crew_definitions,
    )

    # Filter uncontrolled paths by guardrail coverage (v4)
    # Paths covered by HITL guardrails (human_input=True, interrupt_before) are excluded
    uncontrolled_paths = _filter_guarded_paths(
        result.graph.uncontrolled_paths if result.graph else [],
        all_guardrails, result.graph,
    )

    # Replace pairwise STRATUM-001 findings with graph-derived findings
    if result.graph and uncontrolled_paths:
        graph_findings = []
        for risk_path in uncontrolled_paths:
            finding = _graph_finding_for_path(
                risk_path, result.graph, result.detected_frameworks,
                crew_definitions=result.crew_definitions,
            )
            if finding:
                graph_findings.append(finding)

        # Consolidate graph findings with same rule ID
        graph_findings = _consolidate_graph_findings(graph_findings)

        # Remove old pairwise STRATUM-001 findings, replace with graph findings
        result.top_paths = [
            f for f in result.top_paths if f.id != "STRATUM-001"
        ] + graph_findings
        # Re-sort by severity
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        result.top_paths.sort(
            key=lambda f: severity_order.get(f.severity.value if hasattr(f.severity, 'value') else f.severity, 0),
            reverse=True,
        )
        result.top_paths = result.top_paths[:5]

    # Run business risk rules
    from stratum.rules.business_risk import evaluate_business_risks
    business_findings = evaluate_business_risks(result)

    # Run operational risk rules
    from stratum.rules.operational_risk import evaluate_operational_risks
    operational_findings = evaluate_operational_risks(result)

    # Run compounding risk rules
    from stratum.rules.compounding_risk import evaluate_compounding_risks
    compounding_findings = evaluate_compounding_risks(result)

    # Generate blast radius findings (STRATUM-CR05)
    blast_radius_findings = _generate_blast_radius_findings(result)

    # Generate control bypass findings (STRATUM-CR06)
    bypass_findings = _generate_bypass_findings(result)

    # Merge new findings — consolidate duplicates per rule ID
    all_new_findings = (
        business_findings + operational_findings + compounding_findings
        + blast_radius_findings + bypass_findings
    )
    # Apply severity gating
    from stratum.rules.engine import _gate_severity
    for f in all_new_findings:
        f = _gate_severity(f)

    # Consolidate: keep at most 1 finding per rule ID (merge evidence)
    consolidated_new: list[Finding] = []
    seen_rule_ids: dict[str, Finding] = {}
    for f in all_new_findings:
        if f.id not in seen_rule_ids:
            seen_rule_ids[f.id] = f
            consolidated_new.append(f)
        else:
            # Merge evidence into existing finding
            existing = seen_rule_ids[f.id]
            for ev in f.evidence:
                if ev not in existing.evidence:
                    existing.evidence.append(ev)

    # Limit evidence to 3 items max after merging
    for f in consolidated_new:
        f.evidence = limit_evidence(f.evidence)

    # Route into top_paths or signals
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    for f in consolidated_new:
        sev_val = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
        cat_val = f.category.value if hasattr(f.category, 'value') else str(f.category)
        if severity_rank.get(sev_val, 0) >= 3 or cat_val in ("security", "compounding"):
            result.top_paths.append(f)
        else:
            result.signals.append(f)

    # Re-sort and trim top_paths
    result.top_paths.sort(
        key=lambda f: severity_rank.get(
            f.severity.value if hasattr(f.severity, 'value') else str(f.severity), 0
        ),
        reverse=True,
    )

    # Tag finding_class on all findings from FINDING_CLASS mapping (v4)
    all_findings_final = result.top_paths + result.signals
    for f in all_findings_final:
        base_id = f.id.split(".")[0]
        if base_id in FINDING_CLASS:
            f.finding_class = FINDING_CLASS[base_id]

    # Calculate risk score with asymptotic normalization (v5)
    result.risk_score = calculate_risk_score(all_findings_final)

    # === TOXIC COMBINATION DETECTION ===
    tc_matches = []
    if result.graph is not None:
        try:
            from stratum.graph.toxic_combinations import match_all as match_toxic_combinations
            tc_matches = match_toxic_combinations(result.graph)
        except Exception:
            logger.warning("TC matching failed, continuing without toxic combinations")

    result.tc_matches = tc_matches

    # Compute compound risk score (TC-adjusted)
    if tc_matches:
        result.compound_risk_score = compute_compound_risk_score(
            all_findings_final, tc_matches, result.risk_score,
        )
    else:
        result.compound_risk_score = result.risk_score

    # Compute per-crew scores using crew_id on findings (v4)
    per_crew_scores_map: dict[str, int] = {}
    for crew in crew_definitions:
        per_crew_scores_map[crew.name] = _score_crew(crew.name, all_findings_final)
    if per_crew_scores_map:
        result._per_crew_scores = per_crew_scores_map

    # Match against known real-world incidents
    from stratum.intelligence.incidents import match_incidents
    result.incident_matches = match_incidents(result)

    return result


def _calculate_risk_score(
    all_findings: list,
    capabilities: list[Capability],
    guardrails: list[GuardrailSignal],
    mcp_servers: list[MCPServer],
    governance_context: dict | None = None,
    crew_definitions: list | None = None,
) -> int | tuple[int, dict[str, int]]:
    """Calculate the risk score from findings and context.

    When crew_definitions has >5 crews (monorepo), returns (global_score, per_crew_scores).
    Otherwise returns just the global score.
    """
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

    # Monorepo calibration: when >5 crews, compute per-crew scores
    # and use max_crew + log bonus instead of raw sum
    crews = crew_definitions or []
    if len(crews) > 5:
        import math
        # Assign findings to crews by evidence file paths
        crew_scores: dict[str, int] = {}
        for crew in crews:
            crew_finding_score = 0
            for f in all_findings:
                # Check if finding evidence overlaps with crew's source file
                crew_source = crew.source_file or ""
                if any(crew_source and crew_source in ev for ev in f.evidence):
                    sev_pts = {Severity.CRITICAL: 25, Severity.HIGH: 15, Severity.MEDIUM: 8, Severity.LOW: 3}
                    crew_finding_score += sev_pts.get(f.severity, 0)
            crew_scores[crew.name] = min(crew_finding_score, 100)

        if crew_scores:
            sorted_scores = sorted(crew_scores.values(), reverse=True)
            max_crew = sorted_scores[0]
            others_sum = sum(sorted_scores[1:])
            # Logarithmic bonus from other crews: prevents 98/100 for monorepos
            log_bonus = int(10 * math.log2(1 + others_sum / 50)) if others_sum > 0 else 0
            calibrated = max_crew + log_bonus
            score = min(calibrated, score)  # Never increase the raw score
            return (min(score, 100), crew_scores)

    return min(score, 100)


def _score_crew(crew_name: str, all_findings: list[Finding]) -> int:
    """Compute risk score for a single crew using asymptotic normalization."""
    crew_findings = [f for f in all_findings if getattr(f, 'crew_id', '') == crew_name]
    return calculate_risk_score(crew_findings)


def _finalize_score(raw_score: int, all_findings: list[Finding]) -> int:
    """Enforce a score floor when real findings exist.

    Prevents score=0 when there are actual findings.
    Floor = max(8, non_info_count * 2), capped at 100.
    """
    non_info_findings = [
        f for f in all_findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
    ]
    if non_info_findings:
        floor = max(8, len(non_info_findings) * 2)
        return max(floor, min(raw_score, 100))
    return max(0, min(raw_score, 100))


def _filter_guarded_paths(
    uncontrolled_paths: list,
    guardrails: list[GuardrailSignal],
    graph,
) -> list:
    """Filter out paths covered by HITL guardrails.

    A path is "guarded" if any agent on the path has a HITL guardrail
    (human_input=True on its Task, or interrupt_before containing its node name).
    """
    if not uncontrolled_paths or not guardrails:
        return list(uncontrolled_paths)

    # Build set of agent names/tools that have HITL coverage
    hitl_covered_names: set[str] = set()
    # Files that contain HITL guardrails (human_input=True, interrupt)
    hitl_covered_files: set[str] = set()

    for g in guardrails:
        if g.kind == "hitl":
            if g.covers_tools:
                hitl_covered_names.update(t.lower() for t in g.covers_tools)
            # Track source files with HITL guards
            detail = (g.detail or "").lower()
            if "human_input" in detail or "interrupt" in detail:
                hitl_covered_files.add(g.source_file)

    if not hitl_covered_names and not hitl_covered_files:
        return list(uncontrolled_paths)

    # Build agent-to-file mapping from graph nodes
    agent_files: dict[str, set[str]] = {}
    if graph and hasattr(graph, 'nodes'):
        for nid, node in graph.nodes.items():
            if node.node_type == NodeType.AGENT:
                label_lower = node.label.lower().replace(" ", "_").replace("-", "_")
                source = getattr(node, 'source_file', '') or ''
                if source:
                    agent_files.setdefault(label_lower, set()).add(source)
                    agent_files.setdefault(node.label.lower(), set()).add(source)

    unguarded = []
    for path in uncontrolled_paths:
        path_guarded = False
        for nid in path.nodes:
            node = graph.nodes.get(nid) if graph else None
            if node and node.node_type == NodeType.AGENT:
                label_lower = node.label.lower().replace(" ", "_").replace("-", "_")
                # Check 1: agent name/tool directly in HITL covered names
                if label_lower in hitl_covered_names or node.label.lower() in hitl_covered_names:
                    path_guarded = True
                    break
                # Check 2: agent's source file has an HITL guardrail
                node_source = getattr(node, 'source_file', '') or ''
                if node_source and node_source in hitl_covered_files:
                    path_guarded = True
                    break
                # Check 3: agent mapped to a file with HITL guardrail
                for key in (label_lower, node.label.lower()):
                    if key in agent_files:
                        if agent_files[key] & hitl_covered_files:
                            path_guarded = True
                            break
                if path_guarded:
                    break
        if not path_guarded:
            unguarded.append(path)

    return unguarded


def calculate_risk_score(all_findings: list[Finding]) -> int:
    """Compute a 0-100 risk score using class-weighted severity and asymptotic normalization.

    Uses raw / (raw + K) * 100 with K=50 for diminishing returns.
    Replaces the old linear sum scoring entirely.
    """
    # Step 1: Compute raw weighted sum
    raw = 0
    for f in all_findings:
        sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
        fc = getattr(f, 'finding_class', 'security')
        # Normalize: 'security' and 'compounding' map to 'architecture' for weights
        if fc in ('security', 'compounding'):
            fc = 'architecture'
        base_id = f.id.rsplit('.', 1)[0] if '.' in f.id else f.id
        cls = FINDING_CLASS.get(base_id, fc)
        if cls in ('security', 'compounding'):
            cls = 'architecture'
        weight = SCORE_WEIGHTS.get((sev, cls), 0)
        raw += weight

    # Step 2: Asymptotic normalization
    # k=50: raw=50 → score=50, raw=100 → score=67, raw=200 → score=80
    K = 50
    if raw == 0:
        score = 0.0
    else:
        score = (raw / (raw + K)) * 100

    # Step 3: Floor — if real findings exist, minimum score is 8
    non_info = [
        f for f in all_findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
    ]
    if non_info:
        floor = max(8, len(non_info) * 2)
        score = max(floor, score)

    # Step 4: Round to integer, cap at 100
    return min(100, round(score))


# ---------------------------------------------------------------------------
# Compound risk scoring (toxic combinations)
# ---------------------------------------------------------------------------

TC_SEVERITY_WEIGHTS = {
    "CRITICAL": 20,
    "HIGH": 12,
    "MEDIUM": 6,
}

COMPONENT_MULTIPLIER = 0.2  # +20% per component beyond 2

FINDING_SEVERITY_WEIGHTS = {
    "CRITICAL": 12,
    "HIGH": 8,
    "MEDIUM": 5,
    "LOW": 2,
}


def compute_compound_risk_score(findings, tc_matches, base_score: int) -> int:
    """Compute risk score that accounts for toxic combinations.

    The compound score is always >= the base score and <= 100.
    TCs add risk on top of individual findings, with partial
    deduction to avoid fully double-counting.
    """
    if not tc_matches:
        return base_score

    # TC bonus
    tc_bonus = 0
    for tc in tc_matches:
        component_count = len(tc.finding_components)
        weight = TC_SEVERITY_WEIGHTS.get(tc.severity, 0)
        multiplier = 1 + COMPONENT_MULTIPLIER * max(0, component_count - 2)
        tc_bonus += weight * multiplier

    # Partial deduction for double-counting: component findings are already
    # counted in the base score. Deduct 50% of their individual weights.
    component_finding_ids = set()
    for tc in tc_matches:
        component_finding_ids.update(tc.finding_components)

    double_count_deduction = 0
    for finding in findings:
        if finding.id in component_finding_ids:
            sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            double_count_deduction += FINDING_SEVERITY_WEIGHTS.get(sev, 0) * 0.5

    raw = base_score + tc_bonus - double_count_deduction
    return min(max(int(raw), base_score), 100)  # Never lower than base, never above 100


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


def _deduplicate_capabilities(caps: list[Capability]) -> list[Capability]:
    """Remove duplicate capabilities, keeping highest confidence.

    Dedup key: (source_file, kind, library_root). When framework detection
    finds the same tool via import and via Agent(tools=[...]), keep one.
    """
    seen: dict[tuple[str, str, str], Capability] = {}
    confidence_order = {Confidence.CONFIRMED: 2, Confidence.PROBABLE: 1, Confidence.HEURISTIC: 0}
    for cap in caps:
        lib_root = cap.library.split(".")[0] if cap.library else ""
        key = (cap.source_file, cap.kind, lib_root)
        if key not in seen:
            seen[key] = cap
        else:
            existing = seen[key]
            if confidence_order.get(cap.confidence, 0) > confidence_order.get(existing.confidence, 0):
                seen[key] = cap
    return list(seen.values())


def _scan_yaml_configs(yaml_files: list[tuple[str, str]]) -> list[Capability]:
    """Scan YAML config files for framework tool references.

    Looks for tools: [...] keys containing known tool class names.
    Requires PyYAML; silently returns empty if not installed.
    """
    try:
        import yaml
    except ImportError:
        return []

    from stratum.framework_tools import KNOWN_TOOLS

    capabilities: list[Capability] = []
    seen: set[tuple[str, str, str]] = set()

    for file_path, content in yaml_files:
        try:
            docs = list(yaml.safe_load_all(content))
        except Exception:
            continue

        for doc in docs:
            if isinstance(doc, dict):
                _extract_tools_from_yaml(doc, file_path, capabilities, seen, KNOWN_TOOLS)

    return capabilities


def _extract_tools_from_yaml(
    obj: dict | list,
    file_path: str,
    capabilities: list[Capability],
    seen: set[tuple[str, str, str]],
    known_tools: dict,
) -> None:
    """Recursively find tools: [...] in YAML structures."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == "tools" and isinstance(value, list):
                for tool_name in value:
                    if isinstance(tool_name, str) and tool_name in known_tools:
                        profile = known_tools[tool_name]
                        for kind in profile.kinds:
                            k = (tool_name, kind, file_path)
                            if k not in seen:
                                seen.add(k)
                                _TRUST_BY_KIND = {
                                    "data_access": "internal",
                                    "outbound": "external",
                                    "code_exec": "privileged",
                                    "destructive": "internal",
                                    "financial": "restricted",
                                    "file_system": "internal",
                                }
                                capabilities.append(Capability(
                                    function_name=f"[YAML: {tool_name}]",
                                    kind=kind,
                                    library=profile.source_modules[0] if profile.source_modules else "yaml_config",
                                    confidence=Confidence.CONFIRMED,
                                    source_file=file_path,
                                    line_number=0,
                                    evidence=f"{tool_name} in YAML config",
                                    trust_level=TrustLevel(_TRUST_BY_KIND.get(kind, "external")),
                                    has_error_handling=False,
                                    has_timeout=False,
                                    call_text=f"{tool_name} in YAML config",
                                ))
            else:
                _extract_tools_from_yaml(value, file_path, capabilities, seen, known_tools)
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                _extract_tools_from_yaml(item, file_path, capabilities, seen, known_tools)


# ---------------------------------------------------------------------------
# Graph-derived finding generation
# ---------------------------------------------------------------------------

def _graph_finding_for_path(
    risk_path: RiskPath,
    graph,
    detected_frameworks: list[str],
    crew_definitions: list | None = None,
) -> Finding | None:
    """Convert a RiskPath from the graph traversal into a Finding.

    Replaces the old pairwise rule match for STRATUM-001.
    """
    nodes = [graph.nodes[nid] for nid in risk_path.nodes]

    finding_id = "STRATUM-001"
    title = "Unguarded data-to-external path"

    # Resolve crew for this path
    crew_name = ""
    if crew_definitions:
        agent_node_ids = [
            nid for nid in risk_path.nodes
            if graph.nodes.get(nid) and graph.nodes[nid].node_type == NodeType.AGENT
        ]
        for crew in crew_definitions:
            crew_agent_ids = set()
            for name in crew.agent_names:
                crew_agent_ids.add(f"agent_{name.lower().replace(' ', '_').replace('-', '_')}")
                crew_agent_ids.add(name)
            agent_labels = {graph.nodes[aid].label for aid in agent_node_ids if aid in graph.nodes}
            if agent_labels & crew_agent_ids or any(aid in crew_agent_ids for aid in agent_node_ids):
                crew_name = crew.name
                break

    # Path display: friendly labels joined by arrow
    path_display = " \u2192 ".join(n.label for n in nodes)

    # What happens: from the scenario generator
    what_happens = risk_path.plain_description or risk_path.description

    # Evidence: source files from capability nodes on the path
    evidence = []
    for node in nodes:
        if node.source_file and node.source_file not in evidence:
            file_ref = (
                f"{node.source_file}:{node.line_number}"
                if node.line_number > 0
                else node.source_file
            )
            evidence.append(file_ref)

    # Remediation: framework-specific
    remediation_text = framework_remediation(
        finding_id, detected_frameworks, risk_path.nodes, graph,
    )

    from stratum.research.owasp import get_owasp
    owasp_id, owasp_name = get_owasp("STRATUM-001")

    return Finding(
        id=finding_id,
        severity=Severity(risk_path.severity),
        confidence=Confidence.CONFIRMED,
        category=RiskCategory.SECURITY,
        title=title,
        path=path_display,
        description=what_happens,
        evidence=evidence,
        scenario=what_happens,
        remediation=remediation_text,
        effort="low",
        references=["https://embracethered.com/blog/posts/2024/m365-copilot-echo-leak/"],
        owasp_id=owasp_id,
        owasp_name=owasp_name,
        finding_class="security",
        quick_fix_type="add_hitl",
        graph_paths=[risk_path],
        crew_id=crew_name,
    )


def _consolidate_graph_findings(findings: list[Finding]) -> list[Finding]:
    """Merge findings with the same rule ID into one finding with multiple paths.

    Three STRATUM-001 findings become one STRATUM-001 with three paths listed.
    Keeps the highest severity. Uses the most dangerous path's scenario as primary.
    """
    by_id: dict[str, list[Finding]] = {}
    for f in findings:
        by_id.setdefault(f.id, []).append(f)

    consolidated: list[Finding] = []
    for rule_id, group in by_id.items():
        if len(group) == 1:
            consolidated.append(group[0])
            continue

        # Sort by severity (most severe first)
        severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        group.sort(
            key=lambda f: severity_rank.get(
                f.severity.value if hasattr(f.severity, 'value') else f.severity, 0
            ),
            reverse=True,
        )

        primary = group[0]  # Most dangerous path

        # Build multi-path display
        all_paths = [f.path for f in group]
        path_display = "\n    ".join(all_paths)

        # Merge evidence (deduplicate)
        all_evidence: list[str] = []
        seen_ev: set[str] = set()
        for f in group:
            for ev in f.evidence:
                if ev not in seen_ev:
                    seen_ev.add(ev)
                    all_evidence.append(ev)

        merged = Finding(
            id=primary.id,
            severity=primary.severity,
            confidence=primary.confidence,
            category=primary.category,
            title=f"{primary.title} ({len(group)} paths)",
            path=path_display,
            description=primary.description,
            evidence=all_evidence,
            scenario=primary.scenario,
            business_context=primary.business_context,
            remediation=primary.remediation,
            effort=primary.effort,
            references=primary.references,
            owasp_id=primary.owasp_id,
            owasp_name=primary.owasp_name,
            finding_class=primary.finding_class,
            quick_fix_type=primary.quick_fix_type,
        )
        consolidated.append(merged)

    return consolidated


# ---------------------------------------------------------------------------
# Blast radius + control bypass findings
# ---------------------------------------------------------------------------

def _to_var_name(agent_name: str) -> str:
    """Convert agent name to a Python variable name."""
    return agent_name.lower().replace(" ", "_").replace("'", "").replace("-", "_")


def _cr06_code_remediation(bp: dict) -> str:
    """Build code-based remediation for CR06 bypass findings."""
    downstream_var = _to_var_name(bp["downstream_agent"])
    return (
        f"Fix — Remove direct data access from downstream agent:\n"
        f"  {downstream_var} = Agent(\n"
        f"      role=\"{bp['downstream_agent']}\",\n"
        f"-     tools=[{bp['data_source']}, ...],\n"
        f"+     tools=[...],  # remove direct {bp['data_source']} access\n"
        f"  )\n\n"
        f"Or — add validation on the direct read:\n"
        f"  task = Task(\n"
        f"      agent={downstream_var},\n"
        f"+     output_pydantic=ValidatedInput,\n"
        f"  )"
    )


def _build_cr05_evidence(br, agent_list: str, ext_list: str, result: ScanResult) -> list[str]:
    """Build CR05 evidence with file paths for developer navigation."""
    evidence = [
        f"Crew: {br.crew_name}" if br.crew_name else "(no crew)",
        f"Shared by: {agent_list}",
    ]
    # Add file paths early so they survive evidence limiting
    added_files: set[str] = set()
    crew_obj = next((c for c in result.crew_definitions if c.name == br.crew_name), None)
    if crew_obj and crew_obj.source_file:
        evidence.append(crew_obj.source_file)
        added_files.add(crew_obj.source_file)
    # Match agents by name or role (labels come from graph node roles)
    label_set = set(br.affected_agent_labels)
    for agent_def in result.agent_definitions:
        if (agent_def.name in label_set or agent_def.role in label_set) and agent_def.source_file:
            if agent_def.source_file not in added_files:
                evidence.append(agent_def.source_file)
                added_files.add(agent_def.source_file)
                break
    if ext_list:
        evidence.append(f"Downstream: {ext_list}")
    return evidence


def _generate_blast_radius_findings(result: ScanResult) -> list[Finding]:
    """Generate STRATUM-CR05 findings from blast radius analysis — one per (tool, crew)."""
    findings: list[Finding] = []
    for br in result.blast_radii:
        if br.agent_count < 2:
            continue

        if br.agent_count >= 3 and br.external_count >= 1:
            severity = Severity.CRITICAL
        elif br.agent_count >= 2:
            severity = Severity.HIGH
        else:
            continue

        agent_list = ", ".join(br.affected_agent_labels[:6])
        ext_list = ", ".join(br.downstream_external_labels[:4])
        crew_context = f" in crew '{br.crew_name}'" if br.crew_name else ""

        fan_lines = [f"{br.source_label} (shared tool{crew_context})"]
        for i, alabel in enumerate(br.affected_agent_labels):
            prefix = "  L--> " if i == len(br.affected_agent_labels) - 1 else "  |--> "
            fan_lines.append(f"{prefix}{alabel}")
        fan_diagram = "\n".join(fan_lines)

        findings.append(Finding(
            id="STRATUM-CR05",
            severity=severity,
            confidence=Confidence.CONFIRMED,
            category=RiskCategory.COMPOUNDING,
            title=(
                f"Shared tool blast radius: {br.source_label} -> "
                f"{br.agent_count} agents{crew_context}"
            ),
            path=fan_diagram,
            description=(
                f"{br.source_label} feeds {br.agent_count} agents{crew_context} -- "
                f"blast radius: {br.external_count} external services. "
                f"If {br.source_label} returns poisoned data (prompt injection in scraped "
                f"content), {br.agent_count} agents are compromised simultaneously within "
                f"the same execution context. Each has independent downstream actions, so a "
                f"single point of compromise fans out to {br.external_count} external services."
            ),
            evidence=_build_cr05_evidence(br, agent_list, ext_list, result),
            scenario=(
                f"A single poisoned input to {br.source_label} would compromise your "
                f"{br.crew_name + ' pipeline' if br.crew_name else 'pipeline'}: {agent_list}."
            ),
            business_context=(
                "This finding exists because the graph traced fan-out from one shared tool "
                "within a single execution context. No checklist produces it."
            ),
            remediation=(
                f"Option 1 -- Add input validation on the shared tool:\n"
                f"  class Validated{br.source_label.replace(' ', '')}(BaseTool):\n"
                f"      def _run(self, input: str) -> str:\n"
                f"          raw = {br.source_label.replace(' ', '')}()._run(input)\n"
                f"          if contains_injection_patterns(raw):\n"
                f"              raise ValueError('Suspicious content detected')\n"
                f"          return raw\n\n"
                f"Option 2 -- Give each agent its own tool instance"
            ),
            effort="med",
            finding_class="compounding",
            owasp_id="ASI01",
            owasp_name="Agent Goal Hijacking",
            crew_id=br.crew_name,
        ))

    # Sort by severity (CRITICAL first), then agent count
    findings.sort(key=lambda f: (f.severity != Severity.CRITICAL, -len(f.evidence)), reverse=False)

    # Assign sub-IDs: STRATUM-CR05, STRATUM-CR05.1, STRATUM-CR05.2
    for i, f in enumerate(findings):
        f.id = f"STRATUM-CR05{'.' + str(i) if i > 0 else ''}"

    return findings[:3]  # Cap at 3 per-crew findings


def _generate_bypass_findings(result: ScanResult) -> list[Finding]:
    """Generate STRATUM-CR06 findings from control bypass analysis."""
    bypasses = getattr(result, '_control_bypasses', [])
    if not bypasses:
        return []

    findings: list[Finding] = []
    seen_pairs: set[tuple[str, str]] = set()

    for bp in bypasses:
        pair = (bp["upstream_agent"], bp["downstream_agent"])
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)

        findings.append(Finding(
            id="STRATUM-CR06",
            severity=Severity.HIGH,
            confidence=Confidence.PROBABLE,
            category=RiskCategory.COMPOUNDING,
            title=(
                f"'{bp['downstream_agent']}' bypasses '{bp['upstream_agent']}' "
                f"-- reads {bp['data_source']} directly"
            ),
            path=(
                f"{bp['data_source']} --> {bp['upstream_agent']} (intended filter)\n"
                f"{bp['data_source']} --> {bp['downstream_agent']} (direct access, bypassing filter)"
            ),
            description=(
                f"{bp['upstream_agent']} is supposed to filter input from "
                f"{bp['data_source']}, but {bp['downstream_agent']} reads "
                f"{bp['data_source']} directly via the same tool. The filter agent "
                f"doesn't sit on the data path -- it runs in parallel, not as a gate."
            ),
            evidence=[
                f"Crew: {bp['crew_name']}",
                f"Shared source: {bp['data_source']}",
            ],
            scenario=(
                f"Malicious content in {bp['data_source']} reaches "
                f"{bp['downstream_agent']} unfiltered regardless of what "
                f"{bp['upstream_agent']} does. The filter is architecturally irrelevant."
            ),
            business_context=(
                "The control exists but data flows around it. This is worse than no "
                "control -- it creates a false sense of security."
            ),
            remediation=_cr06_code_remediation(bp),
            effort="med",
            finding_class="compounding",
            owasp_id="ASI05",
            owasp_name="Insufficient Sandboxing",
            crew_id=bp.get("crew_name", ""),
        ))

    # Assign sub-IDs: STRATUM-CR06, STRATUM-CR06.1, etc.
    for i, f in enumerate(findings):
        f.id = f"STRATUM-CR06{'.' + str(i) if i > 0 else ''}"

    return findings[:3]  # Cap at 3 per-crew findings
