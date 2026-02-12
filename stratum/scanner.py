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
from stratum.rules.engine import Engine
from stratum.graph.builder import build_graph
from stratum.graph.models import NodeType, RiskPath
from stratum.graph.remediation import framework_remediation, framework_remediation_008, framework_remediation_010
from stratum.graph.agents import extract_agents_from_yaml, extract_agents_from_python

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
            # Merge tools from duplicate
            for t in ad.tool_names:
                if t not in existing.tool_names:
                    existing.tool_names.append(t)
    all_agent_defs = list(agent_dedup.values())

    # Extract crew definitions and agent relationships
    from stratum.parsers.agents import (
        extract_crew_definitions, detect_shared_tools, detect_cross_crew_flows,
    )
    # Build (file_path, content, ast_tree) triples for crew extraction
    py_files_with_ast: list[tuple[str, str, ast.Module]] = []
    for file_path, content in py_files:
        rel = os.path.relpath(file_path, abs_path)
        try:
            tree = ast.parse(content)
            py_files_with_ast.append((rel, content, tree))
        except SyntaxError:
            pass

    crew_definitions = extract_crew_definitions(py_files_with_ast)
    shared_tool_rels = detect_shared_tools(all_agent_defs)
    cross_crew_rels = detect_cross_crew_flows(
        crew_definitions, [(os.path.relpath(fp, abs_path), c) for fp, c in py_files],
    )
    all_agent_relationships = shared_tool_rels + cross_crew_rels

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
        if f.id == "STRATUM-008":
            f.remediation = framework_remediation_008(fw_list)
        elif f.id == "STRATUM-010":
            f.remediation = framework_remediation_010(fw_list)

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
    )

    # Build risk graph
    result.graph = build_graph(result)

    # Replace pairwise STRATUM-001 findings with graph-derived findings
    if result.graph and result.graph.uncontrolled_paths:
        graph_findings = []
        for risk_path in result.graph.uncontrolled_paths:
            finding = _graph_finding_for_path(
                risk_path, result.graph, result.detected_frameworks,
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

    # Merge new findings — consolidate duplicates per rule ID
    all_new_findings = business_findings + operational_findings + compounding_findings
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

    # Recalculate risk score with compounding bonuses
    all_findings_final = result.top_paths + result.signals
    compounding_bonus = 0
    if any(f.id == "STRATUM-CR01" for f in all_findings_final):
        compounding_bonus += 10
    if any(f.id == "STRATUM-CR02" for f in all_findings_final):
        compounding_bonus += 5
    if any(f.id == "STRATUM-CR03" for f in all_findings_final):
        compounding_bonus += 10
    result.risk_score = min(result.risk_score + compounding_bonus, 100)

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
) -> Finding | None:
    """Convert a RiskPath from the graph traversal into a Finding.

    Replaces the old pairwise rule match for STRATUM-001.
    """
    nodes = [graph.nodes[nid] for nid in risk_path.nodes]

    finding_id = "STRATUM-001"
    title = "Unguarded data-to-external path"

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
