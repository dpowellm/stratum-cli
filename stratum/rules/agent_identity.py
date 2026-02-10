"""Agent identity rules.

Detects shared credentials, missing identity, and human credential usage.
"""
from __future__ import annotations

import ast
import logging

from stratum.models import (
    Confidence, Finding, RiskCategory, Severity,
)
from stratum.knowledge.learning_patterns import (
    MODEL_PROVIDERS, IDENTITY_PARAMS, HUMAN_CREDENTIAL_PATTERNS,
    API_KEY_PATTERNS,
)
from stratum.research.owasp import get_owasp

logger = logging.getLogger(__name__)


def evaluate(
    py_files: list[tuple[str, str]],
    telemetry_context: dict,
) -> tuple[list[Finding], dict]:
    """Run agent identity rules.

    Returns (findings, context).
    """
    # Detect agent scopes: functions/classes that instantiate LLM clients
    agent_scopes: list[dict] = []

    for file_path, content in py_files:
        try:
            tree = ast.parse(content)
        except SyntaxError:
            continue

        file_imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    file_imports.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                file_imports.add(node.module.split(".")[0])

        # Check for model provider imports
        model_libs = set()
        for provider_key in MODEL_PROVIDERS:
            top = provider_key.split(".")[0]
            if top in file_imports:
                model_libs.add(top)

        if not model_libs:
            continue

        # Collect module-level credential vars
        module_creds: list[str] = []
        for node in tree.body:
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call):
                    env_var = _extract_env_var(sub)
                    if env_var and _is_api_key_var(env_var):
                        module_creds.append(env_var)

        # Find agent scopes: functions that use LLM client calls
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scope_info = _analyze_agent_scope(node, file_path, model_libs, content)
                if scope_info:
                    # Inherit module-level credentials if scope has none
                    if not scope_info["credential_vars"] and module_creds:
                        scope_info["credential_vars"] = list(module_creds)
                    agent_scopes.append(scope_info)

    context = {
        "agent_scopes": agent_scopes,
        "agent_count": len(agent_scopes),
        "has_shared_credentials": False,
        "all_have_identity": False,
    }

    findings: list[Finding] = []

    if len(agent_scopes) < 2:
        # Check for identity even with single agent
        if agent_scopes and not agent_scopes[0].get("has_identity"):
            # Don't fire IDENTITY-002 for single agent
            pass
        context["all_have_identity"] = all(s.get("has_identity") for s in agent_scopes) if agent_scopes else True
        return findings, context

    # IDENTITY-001: Shared credentials
    # Group agent scopes by credential env var
    cred_groups: dict[str, list[dict]] = {}
    for scope in agent_scopes:
        for cred in scope.get("credential_vars", []):
            cred_groups.setdefault(cred, []).append(scope)

    for cred_var, scopes in cred_groups.items():
        if len(scopes) >= 2:
            scope_names = [s["name"] for s in scopes]
            locations = [f"{s['file']}:{s['name']}" for s in scopes]
            owasp_id, owasp_name = get_owasp("IDENTITY-001")
            findings.append(Finding(
                id="IDENTITY-001",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                category=RiskCategory.SECURITY,
                title="Multiple agents share the same API credentials",
                path=f"{' and '.join(scope_names)} use {cred_var}",
                description=(
                    f"Agents in {', '.join(locations)} all use {cred_var}. Shared credentials make "
                    f"it impossible to: attribute API calls to specific agents, audit "
                    f"per-agent behavior, revoke one agent's access without disrupting "
                    f"others, or enforce per-agent rate limits."
                ),
                evidence=locations,
                remediation=(
                    f"Use per-agent API keys: "
                    f"agent_a_key = os.getenv('{cred_var}_AGENT_A'), "
                    f"agent_b_key = os.getenv('{cred_var}_AGENT_B')"
                ),
                owasp_id=owasp_id,
                owasp_name=owasp_name,
                finding_class="governance",
            ))
            context["has_shared_credentials"] = True
            break  # One finding

    # IDENTITY-002: No unique agent identity
    agents_without_identity = [s for s in agent_scopes if not s.get("has_identity")]
    if agents_without_identity:
        n = len(agents_without_identity)
        owasp_id, owasp_name = get_owasp("IDENTITY-002")
        findings.append(Finding(
            id="IDENTITY-002",
            severity=Severity.MEDIUM,
            confidence=Confidence.PROBABLE,
            category=RiskCategory.COMPLIANCE,
            title="Agent has no unique identifier",
            path=f"{n} agent{'s' if n != 1 else ''} ha{'ve' if n != 1 else 's'} no agent_id or name in configuration",
            description=(
                f"No agent_id, name, or unique identifier found in agent configuration. "
                f"Audit trails cannot distinguish between agents."
            ),
            evidence=[f"{s['file']}:{s['name']}" for s in agents_without_identity[:3]],
            remediation=(
                "Add a unique identifier to each agent: "
                "agent = Agent(name='customer_support_v2', agent_id=str(uuid.uuid4())[:8])"
            ),
            owasp_id=owasp_id,
            owasp_name=owasp_name,
            finding_class="governance",
        ))

    # IDENTITY-003: Human credentials on agent
    for scope in agent_scopes:
        for cred in scope.get("credential_vars", []):
            upper = cred.upper()
            if any(pat in upper for pat in HUMAN_CREDENTIAL_PATTERNS):
                owasp_id, owasp_name = get_owasp("IDENTITY-003")
                findings.append(Finding(
                    id="IDENTITY-003",
                    severity=Severity.HIGH,  # Will be gated to MEDIUM by engine (HEURISTIC)
                    confidence=Confidence.HEURISTIC,
                    category=RiskCategory.SECURITY,
                    title="Agent may be using human user credentials",
                    path=f"{scope['name']} uses {cred}",
                    description=(
                        f"Credential variable {cred} suggests human user credentials "
                        f"rather than a service identity. The agent inherits the human's "
                        f"full permission scope."
                    ),
                    evidence=[f"{scope['file']}:{scope['name']}"],
                    remediation=(
                        "Create a dedicated service account / API key for the agent "
                        "with least-privilege permissions."
                    ),
                    owasp_id=owasp_id,
                    owasp_name=owasp_name,
                    finding_class="governance",
                ))
                break

    context["all_have_identity"] = all(s.get("has_identity") for s in agent_scopes)

    return findings, context


def _analyze_agent_scope(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    file_path: str,
    model_libs: set[str],
    content: str,
) -> dict | None:
    """Analyze a function scope for agent characteristics."""
    # Check if this function makes LLM API calls
    has_llm_call = False
    credential_vars: list[str] = []
    has_identity = False

    for node in ast.walk(func_node):
        # Detect LLM API calls (chat.completions.create, etc.)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            method = node.func.attr
            if method in ("create", "generate", "invoke", "chat", "complete"):
                has_llm_call = True

            # Check for identity parameters
            for kw in node.keywords:
                if kw.arg in IDENTITY_PARAMS:
                    has_identity = True

        # Detect env var access for API keys
        if isinstance(node, ast.Call):
            env_var = _extract_env_var(node)
            if env_var and _is_api_key_var(env_var):
                credential_vars.append(env_var)

    if not has_llm_call:
        return None

    # Also check module-level env var references that this scope would inherit
    # (the scope uses a module-level client that uses env vars)

    return {
        "file": file_path,
        "name": func_node.name,
        "credential_vars": credential_vars,
        "has_identity": has_identity,
    }


def _extract_env_var(node: ast.Call) -> str:
    """Extract env var name from os.getenv/os.environ.get calls."""
    func = node.func
    if isinstance(func, ast.Attribute):
        # os.getenv("X") or os.environ.get("X")
        if func.attr in ("getenv", "get"):
            if node.args and isinstance(node.args[0], ast.Constant):
                return str(node.args[0].value)
    # os.environ["X"]
    if isinstance(node, ast.Subscript):
        if isinstance(node.slice, ast.Constant):
            return str(node.slice.value)
    return ""


def _is_api_key_var(var_name: str) -> bool:
    """Check if an env var name looks like an API key."""
    upper = var_name.upper()
    return any(pat in upper for pat in API_KEY_PATTERNS)
