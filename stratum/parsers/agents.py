"""Extract agent relationships from CrewAI, LangGraph, and other frameworks."""
from __future__ import annotations

import ast
from pathlib import Path

from stratum.models import AgentRelationship, CrewDefinition


def extract_crew_definitions(
    python_files: list[tuple[str, str, ast.Module]],
) -> list[CrewDefinition]:
    """Extract crew/flow definitions that group agents together.

    For CrewAI:
    - Find Crew() calls with agents=[...] and tasks=[...]
    - Detect process= parameter (sequential/hierarchical)
    - Find @CrewBase decorated classes with @agent/@task methods

    python_files: list of (file_path, content, ast_tree) triples.
    """
    crews: list[CrewDefinition] = []
    for file_path, content, tree in python_files:
        crews.extend(_extract_crewai_crews(file_path, content, tree))
    return crews


def detect_shared_tools(
    agent_profiles: list,
    crew_definitions: list[CrewDefinition] | None = None,
) -> list[AgentRelationship]:
    """Find agents that share the same tool — a compounding risk signal.

    When *crew_definitions* is provided, only pairs of agents that belong to
    the **same crew** are reported.  Agents not in any crew are allowed to
    match with any other agent (backward-compat for non-crew projects).
    """
    # Build agent → set-of-crews lookup
    agent_crews: dict[str, set[str]] = {}
    if crew_definitions:
        for crew in crew_definitions:
            for name in crew.agent_names:
                agent_crews.setdefault(name, set()).add(crew.name)

    tool_to_agents: dict[str, list[str]] = {}
    for agent in agent_profiles:
        for tool in agent.tool_names:
            tool_to_agents.setdefault(tool, []).append(agent.name)

    relationships: list[AgentRelationship] = []
    for tool, agents in tool_to_agents.items():
        if len(agents) > 1:
            for i, a in enumerate(agents):
                for b in agents[i + 1:]:
                    # Skip cross-crew pairs when crew info is available
                    if crew_definitions:
                        a_crews = agent_crews.get(a, set())
                        b_crews = agent_crews.get(b, set())
                        # Both have crew assignments → must share at least one
                        if a_crews and b_crews and not (a_crews & b_crews):
                            continue
                    relationships.append(AgentRelationship(
                        source_agent=a,
                        target_agent=b,
                        relationship_type="shares_tool",
                        shared_resource=tool,
                    ))
    return relationships


def detect_cross_crew_flows(
    crew_defs: list[CrewDefinition],
    python_files: list[tuple[str, str]],
) -> list[AgentRelationship]:
    """Detect flows between crews via Flow classes (@start, @listen, @router).

    Heuristic: Look for classes with @start/@listen decorators (CrewAI Flows)
    that reference multiple crew classes.
    """
    relationships: list[AgentRelationship] = []

    for file_path, content in python_files:
        try:
            tree = ast.parse(content)
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue

            start_methods: list[ast.FunctionDef] = []
            listen_methods: list[ast.FunctionDef] = []
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if _has_decorator(item, "start"):
                        start_methods.append(item)
                    if _has_decorator(item, "listen"):
                        listen_methods.append(item)

            for listener in listen_methods:
                source_crew = _extract_listen_source(listener)
                target_crew = _infer_crew_from_method_body(listener, tree)
                if source_crew and target_crew and source_crew != target_crew:
                    relationships.append(AgentRelationship(
                        source_agent=source_crew,
                        target_agent=target_crew,
                        relationship_type="feeds_into",
                        source_file=file_path,
                    ))

    return relationships


# ---------------------------------------------------------------------------
# CrewAI crew extraction
# ---------------------------------------------------------------------------

def _extract_crewai_crews(
    file_path: str, content: str, tree: ast.Module,
) -> list[CrewDefinition]:
    crews: list[CrewDefinition] = []

    # Pattern 1: Direct Crew() instantiation
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_name(node.func, "Crew"):
            agents = _extract_list_arg(node, "agents")
            process = _extract_keyword_str(node, "process", default="sequential")
            has_manager = _has_keyword(node, "manager_llm") or _has_keyword(node, "manager_agent")

            if agents:
                crews.append(CrewDefinition(
                    name=_infer_crew_name(file_path),
                    framework="CrewAI",
                    agent_names=agents,
                    process_type="hierarchical" if has_manager else process,
                    source_file=file_path,
                    has_manager=has_manager,
                    delegation_enabled=any(
                        _agent_allows_delegation(tree, a) for a in agents
                    ),
                ))

    # Pattern 2: @CrewBase class with @agent methods (CrewAI v2 pattern)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and _has_decorator(node, "CrewBase"):
            agent_methods = [
                n.name for n in node.body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and _has_decorator(n, "agent")
            ]
            if agent_methods:
                # Check @crew method for process type
                process_type = "sequential"
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if _has_decorator(item, "crew"):
                            process_type = _detect_process_in_method(item)

                crews.append(CrewDefinition(
                    name=node.name,
                    framework="CrewAI",
                    agent_names=agent_methods,
                    process_type=process_type,
                    source_file=file_path,
                ))

    return crews


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

def _is_name(node: ast.expr, name: str) -> bool:
    if isinstance(node, ast.Name):
        return node.id == name
    if isinstance(node, ast.Attribute):
        return node.attr == name
    return False


def _has_decorator(node: ast.AST, name: str) -> bool:
    decorators = getattr(node, 'decorator_list', [])
    for d in decorators:
        if isinstance(d, ast.Name) and d.id == name:
            return True
        if isinstance(d, ast.Attribute) and d.attr == name:
            return True
        if isinstance(d, ast.Call):
            if isinstance(d.func, ast.Name) and d.func.id == name:
                return True
            if isinstance(d.func, ast.Attribute) and d.func.attr == name:
                return True
    return False


def _has_keyword(node: ast.Call, name: str) -> bool:
    return any(kw.arg == name for kw in node.keywords)


def _extract_keyword_str(node: ast.Call, name: str, default: str = "") -> str:
    for kw in node.keywords:
        if kw.arg == name:
            if isinstance(kw.value, ast.Constant):
                return str(kw.value.value)
            # Process.sequential → "sequential"
            if isinstance(kw.value, ast.Attribute):
                return kw.value.attr.lower()
    return default


def _extract_list_arg(node: ast.Call, name: str) -> list[str]:
    """Extract names from a keyword list argument like agents=[a, b, c]."""
    for kw in node.keywords:
        if kw.arg == name and isinstance(kw.value, ast.List):
            names: list[str] = []
            for elt in kw.value.elts:
                if isinstance(elt, ast.Name):
                    names.append(elt.id)
                elif isinstance(elt, ast.Call):
                    if isinstance(elt.func, ast.Name):
                        names.append(elt.func.id)
                    elif isinstance(elt.func, ast.Attribute):
                        names.append(elt.func.attr)
                elif isinstance(elt, ast.Constant):
                    names.append(str(elt.value))
            return names
    return []


def _infer_crew_name(file_path: str) -> str:
    """Infer crew name from file path."""
    p = Path(file_path)
    # Try parent directory name first (common: crews/my_crew/src/crew.py)
    for part in reversed(p.parts[:-1]):
        if part not in ("src", "config", "tools", "tests", "__pycache__"):
            return part
    return p.stem


def _agent_allows_delegation(tree: ast.Module, agent_var: str) -> bool:
    """Check if an agent has allow_delegation=True."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_name(node.func, "Agent"):
            for kw in node.keywords:
                if kw.arg == "allow_delegation":
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        return True
    return False


def _detect_process_in_method(method: ast.FunctionDef) -> str:
    """Detect process type from a @crew method body."""
    for node in ast.walk(method):
        if isinstance(node, ast.Call) and _is_name(node.func, "Crew"):
            return _extract_keyword_str(node, "process", default="sequential")
    return "sequential"


def _extract_listen_source(listener: ast.FunctionDef) -> str:
    """Extract the source method name from @listen(method_name)."""
    for d in listener.decorator_list:
        if isinstance(d, ast.Call) and _is_name(d.func, "listen"):
            if d.args:
                arg = d.args[0]
                if isinstance(arg, ast.Name):
                    return arg.id
                if isinstance(arg, ast.Constant):
                    return str(arg.value)
    return ""


def _infer_crew_from_method_body(method: ast.FunctionDef, tree: ast.Module) -> str:
    """Infer which crew a method invokes from its body (e.g., crew.kickoff())."""
    for node in ast.walk(method):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "kickoff":
                if isinstance(node.func.value, ast.Name):
                    return node.func.value.id
                if isinstance(node.func.value, ast.Call):
                    if isinstance(node.func.value.func, ast.Name):
                        return node.func.value.func.id
    return ""
