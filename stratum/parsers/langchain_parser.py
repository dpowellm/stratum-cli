"""Detect LangChain agent patterns and convert to Stratum's model.

Patterns:
  1. AgentExecutor(agent=..., tools=[...])
  2. create_react_agent(llm, tools, prompt)
  3. create_openai_functions_agent(llm, tools, prompt)
  4. create_tool_calling_agent(llm, tools)
  5. initialize_agent(tools, llm, agent=AgentType.ZERO_SHOT_REACT)

Each AgentExecutor/create_*_agent = one agent.
Multiple in the same file or project = multi-agent system.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from stratum.graph.agents import AgentDefinition
from stratum.models import AgentRelationship, CrewDefinition


AGENT_FACTORY_FUNCTIONS = {
    "create_react_agent",
    "create_openai_functions_agent",
    "create_tool_calling_agent",
    "create_openai_tools_agent",
    "create_structured_chat_agent",
    "create_json_chat_agent",
    "create_xml_agent",
    "initialize_agent",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_langchain_agents(
    asts: dict[str, ast.Module],
    files: list[str],
) -> tuple[list[CrewDefinition], list[AgentDefinition], list[AgentRelationship]]:
    """Parse LangChain agent definitions from pre-parsed ASTs.

    Returns (crews, agents, relationships).

    LangChain doesn't have crews/graphs, so we create synthetic groupings:
    - All agents in the same file = one "crew" (they likely work together)
    - If only one agent in the whole project, it's a single-agent crew
    """
    # First pass: find all agent definitions across all files
    file_agents: dict[str, list[_LCAgentDef]] = {}

    for filepath, tree in asts.items():
        agents_in_file = _find_agents_in_file(tree, filepath)
        if agents_in_file:
            file_agents[filepath] = agents_in_file

    # Second pass: group into synthetic crews
    all_crews: list[CrewDefinition] = []
    all_agents: list[AgentDefinition] = []
    all_rels: list[AgentRelationship] = []

    for filepath, agents_in_file in file_agents.items():
        stem = _filepath_stem(filepath)

        if len(agents_in_file) > 1:
            # Multiple agents in one file → they're a system
            crew_name = f"{stem}_agents"
            process_type = "sequential"

            # Create feeds_into relationships based on definition order
            for i in range(len(agents_in_file) - 1):
                all_rels.append(AgentRelationship(
                    source_agent=agents_in_file[i].var_name,
                    target_agent=agents_in_file[i + 1].var_name,
                    relationship_type="feeds_into",
                    shared_resource="",
                    source_file=filepath,
                ))
        else:
            crew_name = f"{stem}_agent"
            process_type = "single"

        crew = CrewDefinition(
            name=crew_name,
            framework="LangChain",
            agent_names=[a.var_name for a in agents_in_file],
            process_type=process_type,
            source_file=filepath,
            has_manager=False,
            delegation_enabled=False,
        )
        all_crews.append(crew)

        for agent_def in agents_in_file:
            agent = AgentDefinition(
                name=agent_def.var_name,
                role=agent_def.var_name,
                framework="LangChain",
                source_file=filepath,
                tool_names=agent_def.tools,
            )
            all_agents.append(agent)

    # Cross-file agents: if agents in different files share tools, create shares_tool rels
    all_tool_owners: dict[str, list[str]] = {}
    for filepath, agents_in_file in file_agents.items():
        for agent_def in agents_in_file:
            for tool in agent_def.tools:
                all_tool_owners.setdefault(tool, []).append(agent_def.var_name)

    for tool_name, owners in all_tool_owners.items():
        if len(owners) >= 2:
            for i in range(len(owners)):
                for j in range(i + 1, len(owners)):
                    all_rels.append(AgentRelationship(
                        source_agent=owners[i],
                        target_agent=owners[j],
                        relationship_type="shares_tool",
                        shared_resource=tool_name,
                        source_file="",
                    ))

    return all_crews, all_agents, all_rels


# ---------------------------------------------------------------------------
# Internal data class
# ---------------------------------------------------------------------------

@dataclass
class _LCAgentDef:
    var_name: str
    agent_type: str
    tools: list[str] = field(default_factory=list)
    source_file: str = ""
    line: int = 0


# ---------------------------------------------------------------------------
# AST visitors
# ---------------------------------------------------------------------------

def _find_agents_in_file(tree: ast.Module, filepath: str) -> list[_LCAgentDef]:
    """Find all LangChain agent definitions in a single file."""
    agents: list[_LCAgentDef] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, ast.Call):
            continue

        call = node.value
        func_name = _get_call_name(call)
        var_name = _get_assign_target(node)

        # Pattern 1: AgentExecutor(agent=..., tools=[...])
        if func_name == "AgentExecutor":
            tools = _extract_tools_kwarg(call)
            agents.append(_LCAgentDef(
                var_name=var_name or "agent",
                agent_type="AgentExecutor",
                tools=tools,
                source_file=filepath,
                line=node.lineno,
            ))

        # Pattern 2: create_react_agent(...) and similar
        elif func_name in AGENT_FACTORY_FUNCTIONS:
            tools = _extract_tools_arg(call)
            agents.append(_LCAgentDef(
                var_name=var_name or func_name,
                agent_type=func_name,
                tools=tools,
                source_file=filepath,
                line=node.lineno,
            ))

    return agents


# ---------------------------------------------------------------------------
# Tool extraction helpers
# ---------------------------------------------------------------------------

def _extract_tools_kwarg(call: ast.Call) -> list[str]:
    """Extract tool names from tools=[...] keyword arg."""
    for kw in call.keywords:
        if kw.arg == "tools":
            return _extract_tool_names(kw.value)
    return []


def _extract_tools_arg(call: ast.Call) -> list[str]:
    """Extract tool names from positional or keyword tools arg."""
    # Most create_*_agent functions: create_react_agent(llm, tools, prompt)
    # tools is typically arg[1]
    if len(call.args) >= 2:
        return _extract_tool_names(call.args[1])
    return _extract_tools_kwarg(call)


def _extract_tool_names(node: ast.expr) -> list[str]:
    """Extract tool names from a list expression: [SearchTool(), CalcTool()]."""
    names: list[str] = []
    if isinstance(node, ast.List):
        for elt in node.elts:
            if isinstance(elt, ast.Call):
                name = _get_call_name(elt)
                if name:
                    names.append(name)
            elif isinstance(elt, ast.Name):
                names.append(elt.id)
    elif isinstance(node, ast.Name):
        # tools is a variable reference, can't resolve statically
        names.append(f"${node.id}")
    return names


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

def _get_call_name(node: ast.Call) -> str:
    """Get the simple name from a Call node."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""


def _get_assign_target(node: ast.Assign) -> str:
    """Get the target variable name from an assignment."""
    if node.targets and isinstance(node.targets[0], ast.Name):
        return node.targets[0].id
    return ""


def _filepath_stem(filepath: str) -> str:
    """Get the stem of a filepath (filename without extension)."""
    return Path(filepath).stem
