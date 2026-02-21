"""Detect LangGraph StateGraph definitions and convert to Stratum's model.

LangGraph patterns:
  graph = StateGraph(AgentState)
  graph.add_node("researcher", research_fn)
  graph.add_node("writer", write_fn)
  graph.add_edge("researcher", "writer")
  graph.add_edge(START, "researcher")
  graph.add_conditional_edges("writer", route_fn, {"continue": "researcher", "end": END})
  compiled = graph.compile(checkpointer=MemorySaver(), interrupt_before=["writer"])

Mapping:
  StateGraph       -> CrewDefinition (one graph = one crew)
  add_node         -> AgentDefinition (one node = one agent)
  add_edge         -> AgentRelationship (feeds_into)
  conditional_edge -> AgentRelationship (feeds_into, conditional=True)
  compile(checkpointer=) -> has_checkpointing = True
  compile(interrupt_before=) -> has_hitl = True
  Tool bindings on node functions -> agent.tool_names
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from stratum.graph.agents import AgentDefinition
from stratum.models import AgentRelationship, CrewDefinition


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_langgraph(
    asts: dict[str, ast.Module],
    files: list[str],
) -> tuple[list[CrewDefinition], list[AgentDefinition], list[AgentRelationship]]:
    """Parse LangGraph StateGraph definitions from pre-parsed ASTs.

    Returns (crews, agents, relationships).
    """
    all_crews: list[CrewDefinition] = []
    all_agents: list[AgentDefinition] = []
    all_rels: list[AgentRelationship] = []

    for filepath, tree in asts.items():
        graphs = _find_stategraphs(tree, filepath)

        for graph in graphs:
            _resolve_graph_structure(tree, graph)

            crew = CrewDefinition(
                name=graph.var_name or f"graph_{_filepath_stem(filepath)}",
                framework="LangGraph",
                agent_names=[n.name for n in graph.nodes],
                process_type="graph",
                source_file=filepath,
                has_manager=False,
                delegation_enabled=False,
            )
            all_crews.append(crew)

            for node in graph.nodes:
                tool_names = _detect_node_tools(tree, node.func_name, filepath)
                agent = AgentDefinition(
                    name=node.name,
                    role=node.name,
                    framework="LangGraph",
                    source_file=filepath,
                    tool_names=tool_names,
                )
                all_agents.append(agent)

            for edge in graph.edges:
                if edge.source in ("__start__", "START") or edge.target in ("__end__", "END"):
                    continue
                rel = AgentRelationship(
                    source_agent=edge.source,
                    target_agent=edge.target,
                    relationship_type="delegates_to",
                    shared_resource="",
                    source_file=filepath,
                )
                all_rels.append(rel)

    return all_crews, all_agents, all_rels


# ---------------------------------------------------------------------------
# Internal data classes
# ---------------------------------------------------------------------------

@dataclass
class _LangGraphDef:
    var_name: str
    source_file: str
    state_class: str
    nodes: list[_GraphNode] = field(default_factory=list)
    edges: list[_GraphEdge] = field(default_factory=list)
    has_checkpointer: bool = False
    interrupt_before: list[str] = field(default_factory=list)


@dataclass
class _GraphNode:
    name: str
    func_name: str | None = None


@dataclass
class _GraphEdge:
    source: str
    target: str


# ---------------------------------------------------------------------------
# AST visitors
# ---------------------------------------------------------------------------

def _find_stategraphs(tree: ast.Module, filepath: str) -> list[_LangGraphDef]:
    """Find all StateGraph(...) instantiations."""
    graphs: list[_LangGraphDef] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        call = node.value
        if not isinstance(call, ast.Call):
            continue

        func_name = _get_call_name(call)
        if func_name != "StateGraph":
            continue

        var_name = _get_assign_target(node)
        graphs.append(_LangGraphDef(
            var_name=var_name,
            source_file=filepath,
            state_class=_get_first_arg_name(call),
        ))

    return graphs


def _resolve_graph_structure(tree: ast.Module, graph: _LangGraphDef) -> None:
    """Walk the AST to find add_node, add_edge, add_conditional_edges,
    and compile calls on this graph variable."""
    var = graph.var_name

    for node in ast.walk(tree):
        call = None

        # Expression statement: graph.add_node(...)
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call = node.value
        # Assignment: compiled = graph.compile(...)
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            call = node.value

        if call is None:
            continue

        method = _get_method_call(call, var)
        if method is None:
            continue

        if method == "add_node":
            node_name = _get_string_arg(call, 0)
            func_name = _get_arg_name(call, 1)
            if node_name:
                graph.nodes.append(_GraphNode(name=node_name, func_name=func_name))

        elif method == "add_edge":
            src = _get_string_or_const(call, 0)
            dst = _get_string_or_const(call, 1)
            if src and dst:
                graph.edges.append(_GraphEdge(source=src, target=dst))

        elif method == "add_conditional_edges":
            src = _get_string_or_const(call, 0)
            # Third arg is the routing dict: {"continue": "node_a", "end": END}
            mapping = _get_dict_values(call, 2)
            for target in mapping:
                if target not in ("__end__", "END"):
                    graph.edges.append(_GraphEdge(source=src, target=target))

        elif method == "compile":
            for kw in call.keywords:
                if kw.arg == "checkpointer" and not _is_none(kw.value):
                    graph.has_checkpointer = True
                if kw.arg == "interrupt_before":
                    graph.interrupt_before = _extract_string_list(kw.value)


def _detect_node_tools(
    tree: ast.Module, func_name: str | None, filepath: str,
) -> list[str]:
    """Find tools bound to a LangGraph node function.

    Patterns:
      def research_fn(state):
          tools = [search_tool, wiki_tool]
          result = model.bind_tools(tools).invoke(...)

    Or:
      research_fn = create_react_agent(model, tools=[...])
    """
    if not func_name:
        return []

    tool_names: list[str] = []

    # Resolve module-level variable assignments: search_tool = TavilySearchResults()
    module_vars: dict[str, str] = {}
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and isinstance(node.value, ast.Call):
                name = _get_call_name(node.value)
                if name:
                    module_vars[target.id] = name
        # Also handle @tool decorated functions
        if isinstance(node, ast.FunctionDef):
            for d in node.decorator_list:
                if (isinstance(d, ast.Name) and d.id == "tool") or (
                    isinstance(d, ast.Attribute) and d.attr == "tool"
                ):
                    module_vars[node.name] = node.name

    for node in ast.walk(tree):
        # Pattern 1: function definition with tool usage inside
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            # Resolve local variable assignments
            local_vars: dict[str, str] = {}
            local_lists: dict[str, list[str]] = {}
            for child in ast.walk(node):
                if isinstance(child, ast.Assign) and len(child.targets) == 1:
                    target = child.targets[0]
                    if isinstance(target, ast.Name):
                        if isinstance(child.value, ast.Call):
                            name = _get_call_name(child.value)
                            if name:
                                local_vars[target.id] = name
                        elif isinstance(child.value, ast.List):
                            # tools = [search_tool, wiki_tool, query_database]
                            items: list[str] = []
                            for elt in child.value.elts:
                                if isinstance(elt, ast.Name):
                                    # Resolve to module-level var or keep name
                                    items.append(module_vars.get(elt.id, elt.id))
                                elif isinstance(elt, ast.Call):
                                    name = _get_call_name(elt)
                                    if name:
                                        items.append(name)
                            local_lists[target.id] = items

            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    name = _get_call_name(child)
                    if name and name.endswith("Tool"):
                        tool_names.append(name)
                    # bind_tools([...]) or bind_tools(tools_var)
                    if name == "bind_tools" and child.args:
                        arg = child.args[0]
                        if isinstance(arg, ast.List):
                            tool_names.extend(_extract_tool_names_from_list(child.args))
                        elif isinstance(arg, ast.Name):
                            # Resolve variable to its list contents
                            resolved = local_lists.get(arg.id, [])
                            tool_names.extend(resolved)

        # Pattern 2: assignment to func_name using create_react_agent etc.
        if isinstance(node, ast.Assign) and _get_assign_target(node) == func_name:
            if isinstance(node.value, ast.Call):
                for kw in node.value.keywords:
                    if kw.arg == "tools":
                        tool_names.extend(_extract_tool_names_from_list([kw.value]))

    return list(set(tool_names))


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

def _get_call_name(node: ast.Call) -> str:
    """Get the simple name from a Call node (e.g. StateGraph, Agent)."""
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


def _get_first_arg_name(call: ast.Call) -> str:
    """Get the name of the first positional argument."""
    if call.args:
        arg = call.args[0]
        if isinstance(arg, ast.Name):
            return arg.id
    return ""


def _get_method_call(call: ast.Call, var_name: str) -> str | None:
    """If call is var_name.method(...), return the method name."""
    if isinstance(call.func, ast.Attribute):
        if isinstance(call.func.value, ast.Name) and call.func.value.id == var_name:
            return call.func.attr
    return None


def _get_string_arg(call: ast.Call, index: int) -> str:
    """Get the string value of a positional argument."""
    if len(call.args) > index:
        arg = call.args[index]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value
    return ""


def _get_arg_name(call: ast.Call, index: int) -> str | None:
    """Get the name/identifier of a positional argument."""
    if len(call.args) > index:
        arg = call.args[index]
        if isinstance(arg, ast.Name):
            return arg.id
        if isinstance(arg, ast.Attribute):
            return arg.attr
    return None


def _get_string_or_const(call: ast.Call, index: int) -> str:
    """Get a string literal or well-known constant (START, END) at argument index."""
    if len(call.args) <= index:
        return ""
    arg = call.args[index]
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return arg.value
    if isinstance(arg, ast.Name):
        # START → __start__, END → __end__
        if arg.id == "START":
            return "__start__"
        if arg.id == "END":
            return "__end__"
        return arg.id
    if isinstance(arg, ast.Attribute):
        return arg.attr
    return ""


def _get_dict_values(call: ast.Call, index: int) -> list[str]:
    """Get string values from a dict literal argument."""
    values: list[str] = []
    if len(call.args) > index:
        arg = call.args[index]
        if isinstance(arg, ast.Dict):
            for v in arg.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    values.append(v.value)
                elif isinstance(v, ast.Name):
                    if v.id == "END":
                        values.append("__end__")
                    else:
                        values.append(v.id)
    # Also check keyword argument for path_map
    for kw in call.keywords:
        if kw.arg == "path_map" and isinstance(kw.value, ast.Dict):
            for v in kw.value.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    values.append(v.value)
                elif isinstance(v, ast.Name):
                    if v.id == "END":
                        values.append("__end__")
                    else:
                        values.append(v.id)
    return values


def _is_none(node: ast.expr) -> bool:
    """Check if node is None."""
    return isinstance(node, ast.Constant) and node.value is None


def _extract_string_list(node: ast.expr) -> list[str]:
    """Extract a list of strings from a list literal."""
    if isinstance(node, ast.List):
        return [
            elt.value for elt in node.elts
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
        ]
    return []


def _extract_tool_names_from_list(args: list[ast.expr]) -> list[str]:
    """Extract tool names from argument list (bind_tools args)."""
    names: list[str] = []
    for arg in args:
        if isinstance(arg, ast.List):
            for elt in arg.elts:
                if isinstance(elt, ast.Call):
                    name = _get_call_name(elt)
                    if name:
                        names.append(name)
                elif isinstance(elt, ast.Name):
                    names.append(elt.id)
        elif isinstance(arg, ast.Name):
            # Variable reference to a tools list — can't resolve statically
            pass
    return names


def _filepath_stem(filepath: str) -> str:
    """Get the stem of a filepath (filename without extension)."""
    return Path(filepath).stem
