"""Extract agent definitions from project files and add AGENT nodes to the graph."""
from __future__ import annotations

import ast
from dataclasses import dataclass, field


@dataclass
class AgentDefinition:
    """An agent defined in the project."""
    name: str                   # "email_filter", "email_responder"
    role: str                   # "Email Filter Agent"
    framework: str              # "CrewAI"
    source_file: str
    tool_names: list[str] = field(default_factory=list)


def extract_agents_from_yaml(yaml_content: str, file_path: str) -> list[AgentDefinition]:
    """Extract agent definitions from CrewAI-style YAML configs.

    Expected format:
    ```yaml
    email_filter:
      role: "Email Filter Agent"
      goal: "Filter emails"
      tools:
        - SerperDevTool
        - GmailGetThread
    ```
    """
    agents: list[AgentDefinition] = []
    try:
        import yaml
        doc = yaml.safe_load(yaml_content)
    except Exception:
        return []

    if not isinstance(doc, dict):
        return []

    for agent_key, agent_def in doc.items():
        if not isinstance(agent_def, dict):
            continue

        # Must have at least 'role' or 'goal' to be an agent definition
        if not any(k in agent_def for k in ("role", "goal", "backstory", "tools")):
            continue

        tools: list[str] = []
        if "tools" in agent_def and isinstance(agent_def["tools"], list):
            tools = [str(t) for t in agent_def["tools"]]

        role = agent_def.get("role", agent_key)
        if isinstance(role, str):
            role = role.strip()

        agents.append(AgentDefinition(
            name=agent_key,
            role=role,
            framework="CrewAI",
            source_file=file_path,
            tool_names=tools,
        ))

    return agents


def extract_agents_from_python(source: str, file_path: str) -> list[AgentDefinition]:
    """Extract agent definitions from Python code.

    Patterns:
    - CrewAI @agent-decorated methods containing Agent(tools=[...])
    - Generic Agent(role="...", tools=[...])
    - LangChain: AgentExecutor(agent=..., tools=[...])
    - AutoGen: AssistantAgent(name="...", ...)
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    agents: list[AgentDefinition] = []

    # Strategy 1: CrewAI @agent-decorated methods
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        # Check for @agent decorator
        is_agent_method = any(
            (isinstance(d, ast.Name) and d.id == "agent")
            or (isinstance(d, ast.Attribute) and d.attr == "agent")
            for d in node.decorator_list
        )
        if not is_agent_method:
            continue

        method_name = node.name
        tool_names: list[str] = []

        # Resolve local variable assignments (e.g., search_tool = SerperDevTool())
        local_vars: dict[str, str] = {}
        for child in ast.walk(node):
            if isinstance(child, ast.Assign) and len(child.targets) == 1:
                target = child.targets[0]
                if isinstance(target, ast.Name) and isinstance(child.value, ast.Call):
                    call_name = ""
                    if isinstance(child.value.func, ast.Name):
                        call_name = child.value.func.id
                    elif isinstance(child.value.func, ast.Attribute):
                        call_name = child.value.func.attr
                    if call_name:
                        local_vars[target.id] = call_name

        # Find Agent() call inside this method and extract tools
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            call_name = ""
            if isinstance(child.func, ast.Name):
                call_name = child.func.id
            elif isinstance(child.func, ast.Attribute):
                call_name = child.func.attr
            if call_name != "Agent":
                continue

            for kw in child.keywords:
                if kw.arg == "tools" and isinstance(kw.value, ast.List):
                    for elt in kw.value.elts:
                        if isinstance(elt, ast.Call):
                            if isinstance(elt.func, ast.Name):
                                tool_names.append(elt.func.id)
                            elif isinstance(elt.func, ast.Attribute):
                                tool_names.append(elt.func.attr)
                        elif isinstance(elt, ast.Name):
                            # Resolve variable to class name if possible
                            resolved = local_vars.get(elt.id, elt.id)
                            tool_names.append(resolved)

        agents.append(AgentDefinition(
            name=method_name,
            role=method_name.replace("_", " ").title(),
            framework="CrewAI",
            source_file=file_path,
            tool_names=tool_names,
        ))

    # Strategy 2: Generic Agent/AgentExecutor/AssistantAgent calls
    # (only if no @agent-decorated methods found)
    if not agents:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            if func_name not in ("Agent", "AgentExecutor", "AssistantAgent", "UserProxyAgent"):
                continue

            name = func_name
            role = ""
            tool_names_generic: list[str] = []
            framework = "unknown"

            for keyword in node.keywords:
                if keyword.arg == "role" and isinstance(keyword.value, ast.Constant):
                    role = keyword.value.value
                elif keyword.arg == "name" and isinstance(keyword.value, ast.Constant):
                    name = keyword.value.value
                elif keyword.arg == "tools" and isinstance(keyword.value, ast.List):
                    for elt in keyword.value.elts:
                        if isinstance(elt, ast.Call):
                            if isinstance(elt.func, ast.Name):
                                tool_names_generic.append(elt.func.id)
                            elif isinstance(elt.func, ast.Attribute):
                                tool_names_generic.append(elt.func.attr)
                        elif isinstance(elt, ast.Name):
                            tool_names_generic.append(elt.id)

            if func_name == "Agent":
                framework = "CrewAI"
            elif func_name == "AgentExecutor":
                framework = "LangChain"
            elif func_name in ("AssistantAgent", "UserProxyAgent"):
                framework = "AutoGen"

            agents.append(AgentDefinition(
                name=name,
                role=role or name,
                framework=framework,
                source_file=file_path,
                tool_names=tool_names_generic,
            ))

    return agents
