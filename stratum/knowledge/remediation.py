"""Generate framework-specific remediation snippets."""
from __future__ import annotations

REMEDIATIONS: dict[str, dict[str, str]] = {
    "add_hitl": {
        "CrewAI": (
            "Fix (CrewAI):\n"
            "  task = Task(\n"
            "      description=\"...\",\n"
            "+     human_input=True   # review before execution\n"
            "  )"
        ),
        "LangGraph": (
            "Fix (LangGraph):\n"
            "  graph.compile(\n"
            "+     interrupt_before=[\"{tool_name}\"]  # pause for approval\n"
            "  )"
        ),
        "AutoGen": (
            "Fix (AutoGen):\n"
            "  agent = AssistantAgent(\n"
            "      name=\"...\",\n"
            "+     human_input_mode=\"ALWAYS\"  # require approval\n"
            "  )"
        ),
        "OpenAI": (
            "Fix (OpenAI Agents):\n"
            "  agent = Agent(\n"
            "      name=\"...\",\n"
            "+     tools=[{tool_name}],\n"
            "+     input_guardrails=[approval_guardrail]\n"
            "  )"
        ),
        "_default": (
            "Add a human approval step before executing this tool.\n"
            "  Most frameworks support interrupt/approval patterns."
        ),
    },
    "add_structured_output": {
        "CrewAI": (
            "Fix (CrewAI):\n"
            "  task = Task(\n"
            "      description=\"...\",\n"
            "+     output_pydantic=ResultSchema  # enforces structured output\n"
            "  )"
        ),
        "LangGraph": (
            "Fix (LangGraph):\n"
            "  from langchain_core.output_parsers import PydanticOutputParser\n"
            "  parser = PydanticOutputParser(pydantic_object=ResultSchema)\n"
            "  chain = prompt | llm | parser"
        ),
        "_default": "Add structured output validation (e.g., Pydantic schema).",
    },
    "add_cost_controls": {
        "CrewAI": (
            "Fix (CrewAI):\n"
            "  crew = Crew(\n"
            "      agents=[...],\n"
            "+     max_rpm=10,        # rate limit\n"
            "+     verbose=True,      # monitor execution\n"
            "  )\n"
            "  agent = Agent(\n"
            "+     max_iter=5,        # cap reasoning loops\n"
            "  )"
        ),
        "LangGraph": (
            "Fix (LangGraph):\n"
            "  graph.compile(\n"
            "+     recursion_limit=25  # prevent infinite loops\n"
            "  )"
        ),
        "_default": "Add iteration limits and rate limiting to prevent runaway costs.",
    },
    "add_error_handling": {
        "CrewAI": (
            "Fix (CrewAI):\n"
            "  try:\n"
            "      result = crew.kickoff()\n"
            "  except Exception as e:\n"
            "      logger.error(f\"Crew failed: {e}\")\n"
            "      # degrade gracefully"
        ),
        "_default": "Wrap external calls in try/except with graceful degradation.",
    },
}


def framework_remediation(
    detected_frameworks: list[str],
    fix_type: str,
    tool_name: str = "",
) -> str:
    """Return framework-specific remediation based on detected frameworks."""
    fixes = REMEDIATIONS.get(fix_type, {})

    for fw in detected_frameworks:
        if fw in fixes:
            return fixes[fw].replace("{tool_name}", tool_name)

    return fixes.get("_default", "See framework documentation for remediation guidance.")
