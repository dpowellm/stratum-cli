"""Framework-specific remediation text for graph-derived findings."""
from __future__ import annotations

from stratum.graph.models import NodeType, RiskGraph


def framework_remediation(
    finding_id: str,
    detected_frameworks: list[str],
    path_nodes: list[str],
    graph: RiskGraph,
) -> str:
    """Generate framework-specific remediation advice.

    Uses clean node labels (no brackets) and matches the detected framework.
    """
    tool_names = []
    if graph and path_nodes:
        tool_names = [
            graph.nodes[nid].label
            for nid in path_nodes
            if nid in graph.nodes and graph.nodes[nid].node_type == NodeType.CAPABILITY
        ]

    # Pick the primary framework (first detected)
    framework = detected_frameworks[0] if detected_frameworks else "unknown"

    if finding_id in ("STRATUM-001", "STRATUM-002", "STRATUM-007"):

        if framework == "CrewAI":
            return (
                "Fix (CrewAI):\n"
                "  task = Task(\n"
                "      description=\"...\",\n"
                "+     human_input=True   # review before external calls\n"
                "  )"
            )

        elif framework in ("LangChain", "LangGraph"):
            tool_list = ", ".join(f'"{t}"' for t in tool_names[:3])
            return (
                "Fix (LangGraph):\n"
                "  graph.compile(\n"
                "+     checkpointer=MemorySaver(),\n"
                f"+     interrupt_before=[{tool_list}]\n"
                "  )"
            )

        elif framework == "AutoGen":
            return (
                "Fix (AutoGen):\n"
                "  agent = AssistantAgent(\n"
                "      name=\"...\",\n"
                "+     human_input_mode=\"ALWAYS\"\n"
                "  )"
            )

        elif framework == "PydanticAI":
            return (
                "Fix (PydanticAI):\n"
                "+ @agent.result_validator\n"
                "+ def check_output(data):\n"
                "+     # validate before external calls\n"
                "+     return data"
            )

        else:
            return (
                "Fix:\n"
                "  Add a human-in-the-loop gate before external calls.\n"
                "  Check your framework's docs for approval/interrupt patterns."
            )

    return ""


def framework_remediation_008(detected_frameworks: list[str]) -> str:
    """Framework-specific error handling remediation."""
    framework = detected_frameworks[0] if detected_frameworks else "unknown"

    if framework == "CrewAI":
        return (
            "Fix (CrewAI):\n"
            "  Wrap crew execution in error handling:\n\n"
            "  try:\n"
            "      result = crew.kickoff()\n"
            "  except Exception as e:\n"
            '      logger.error(f"Crew failed: {e}")\n'
            "      # degrade gracefully"
        )
    elif framework in ("LangChain", "LangGraph"):
        return (
            "Fix (LangGraph):\n"
            "  Add a fallback to your graph:\n\n"
            "  from langchain_core.runnables import RunnableWithFallbacks\n"
            "  chain_with_fallback = chain.with_fallbacks(\n"
            "      [fallback_chain]\n"
            "  )"
        )
    elif framework == "AutoGen":
        return (
            "Fix (AutoGen):\n"
            "  Register a reply function with error handling:\n\n"
            "  @agent.register_reply(trigger=...)\n"
            "  def safe_reply(recipient, messages, sender, config):\n"
            "      try:\n"
            "          return original_logic(messages)\n"
            "      except Exception as e:\n"
            '          return f"Error: {e}"'
        )
    else:
        return (
            "Fix:\n"
            "  Wrap external tool calls in try/except.\n"
            "  Return a user-friendly error message on failure."
        )


def framework_remediation_010(detected_frameworks: list[str]) -> str:
    """Framework-specific checkpointing remediation."""
    framework = detected_frameworks[0] if detected_frameworks else "unknown"

    if framework == "CrewAI":
        return (
            "Fix (CrewAI):\n"
            "  Enable memory on your crew:\n\n"
            "  crew = Crew(\n"
            "      agents=[...],\n"
            "      tasks=[...],\n"
            "+     memory=True,\n"
            "+     verbose=True\n"
            "  )"
        )
    elif framework in ("LangChain", "LangGraph"):
        return (
            "Fix (LangGraph):\n"
            "  from langgraph.checkpoint.memory import MemorySaver\n"
            "  # minimum — use PostgresSaver for durability\n"
            "  graph.compile(checkpointer=MemorySaver())"
        )
    elif framework == "AutoGen":
        return (
            "Fix (AutoGen):\n"
            "  Enable caching for conversation state:\n\n"
            "  from autogen import Cache\n"
            "  with Cache.disk() as cache:\n"
            "      result = agent.initiate_chat(..., cache=cache)"
        )
    else:
        return (
            "Fix:\n"
            "  Add state persistence to your agent workflow.\n"
            "  Check your framework's docs for checkpointing/memory."
        )
