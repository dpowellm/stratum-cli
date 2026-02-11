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
    tool_names = [
        graph.nodes[nid].label
        for nid in path_nodes
        if graph.nodes[nid].node_type == NodeType.CAPABILITY
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
