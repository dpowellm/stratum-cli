"""Data sensitivity inference and propagation along graph edges."""
from __future__ import annotations

from stratum.graph.models import RiskGraph, NodeType
from stratum.graph.util import tool_class_name


# Data sensitivity inference from library/tool names
SENSITIVITY_MAP: dict[str, str] = {
    # Personal data
    "gmail": "personal",
    "Gmail": "personal",                # catches GmailToolkit, GmailGetThread, GmailGetMessage, etc.
    "GmailToolkit": "personal",
    "GmailGetThread": "personal",
    "GmailGetMessage": "personal",
    "GmailSearch": "personal",
    "GmailCreateDraft": "personal",
    "GmailSendMessage": "personal",
    "O365Toolkit": "personal",
    "SlackToolkit": "personal",
    "Slack": "personal",

    # Financial indicators
    "stripe": "financial",
    "paypalrestsdk": "financial",
    "square": "financial",
    "braintree": "financial",

    # Credential indicators
    "DATABASE_URL": "credentials",
    "AWS_SECRET": "credentials",
    "API_KEY": "credentials",

    # Internal
    "psycopg2": "internal",
    "sqlalchemy": "internal",
    "pymongo": "internal",
    "sqlite3": "internal",
    "chromadb": "internal",
    "pinecone": "internal",
    "weaviate": "internal",

    # Health data (triggers HIPAA)
    "fhirclient": "health",
    "hl7": "health",
    "pydicom": "health",
    "health": "health",
    "medical": "health",
    "epic_fhir": "health",

    # Public (search tools -- these are NOT data sources, they are outbound services)
    "SerperDevTool": "public",
    "Serper": "public",
    "DuckDuckGoSearchRun": "public",
    "WikipediaQueryRun": "public",
    "TavilySearchResults": "public",
    "Tavily": "public",
}

SENSITIVITY_RANK: dict[str, int] = {
    "credentials": 5,
    "personal": 4,
    "health": 4,
    "financial": 3,
    "internal": 2,
    "public": 1,
    "unknown": 0,
}


def infer_sensitivity_from_library(library: str) -> str:
    """Infer data sensitivity from library/tool name.

    Returns: 'personal', 'financial', 'credentials', 'internal', 'public', or 'unknown'
    """
    for key, sensitivity in SENSITIVITY_MAP.items():
        if key.lower() in library.lower():
            return sensitivity
    return "unknown"


def infer_sensitivity_for_cap(cap) -> str:
    """Infer data sensitivity from a capability.

    Checks tool class name first (catches GmailToolkit even when
    library is 'langchain_community.agent_toolkits'), then library path.
    """
    cls = tool_class_name(cap)

    # 1. Exact match on class name
    if cls in SENSITIVITY_MAP:
        return SENSITIVITY_MAP[cls]

    # 2. Substring match on class name
    for key, sensitivity in SENSITIVITY_MAP.items():
        if key.lower() in cls.lower():
            return sensitivity

    # 3. Substring match on library
    for key, sensitivity in SENSITIVITY_MAP.items():
        if key.lower() in cap.library.lower():
            return sensitivity

    return "unknown"


def propagate_sensitivity(graph: RiskGraph) -> None:
    """Propagate data sensitivity forward along edges.

    BFS from all nodes with known sensitivity. When a node's sensitivity
    is upgraded, re-add it to the queue to propagate the upgrade downstream.
    """
    # Start from all nodes with non-trivial sensitivity
    queue: list[str] = [
        nid for nid, node in graph.nodes.items()
        if node.data_sensitivity not in ("public", "unknown")
    ]

    # No visited set -- nodes can be re-processed when upgraded
    max_iterations = len(graph.nodes) * len(graph.edges) + 1  # safety cap
    iterations = 0

    while queue and iterations < max_iterations:
        iterations += 1
        current_id = queue.pop(0)
        current = graph.nodes[current_id]
        current_rank = SENSITIVITY_RANK.get(current.data_sensitivity, 0)

        for edge in graph.edges:
            if edge.source != current_id:
                continue

            # Upgrade edge sensitivity
            edge_rank = SENSITIVITY_RANK.get(edge.data_sensitivity, 0)
            if current_rank > edge_rank:
                edge.data_sensitivity = current.data_sensitivity

            # Upgrade target node sensitivity (if not blocked by control)
            if edge.has_control:
                continue

            target = graph.nodes.get(edge.target)
            if not target:
                continue

            # Don't overwrite native sensitivity of external sinks —
            # the node describes what the service IS, the edge carries
            # what data FLOWS through it.
            if target.node_type in (NodeType.EXTERNAL_SERVICE, NodeType.MCP_SERVER):
                continue

            target_rank = SENSITIVITY_RANK.get(target.data_sensitivity, 0)
            if current_rank > target_rank:
                target.data_sensitivity = current.data_sensitivity
                # Re-queue to propagate the upgrade downstream
                queue.append(edge.target)
