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

    BFS from data source nodes. Each edge inherits the highest
    sensitivity from its source, unless blocked by a guardrail.
    """
    # Start from all nodes with known sensitivity
    queue: list[str] = []
    for node in graph.nodes.values():
        if node.data_sensitivity != "unknown":
            queue.append(node.id)

    visited: set[str] = set()
    while queue:
        current_id = queue.pop(0)
        if current_id in visited:
            continue
        visited.add(current_id)

        current_node = graph.nodes[current_id]
        current_sensitivity = current_node.data_sensitivity

        for edge in graph.edges:
            if edge.source == current_id:
                # Propagate sensitivity to edge
                if SENSITIVITY_RANK.get(current_sensitivity, 0) > SENSITIVITY_RANK.get(edge.data_sensitivity, 0):
                    edge.data_sensitivity = current_sensitivity

                # Propagate to target node if not blocked by guardrail
                target = graph.nodes.get(edge.target)
                if target and not edge.has_control:
                    if SENSITIVITY_RANK.get(current_sensitivity, 0) > SENSITIVITY_RANK.get(target.data_sensitivity, 0):
                        target.data_sensitivity = current_sensitivity
                    queue.append(edge.target)
