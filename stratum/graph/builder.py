"""Build a directed risk graph from ScanResult data."""
from __future__ import annotations

import re

from stratum.models import Capability, MCPServer, GuardrailSignal, ScanResult, TrustLevel
from stratum.graph.models import (
    EdgeType, GraphEdge, GraphNode, NodeType, RiskGraph,
)
from stratum.graph.sensitivity import infer_sensitivity_from_library, propagate_sensitivity
from stratum.graph.traversal import find_uncontrolled_paths
from stratum.graph.surface import compute_risk_surface


def build_graph(result: ScanResult) -> RiskGraph:
    """Build a directed risk graph from scan results.

    Nodes are created from:
    - capabilities -> CAPABILITY nodes + inferred DATA_STORE/EXTERNAL_SERVICE nodes
    - mcp_servers -> MCP_SERVER nodes
    - guardrails -> GUARDRAIL nodes

    Edges are inferred from:
    - capability.kind + capability.trust_level -> data flow direction
    - MCP server configs -> CALLS edges
    - guardrail presence -> FILTERED_BY / GATED_BY edges
    """
    graph = RiskGraph(nodes={}, edges=[])

    # Step 1: Create capability nodes and infer connected nodes
    for cap in result.capabilities:
        cap_node = _capability_to_node(cap)
        graph.nodes[cap_node.id] = cap_node
        _infer_connected_nodes(graph, cap, cap_node)

    # Step 2: Create MCP server nodes
    for mcp in result.mcp_servers:
        mcp_node = _mcp_to_node(mcp)
        graph.nodes[mcp_node.id] = mcp_node

    # Step 3: Create guardrail nodes and connect them
    for guard in result.guardrails:
        guard_node = _guardrail_to_node(guard)
        graph.nodes[guard_node.id] = guard_node
        _connect_guardrail(graph, guard, guard_node)

    # Step 4: Connect data-reading capabilities to outbound capabilities
    # (implicit: the agent can use any tool, so data flows from reads to sends)
    _connect_agent_data_flows(graph, result.capabilities)

    # Step 5: Infer and propagate data sensitivity
    propagate_sensitivity(graph)

    # Step 6: Find uncontrolled paths
    graph.uncontrolled_paths = find_uncontrolled_paths(graph)

    # Step 7: Compute risk surface
    graph.risk_surface = compute_risk_surface(graph)

    return graph


# ---------------------------------------------------------------------------
# Node creation helpers
# ---------------------------------------------------------------------------

def _capability_to_node(cap: Capability) -> GraphNode:
    """Convert a Capability to a GraphNode."""
    return GraphNode(
        id=f"cap_{cap.function_name}_{cap.kind}",
        node_type=NodeType.CAPABILITY,
        label=cap.function_name,
        trust_level=cap.trust_level,
        data_sensitivity=infer_sensitivity_from_library(cap.library),
        framework=cap.library.split(".")[0] if cap.library else "",
        source_file=cap.source_file,
        line_number=cap.line_number,
        has_error_handling=cap.has_error_handling,
        has_timeout=cap.has_timeout,
    )


def _mcp_to_node(mcp: MCPServer) -> GraphNode:
    """Convert an MCPServer to a GraphNode."""
    return GraphNode(
        id=f"mcp_{mcp.name}",
        node_type=NodeType.MCP_SERVER,
        label=mcp.name,
        trust_level=TrustLevel.EXTERNAL if mcp.is_remote else TrustLevel.INTERNAL,
        mcp_auth=mcp.has_auth,
        mcp_pinned=bool(mcp.package_version),
        mcp_remote=mcp.is_remote,
    )


def _guardrail_to_node(guard: GuardrailSignal) -> GraphNode:
    """Convert a GuardrailSignal to a GraphNode."""
    return GraphNode(
        id=f"guard_{guard.kind}_{guard.line_number}",
        node_type=NodeType.GUARDRAIL,
        label=f"{guard.kind} guardrail",
        trust_level=TrustLevel.INTERNAL,
        guardrail_kind=guard.kind,
        guardrail_active=guard.has_usage,
    )


# ---------------------------------------------------------------------------
# Edge inference from capabilities
# ---------------------------------------------------------------------------

def _infer_connected_nodes(
    graph: RiskGraph,
    cap: Capability,
    cap_node: GraphNode,
) -> None:
    """Infer data stores, services, and edges from a capability."""
    if cap.kind == "data_access":
        source = GraphNode(
            id=f"ds_{_lib_key(cap.library)}",
            node_type=NodeType.DATA_STORE,
            label=_friendly_source_name(cap),
            trust_level=_infer_source_trust(cap),
            data_sensitivity=infer_sensitivity_from_library(cap.library),
        )
        if source.id not in graph.nodes:
            graph.nodes[source.id] = source

        graph.edges.append(GraphEdge(
            source=source.id,
            target=cap_node.id,
            edge_type=EdgeType.READS_FROM,
            has_control=False,
            data_sensitivity=source.data_sensitivity,
        ))

    elif cap.kind == "outbound":
        service = GraphNode(
            id=f"ext_{_lib_key(cap.library)}",
            node_type=NodeType.EXTERNAL_SERVICE,
            label=_friendly_service_name(cap),
            trust_level=TrustLevel.EXTERNAL,
        )
        if service.id not in graph.nodes:
            graph.nodes[service.id] = service

        graph.edges.append(GraphEdge(
            source=cap_node.id,
            target=service.id,
            edge_type=EdgeType.SENDS_TO,
            has_control=False,
        ))

    elif cap.kind == "destructive":
        store = GraphNode(
            id=f"ds_{_lib_key(cap.library)}_write",
            node_type=NodeType.DATA_STORE,
            label=_friendly_store_name(cap),
            trust_level=TrustLevel.INTERNAL,
        )
        if store.id not in graph.nodes:
            graph.nodes[store.id] = store

        graph.edges.append(GraphEdge(
            source=cap_node.id,
            target=store.id,
            edge_type=EdgeType.WRITES_TO,
            has_control=False,
        ))

    elif cap.kind == "code_exec":
        sys_node = GraphNode(
            id="sys_exec",
            node_type=NodeType.EXTERNAL_SERVICE,
            label="System (code execution)",
            trust_level=TrustLevel.PRIVILEGED,
        )
        if sys_node.id not in graph.nodes:
            graph.nodes[sys_node.id] = sys_node

        graph.edges.append(GraphEdge(
            source=cap_node.id,
            target=sys_node.id,
            edge_type=EdgeType.CALLS,
            has_control=False,
        ))

    elif cap.kind == "financial":
        fin_node = GraphNode(
            id=f"fin_{_lib_key(cap.library)}",
            node_type=NodeType.EXTERNAL_SERVICE,
            label=_friendly_service_name(cap),
            trust_level=TrustLevel.RESTRICTED,
            data_sensitivity="financial",
        )
        if fin_node.id not in graph.nodes:
            graph.nodes[fin_node.id] = fin_node

        graph.edges.append(GraphEdge(
            source=cap_node.id,
            target=fin_node.id,
            edge_type=EdgeType.SENDS_TO,
            has_control=False,
            data_sensitivity="financial",
        ))


# ---------------------------------------------------------------------------
# Agent-level data flow connections
# ---------------------------------------------------------------------------

def _connect_agent_data_flows(graph: RiskGraph, capabilities: list[Capability]) -> None:
    """Connect data-reading capabilities to outbound/financial capabilities.

    When an agent has both data_access and outbound capabilities, the agent
    can read data and then send it out. This creates implicit edges from
    data_access capability nodes to outbound/financial capability nodes.
    """
    data_caps = [c for c in capabilities if c.kind == "data_access"]
    outbound_caps = [c for c in capabilities if c.kind in ("outbound", "financial")]

    for dc in data_caps:
        dc_node_id = f"cap_{dc.function_name}_{dc.kind}"
        if dc_node_id not in graph.nodes:
            continue

        for oc in outbound_caps:
            oc_node_id = f"cap_{oc.function_name}_{oc.kind}"
            if oc_node_id not in graph.nodes:
                continue

            # Avoid duplicate edges
            already_connected = any(
                e.source == dc_node_id and e.target == oc_node_id
                for e in graph.edges
            )
            if not already_connected:
                graph.edges.append(GraphEdge(
                    source=dc_node_id,
                    target=oc_node_id,
                    edge_type=EdgeType.SHARES_WITH,
                    has_control=False,
                ))


# ---------------------------------------------------------------------------
# Guardrail connection
# ---------------------------------------------------------------------------

def _connect_guardrail(
    graph: RiskGraph,
    guard: GuardrailSignal,
    guard_node: GraphNode,
) -> None:
    """Connect a guardrail node to relevant edges in the graph.

    For output_filter / input_filter guardrails: mark SENDS_TO edges as controlled.
    For hitl guardrails: mark edges to destructive/financial targets as controlled.
    """
    if not guard.has_usage:
        return

    if guard.kind in ("output_filter", "input_filter"):
        for edge in graph.edges:
            if edge.edge_type in (EdgeType.SENDS_TO, EdgeType.CALLS):
                # Check if this guard covers the relevant tools
                if _guard_covers_edge(guard, edge, graph):
                    edge.has_control = True
                    edge.control_type = guard.kind

    elif guard.kind == "hitl":
        for edge in graph.edges:
            src = graph.nodes.get(edge.source)
            if src and src.node_type == NodeType.CAPABILITY:
                if _guard_covers_edge(guard, edge, graph):
                    edge.has_control = True
                    edge.control_type = "hitl"

    elif guard.kind == "validation":
        for edge in graph.edges:
            if edge.edge_type == EdgeType.SENDS_TO:
                tgt = graph.nodes.get(edge.target)
                if tgt and tgt.data_sensitivity == "financial":
                    edge.has_control = True
                    edge.control_type = "validation"


def _guard_covers_edge(
    guard: GuardrailSignal,
    edge: GraphEdge,
    graph: RiskGraph,
) -> bool:
    """Check if a guardrail covers the source capability of an edge."""
    if not guard.covers_tools:
        return True  # Broad guard covers everything
    src = graph.nodes.get(edge.source)
    if src and src.node_type == NodeType.CAPABILITY:
        return src.label in guard.covers_tools
    return False


# ---------------------------------------------------------------------------
# Naming helpers
# ---------------------------------------------------------------------------

_FRIENDLY_SOURCES: dict[str, str] = {
    "gmail": "Gmail inbox",
    "psycopg2": "PostgreSQL",
    "sqlalchemy": "SQL database",
    "pymongo": "MongoDB",
    "sqlite3": "SQLite",
    "chromadb": "ChromaDB",
    "pinecone": "Pinecone",
    "weaviate": "Weaviate",
    "redis": "Redis",
    "o365": "Office 365",
}

_FRIENDLY_SERVICES: dict[str, str] = {
    "serper": "Serper API",
    "serperdevtool": "Serper API",
    "requests": "HTTP endpoint",
    "httpx": "HTTP endpoint",
    "urllib": "HTTP endpoint",
    "smtplib": "Email (SMTP)",
    "slack": "Slack",
    "stripe": "Stripe API",
    "paypalrestsdk": "PayPal API",
    "square": "Square API",
    "braintree": "Braintree API",
    "duckduckgo": "DuckDuckGo",
}


def _lib_key(library: str) -> str:
    """Normalize a library name into a stable node ID component."""
    # Take the last meaningful segment
    parts = library.replace(".", "_").split("_")
    # Filter out very common prefixes
    filtered = [p for p in parts if p.lower() not in ("langchain", "community", "tools", "crewai")]
    key = "_".join(filtered) if filtered else library.replace(".", "_")
    # Sanitize
    return re.sub(r"[^a-zA-Z0-9_]", "", key).lower()


def _friendly_source_name(cap: Capability) -> str:
    """Generate a human-readable data source name."""
    lib_lower = cap.library.lower()
    for key, name in _FRIENDLY_SOURCES.items():
        if key in lib_lower:
            return name
    # Use function name as fallback
    if cap.function_name and cap.function_name.startswith("[YAML:"):
        tool_name = cap.function_name.replace("[YAML: ", "").replace("]", "")
        return f"{tool_name} data source"
    return f"{cap.library.split('.')[-1]} data source"


def _friendly_service_name(cap: Capability) -> str:
    """Generate a human-readable external service name."""
    lib_lower = cap.library.lower()
    for key, name in _FRIENDLY_SERVICES.items():
        if key in lib_lower:
            return name
    fn = cap.function_name
    if fn.startswith("[YAML:"):
        tool_name = fn.replace("[YAML: ", "").replace("]", "")
        return tool_name
    return f"{cap.library.split('.')[-1]} service"


def _friendly_store_name(cap: Capability) -> str:
    """Generate a human-readable data store name for destructive ops."""
    lib_lower = cap.library.lower()
    for key, name in _FRIENDLY_SOURCES.items():
        if key in lib_lower:
            return f"{name} (write)"
    return f"{cap.library.split('.')[-1]} store"


def _infer_source_trust(cap: Capability) -> TrustLevel:
    """Infer the trust level of an inferred data source."""
    lib_lower = cap.library.lower()
    # External services
    if any(kw in lib_lower for kw in ("gmail", "o365", "slack")):
        return TrustLevel.EXTERNAL
    # Internal databases
    if any(kw in lib_lower for kw in ("psycopg2", "sqlalchemy", "pymongo", "sqlite3", "redis")):
        return TrustLevel.INTERNAL
    # Vector stores
    if any(kw in lib_lower for kw in ("chromadb", "pinecone", "weaviate")):
        return TrustLevel.INTERNAL
    return cap.trust_level
