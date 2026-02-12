"""Build a directed risk graph from ScanResult data."""
from __future__ import annotations

import re

from stratum.models import Capability, MCPServer, GuardrailSignal, ScanResult, TrustLevel
from stratum.graph.models import (
    EdgeType, GraphEdge, GraphNode, NodeType, RiskGraph,
)
from stratum.graph.sensitivity import (
    infer_sensitivity_for_cap, propagate_sensitivity, SENSITIVITY_MAP,
)
from stratum.graph.traversal import find_uncontrolled_paths
from stratum.graph.surface import compute_risk_surface
from stratum.graph.util import tool_class_name


# ---------------------------------------------------------------------------
# Friendly-name lookup tables (keyed on clean class name or library fragment)
# ---------------------------------------------------------------------------

FRIENDLY_NAMES: dict[str, tuple[str, str]] = {
    # key -> (data_source_name, external_service_name)
    "GmailGetThread": ("Gmail inbox", "Gmail outbound"),
    "GmailGetMessage": ("Gmail inbox", "Gmail outbound"),
    "GmailSearch": ("Gmail inbox", "Gmail outbound"),
    "GmailCreateDraft": ("Gmail inbox", "Gmail outbound"),
    "GmailSendMessage": ("Gmail inbox", "Gmail outbound"),
    "GmailToolkit": ("Gmail inbox", "Gmail outbound"),
    "Gmail": ("Gmail inbox", "Gmail outbound"),
    "gmail": ("Gmail inbox", "Gmail outbound"),
    "SerperDevTool": ("Serper results", "Serper API"),
    "Serper": ("Serper results", "Serper API"),
    "serper": ("Serper results", "Serper API"),
    "TavilySearchResults": ("Tavily results", "Tavily API"),
    "Tavily": ("Tavily results", "Tavily API"),
    "tavily": ("Tavily results", "Tavily API"),
    "DuckDuckGoSearchRun": ("DuckDuckGo results", "DuckDuckGo"),
    "WikipediaQueryRun": ("Wikipedia", "Wikipedia"),
    "O365Toolkit": ("Office 365 inbox", "Office 365"),
    "o365": ("Office 365 inbox", "Office 365"),
    "SlackToolkit": ("Slack messages", "Slack"),
    "Slack": ("Slack messages", "Slack"),
    "slack": ("Slack messages", "Slack"),
    "psycopg2": ("PostgreSQL", "PostgreSQL"),
    "sqlalchemy": ("SQL database", "SQL database"),
    "pymongo": ("MongoDB", "MongoDB"),
    "sqlite3": ("SQLite", "SQLite"),
    "chromadb": ("ChromaDB", "ChromaDB"),
    "pinecone": ("Pinecone", "Pinecone"),
    "weaviate": ("Weaviate", "Weaviate"),
    "redis": ("Redis", "Redis"),
    "requests": ("HTTP endpoint", "HTTP endpoint"),
    "httpx": ("HTTP endpoint", "HTTP endpoint"),
    "urllib": ("HTTP endpoint", "HTTP endpoint"),
    "smtplib": ("Email (SMTP)", "Email (SMTP)"),
    "stripe": ("Stripe data", "Stripe API"),
    "paypalrestsdk": ("PayPal data", "PayPal API"),
    "square": ("Square data", "Square API"),
    "braintree": ("Braintree data", "Braintree API"),
}


EXTERNAL_SERVICE_SENSITIVITY: dict[str, str] = {
    "Serper API": "public",
    "Serper results": "public",
    "Tavily API": "public",
    "Tavily results": "public",
    "DuckDuckGo": "public",
    "Wikipedia": "public",
    "Gmail outbound": "personal",
    "Email (SMTP)": "personal",
    "Slack": "internal",
    "Office 365": "personal",
    "HTTP endpoint": "unknown",
    "System (code execution)": "unknown",
}

TOOLKIT_MEMBERS: dict[str, list[str]] = {
    "GmailToolkit": [
        "GmailToolkit", "GmailCreateDraft", "GmailSendMessage",
        "GmailGetThread", "GmailGetMessage", "GmailSearch",
    ],
    "O365Toolkit": ["O365Toolkit"],
    "SlackToolkit": ["SlackToolkit"],
}


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

    # Deduplicate capabilities: same tool + same kind = one node
    seen_cap_keys: set[tuple[str, str]] = set()
    unique_caps: list[Capability] = []
    for cap in result.capabilities:
        cls = tool_class_name(cap)
        key = (cls, cap.kind)
        if key not in seen_cap_keys:
            seen_cap_keys.add(key)
            unique_caps.append(cap)

    # Step 1: Create capability nodes and infer connected nodes
    for cap in unique_caps:
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

    # Step 3.5: Agent definitions -> AGENT nodes + TOOL_OF edges
    for agent_def in getattr(result, 'agent_definitions', []):
        agent_id = f"agent_{agent_def.name.lower().replace(' ', '_')}"
        agent_node = GraphNode(
            id=agent_id,
            node_type=NodeType.AGENT,
            label=agent_def.role or agent_def.name,
            trust_level=TrustLevel.INTERNAL,
            framework=agent_def.framework,
            source_file=agent_def.source_file,
        )
        graph.nodes[agent_node.id] = agent_node

        # Connect agent to its tools via TOOL_OF edges
        # Build set of all tool names this agent owns (including toolkit members)
        agent_tool_set: set[str] = set()
        for tool_name in agent_def.tool_names:
            agent_tool_set.add(tool_name)
            agent_tool_set.update(TOOLKIT_MEMBERS.get(tool_name, []))

        # Also check reverse: if agent has a member tool, it owns the toolkit too
        for toolkit, members in TOOLKIT_MEMBERS.items():
            if any(m in agent_tool_set for m in members):
                agent_tool_set.add(toolkit)

        for nid, node in graph.nodes.items():
            if node.node_type == NodeType.CAPABILITY and node.label in agent_tool_set:
                graph.edges.append(GraphEdge(
                    source=nid,
                    target=agent_node.id,
                    edge_type=EdgeType.TOOL_OF,
                    has_control=False,
                ))

    # Step 3.6: Agent relationship edges (FEEDS_INTO, DELEGATES_TO, SHARES_TOOL)
    _add_agent_relationship_edges(graph, result)

    # Step 4: Connect data-reading capabilities to outbound capabilities
    # (implicit: the agent can use any tool, so data flows from reads to sends)
    _connect_agent_data_flows(graph, unique_caps)

    # Step 4b: Deduplicate edges
    _deduplicate_edges(graph)

    # Step 5: Infer and propagate data sensitivity
    propagate_sensitivity(graph)

    # Step 5b: Mark trust boundary crossings on all edges
    _mark_trust_crossings(graph)

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
    cls = tool_class_name(cap)
    return GraphNode(
        id=f"cap_{cls}_{cap.kind}",
        node_type=NodeType.CAPABILITY,
        label=cls,
        trust_level=TrustLevel(cap.trust_level),
        data_sensitivity=infer_sensitivity_for_cap(cap),
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
            id=_source_node_id(cap),
            node_type=NodeType.DATA_STORE,
            label=_friendly_source_name(cap),
            trust_level=_infer_source_trust(cap),
            data_sensitivity=infer_sensitivity_for_cap(cap),
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
        service_name = _friendly_service_name(cap)
        service = GraphNode(
            id=_service_node_id(cap),
            node_type=NodeType.EXTERNAL_SERVICE,
            label=service_name,
            trust_level=TrustLevel.EXTERNAL,
            data_sensitivity=EXTERNAL_SERVICE_SENSITIVITY.get(service_name, "unknown"),
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
            id=f"ds_{tool_class_name(cap).lower()}_write",
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
            id=f"fin_{tool_class_name(cap).lower()}",
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
        dc_cls = tool_class_name(dc)
        dc_node_id = f"cap_{dc_cls}_{dc.kind}"
        if dc_node_id not in graph.nodes:
            continue

        for oc in outbound_caps:
            oc_cls = tool_class_name(oc)
            oc_node_id = f"cap_{oc_cls}_{oc.kind}"
            if oc_node_id not in graph.nodes:
                continue

            graph.edges.append(GraphEdge(
                source=dc_node_id,
                target=oc_node_id,
                edge_type=EdgeType.SHARES_WITH,
                has_control=False,
            ))


# ---------------------------------------------------------------------------
# Agent relationship edges
# ---------------------------------------------------------------------------

TRUST_RANK = {
    TrustLevel.PRIVILEGED: 4,
    TrustLevel.RESTRICTED: 3,
    TrustLevel.INTERNAL: 2,
    TrustLevel.EXTERNAL: 1,
    TrustLevel.PUBLIC: 0,
}


def _add_agent_relationship_edges(graph: RiskGraph, result: ScanResult) -> None:
    """Add FEEDS_INTO, DELEGATES_TO, SHARES_TOOL edges from crew/relationship data."""
    # FEEDS_INTO edges from sequential crew definitions
    for crew in getattr(result, 'crew_definitions', []):
        if crew.process_type == "sequential" and len(crew.agent_names) > 1:
            for i in range(len(crew.agent_names) - 1):
                src = f"agent_{crew.agent_names[i].lower().replace(' ', '_')}"
                tgt = f"agent_{crew.agent_names[i + 1].lower().replace(' ', '_')}"
                if src in graph.nodes and tgt in graph.nodes:
                    graph.edges.append(GraphEdge(
                        source=src, target=tgt,
                        edge_type=EdgeType.FEEDS_INTO, has_control=False,
                    ))

        # Hierarchical: manager delegates to all agents
        if crew.process_type == "hierarchical" and crew.has_manager:
            if crew.agent_names:
                manager_id = f"agent_{crew.agent_names[0].lower().replace(' ', '_')}"
                for agent_name in crew.agent_names[1:]:
                    agent_id = f"agent_{agent_name.lower().replace(' ', '_')}"
                    if manager_id in graph.nodes and agent_id in graph.nodes:
                        graph.edges.append(GraphEdge(
                            source=manager_id, target=agent_id,
                            edge_type=EdgeType.DELEGATES_TO, has_control=False,
                        ))

    # Explicit relationships from agent parser
    for rel in getattr(result, 'agent_relationships', []):
        src = f"agent_{rel.source_agent.lower().replace(' ', '_')}"
        tgt = f"agent_{rel.target_agent.lower().replace(' ', '_')}"
        if src not in graph.nodes or tgt not in graph.nodes:
            continue

        if rel.relationship_type == "shares_tool":
            graph.edges.append(GraphEdge(
                source=src, target=tgt,
                edge_type=EdgeType.SHARES_TOOL, has_control=False,
            ))
        elif rel.relationship_type in ("delegates_to", "feeds_into"):
            edge_type = (EdgeType.DELEGATES_TO if rel.relationship_type == "delegates_to"
                         else EdgeType.FEEDS_INTO)
            graph.edges.append(GraphEdge(
                source=src, target=tgt,
                edge_type=edge_type, has_control=False,
            ))


def _mark_trust_crossings(graph: RiskGraph) -> None:
    """Mark trust boundary crossings on all edges."""
    for edge in graph.edges:
        src_node = graph.nodes.get(edge.source)
        tgt_node = graph.nodes.get(edge.target)
        if not src_node or not tgt_node:
            continue
        src_level = TRUST_RANK.get(src_node.trust_level, 0)
        tgt_level = TRUST_RANK.get(tgt_node.trust_level, 0)
        if src_level != tgt_level:
            edge.trust_crossing = True
            edge.crossing_direction = "outward" if src_level > tgt_level else "inward"


# ---------------------------------------------------------------------------
# Edge deduplication
# ---------------------------------------------------------------------------

def _deduplicate_edges(graph: RiskGraph) -> None:
    """Remove duplicate edges (same source, target, type)."""
    seen: set[tuple[str, str, str]] = set()
    unique: list[GraphEdge] = []
    for edge in graph.edges:
        key = (edge.source, edge.target, edge.edge_type.value)
        if key not in seen:
            seen.add(key)
            unique.append(edge)
    graph.edges = unique


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

def _friendly_source_name(cap) -> str:
    """Resolve a capability to a human-friendly data source name.

    Lookup order:
    1. Exact match on clean tool class name (e.g., "SerperDevTool")
    2. Substring match on tool class name
    3. Substring match on library path
    4. Fallback: last segment of library, cleaned up
    """
    cls = tool_class_name(cap)

    # 1. Exact match on class name
    if cls in FRIENDLY_NAMES:
        return FRIENDLY_NAMES[cls][0]

    # 2. Substring match on class name (e.g., "Gmail" in "GmailGetThread")
    for key, (source, _) in FRIENDLY_NAMES.items():
        if key.lower() in cls.lower():
            return source

    # 3. Substring match on library path
    for key, (source, _) in FRIENDLY_NAMES.items():
        if key.lower() in cap.library.lower():
            return source

    # 4. Fallback: clean up the last library segment
    if hasattr(cap, 'function_name') and cap.function_name and cap.function_name.startswith("[YAML:"):
        tool_name = cap.function_name.replace("[YAML: ", "").replace("]", "")
        return f"{tool_name} data source"
    fallback = cap.library.rsplit(".", 1)[-1] if "." in cap.library else cap.library
    return fallback.replace("_", " ").title()


def _friendly_service_name(cap) -> str:
    """Resolve a capability to a human-friendly external service name.

    Same lookup order as _friendly_source_name but returns service label.
    """
    cls = tool_class_name(cap)

    if cls in FRIENDLY_NAMES:
        return FRIENDLY_NAMES[cls][1]

    for key, (_, service) in FRIENDLY_NAMES.items():
        if key.lower() in cls.lower():
            return service

    for key, (_, service) in FRIENDLY_NAMES.items():
        if key.lower() in cap.library.lower():
            return service

    fn = cap.function_name
    if fn.startswith("[YAML:"):
        tool_name = fn.replace("[YAML: ", "").replace("]", "")
        return tool_name
    fallback = cap.library.rsplit(".", 1)[-1] if "." in cap.library else cap.library
    return fallback.replace("_", " ").title()


def _friendly_store_name(cap) -> str:
    """Generate a human-readable data store name for destructive ops."""
    cls = tool_class_name(cap)

    if cls in FRIENDLY_NAMES:
        return f"{FRIENDLY_NAMES[cls][0]} (write)"

    for key, (source, _) in FRIENDLY_NAMES.items():
        if key.lower() in cls.lower():
            return f"{source} (write)"

    for key, (source, _) in FRIENDLY_NAMES.items():
        if key.lower() in cap.library.lower():
            return f"{source} (write)"

    return f"{cap.library.split('.')[-1]} store"


def _source_node_id(cap) -> str:
    """Stable ID for the inferred data source of a capability.

    Multiple tools that read from the same source (GmailGetThread,
    GmailToolkit) should share the same data_store node.
    """
    friendly = _friendly_source_name(cap)
    # Normalize: "Gmail inbox" -> "ds_gmail_inbox"
    return "ds_" + friendly.lower().replace(" ", "_").replace("(", "").replace(")", "")


def _service_node_id(cap) -> str:
    """Stable ID for the inferred external service a capability sends to."""
    friendly = _friendly_service_name(cap)
    return "ext_" + friendly.lower().replace(" ", "_").replace("(", "").replace(")", "")


def _infer_source_trust(cap) -> TrustLevel:
    """Infer trust level for a data source based on what kind of data it holds.

    Gmail inbox = RESTRICTED (it's YOUR data, inside your org boundary).
    PostgreSQL = INTERNAL.
    ChromaDB = INTERNAL.
    External API response = EXTERNAL.
    """
    sensitivity = infer_sensitivity_for_cap(cap)

    if sensitivity in ("personal", "credentials"):
        return TrustLevel.RESTRICTED
    elif sensitivity == "financial":
        return TrustLevel.RESTRICTED
    elif sensitivity == "internal":
        return TrustLevel.INTERNAL
    else:
        return TrustLevel.EXTERNAL
