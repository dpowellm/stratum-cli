# STRATUM CLI — MVP PATCH

## WHAT THIS PATCH DOES

This patch takes Stratum from "security scanner that works" to "the product that demonstrates the full thesis." It addresses every gap identified from testing against real-world code (crewAI-examples monorepo).

**What's broken right now:**
1. Graph has nodes but no edges — the "network topology for agents" thesis is invisible
2. Zero business risk findings fire on real code
3. Zero compounding risk findings — the core differentiator doesn't exist
4. Guardrails detected but not linked to capabilities (`covers_tools: []` everywhere)
5. Agent discovery is a flat list with no relationships
6. Incident matches have no explanation of WHY they matched
7. Telemetry profile is too thin for the risk map vision
8. Remediation suggests wrong framework syntax (LangGraph for CrewAI projects)

**What works and must not break:**
- STRATUM-001 data exfiltration path detection — the "oh shit" finding
- STRATUM-002 destructive action detection
- Confidence model (CONFIRMED/PROBABLE/HEURISTIC) with severity gating
- AST-based capability detection with var_origin provenance
- Framework tool detection (SerperDevTool, GmailToolkit, etc.)
- MCP config parsing
- Risk scoring formula
- Scan history / delta tracking
- Agent profile discovery from YAML and Python

**Architecture principle: the graph IS the product.** Every finding, every risk path, every compounding interaction should be derived from graph traversal. The graph is not a visualization afterthought — it's the computational core. Build the graph correctly, and findings fall out of it.

---

## HOW TO USE THIS PATCH

This is a Claude Code / Claude Project specification. Add it as `CLAUDE.md` alongside the existing codebase. The existing code is the base; this patch amends, extends, and fixes.

**Rule: where this patch conflicts with existing code, this patch wins.**

### Build Order

```
Message 1: "Patch Phase 1: Models + Graph. Update stratum/models.py with new dataclasses.
            Create stratum/graph/__init__.py and stratum/graph/builder.py.
            Create stratum/graph/pathfinder.py.
            Follow the spec exactly."

Message 2: "Patch Phase 2: Agent relationships + Guardrail mapping.
            Update stratum/parsers/capabilities.py to track source_file context.
            Create stratum/parsers/agents.py for crew/flow relationship extraction.
            Update guardrail detection to populate covers_tools.
            Follow the spec exactly."

Message 3: "Patch Phase 3: Business + Operational risk rules.
            Create stratum/rules/business_risk.py.
            Create stratum/rules/operational_risk.py.
            Wire both into stratum/rules/engine.py.
            Follow the spec exactly."

Message 4: "Patch Phase 4: Compounding risk rules.
            Create stratum/rules/compounding_risk.py.
            Wire into engine. This is the most important file in the patch.
            Follow the spec exactly."

Message 5: "Patch Phase 5: Incident matching upgrade + Framework-aware remediation.
            Update stratum/knowledge/incidents.py with match_reason generation.
            Create stratum/knowledge/remediation.py for framework-specific fixes.
            Follow the spec exactly."

Message 6: "Patch Phase 6: Telemetry enrichment + Terminal output + Scanner integration.
            Update stratum/telemetry/profile.py with enriched fields.
            Update stratum/output/terminal.py to render graph topology + new finding categories.
            Update stratum/scanner.py to wire everything together.
            Run stratum scan test_project/ and verify all validation targets.
            Follow the spec exactly."
```

---

## PHASE 1: MODELS + GRAPH

### New/Updated Dataclasses in `models.py`

Add these to the existing models file. Do not remove existing dataclasses.

```python
# ── Graph Models ──────────────────────────────────────────────

class NodeType(str, Enum):
    CAPABILITY = "capability"
    DATA_STORE = "data_store"
    MCP_SERVER = "mcp_server"
    EXTERNAL_SERVICE = "external"
    GUARDRAIL = "guardrail"
    AGENT = "agent"

class EdgeType(str, Enum):
    READS_FROM = "reads_from"       # data_access cap → data store
    WRITES_TO = "writes_to"         # destructive cap → data store
    SENDS_TO = "sends_to"           # outbound cap → external service
    CALLS = "calls"                 # agent/cap → MCP server
    FILTERED_BY = "filtered_by"     # capability → guardrail (output filter)
    GATED_BY = "gated_by"           # capability → guardrail (HITL/validation)
    TOOL_OF = "tool_of"             # capability → agent that owns it
    DELEGATES_TO = "delegates_to"   # agent → agent (handoff/delegation)
    FEEDS_INTO = "feeds_into"       # agent output → next agent input (crew chain)
    SHARES_TOOL = "shares_tool"     # agent ↔ agent via shared capability

@dataclass
class GraphNode:
    id: str
    node_type: NodeType
    label: str                      # Human-readable: "Gmail inbox", not "ds_gmail"
    trust_level: str                # "internal", "external", "restricted"
    data_sensitivity: str = "unknown"   # "personal", "financial", "credentials", "internal", "public"
    framework: str = ""
    source_file: str = ""
    line_number: int = 0
    has_error_handling: bool = False
    has_timeout: bool = False
    # MCP-specific
    mcp_auth: bool = False
    mcp_pinned: bool = False
    mcp_remote: bool = False
    # Guardrail-specific
    guardrail_kind: str = ""
    guardrail_active: bool = False

    def to_dict(self) -> dict:
        d = {"id": self.id, "type": self.node_type.value, "label": self.label,
             "trust_level": self.trust_level, "data_sensitivity": self.data_sensitivity}
        # Only include populated optional fields
        if self.framework: d["framework"] = self.framework
        if self.source_file: d["source_file"] = self.source_file
        return d

@dataclass
class GraphEdge:
    source: str                     # Node ID
    target: str                     # Node ID
    edge_type: EdgeType
    has_control: bool               # Is there a guardrail on this edge?
    control_type: str = ""          # Which guardrail kind, if controlled
    data_sensitivity: str = "unknown"
    trust_crossing: bool = False    # Does this edge cross a trust boundary?
    crossing_direction: str = ""    # "inward" (external→internal) or "outward" (internal→external)

    def to_dict(self) -> dict:
        return {"source": self.source, "target": self.target, "type": self.edge_type.value,
                "has_control": self.has_control, "trust_crossing": self.trust_crossing,
                "crossing_direction": self.crossing_direction,
                "data_sensitivity": self.data_sensitivity}

@dataclass
class RiskPath:
    """A concrete path through the graph that represents a risk."""
    node_ids: list[str]
    edges: list[GraphEdge]
    hops: int
    source_sensitivity: str
    destination_trust: str
    missing_controls: list[str]     # Guardrail types that should exist but don't
    trust_crossings: int            # Number of trust boundary crossings
    plain_english: str              # "Gmail inbox → GmailGetThread → GmailToolkit → Gmail outbound"

@dataclass
class RiskSurface:
    total_nodes: int = 0
    total_edges: int = 0
    uncontrolled_path_count: int = 0
    max_path_hops: int = 0
    sensitive_data_types: list[str] = field(default_factory=list)
    external_sink_count: int = 0
    edges_with_controls: int = 0
    edges_needing_controls: int = 0
    control_coverage_pct: float = 0.0
    trust_boundary_crossings: int = 0
    outward_crossings: int = 0      # internal→external (data leaving)
    inward_crossings: int = 0       # external→internal (untrusted input)

    def to_dict(self) -> dict:
        return asdict(self)

@dataclass
class RiskGraph:
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)
    uncontrolled_paths: list[RiskPath] = field(default_factory=list)
    risk_surface: RiskSurface = field(default_factory=RiskSurface)

    def to_dict(self) -> dict:
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "risk_surface": self.risk_surface.to_dict(),
            "uncontrolled_paths": [
                {"path": p.plain_english, "hops": p.hops,
                 "trust_crossings": p.trust_crossings,
                 "missing_controls": p.missing_controls}
                for p in self.uncontrolled_paths
            ],
        }

# ── Agent Relationship Models ────────────────────────────────

@dataclass
class AgentRelationship:
    """A directed relationship between two agents."""
    source_agent: str               # Agent name/id
    target_agent: str
    relationship_type: str          # "delegates_to", "feeds_into", "shares_tool"
    shared_resource: str = ""       # Tool name, data store, etc.
    source_file: str = ""

@dataclass
class CrewDefinition:
    """A crew/team/flow grouping agents together."""
    name: str
    framework: str                  # "CrewAI", "LangGraph", "AutoGen"
    agent_names: list[str]          # Ordered list of agents in this crew
    process_type: str = ""          # "sequential", "hierarchical", "parallel"
    source_file: str = ""
    has_manager: bool = False
    delegation_enabled: bool = False

# ── Incident Match Enhancement ────────────────────────────────

@dataclass
class IncidentMatch:
    """Enhanced incident match with explanation."""
    incident_id: str
    name: str
    date: str
    impact: str
    confidence: float
    attack_summary: str
    source_url: str
    match_reason: str               # NEW: "Your email_auto_responder_flow reads untrusted
                                    # email content and routes it through outbound tools —
                                    # the same data→external pattern that enabled EchoLeak."
    matching_capabilities: list[str]  # NEW: which caps triggered the match
    matching_files: list[str]         # NEW: which source files are implicated
```

### Update `ScanResult`

Add these fields to the existing ScanResult dataclass:

```python
@dataclass
class ScanResult:
    # ... ALL existing fields stay ...

    # NEW fields from this patch:
    graph: RiskGraph = field(default_factory=RiskGraph)
    crew_definitions: list[CrewDefinition] = field(default_factory=list)
    agent_relationships: list[AgentRelationship] = field(default_factory=list)

    # incident_matches type changes from list[dict] to list[IncidentMatch]
    # (migration: update serialization)
```

### Update `Finding`

Add one field to Finding:

```python
@dataclass
class Finding:
    # ... ALL existing fields stay ...

    # NEW:
    graph_paths: list[RiskPath] = field(default_factory=list)
    # The actual graph paths that generated this finding.
    # For STRATUM-001, this would be the data_access→outbound paths.
    # For compounding rules, this would be the agent→agent chains.
```

---

## GRAPH BUILDER: `stratum/graph/__init__.py` + `stratum/graph/builder.py`

### `__init__.py`
```python
from .builder import build_graph
from .pathfinder import find_uncontrolled_paths, compute_risk_surface
```

### `builder.py`

The graph builder takes a ScanResult and constructs a directed graph with typed nodes and edges. **No new scanning.** Every input already exists in the ScanResult.

```python
def build_graph(result: ScanResult) -> RiskGraph:
    """Build directed risk graph from scan results."""
    graph = RiskGraph()

    # Step 1: Capability nodes + inferred data stores / external services
    _add_capability_nodes(graph, result.capabilities)

    # Step 2: MCP server nodes
    _add_mcp_nodes(graph, result.mcp_servers)

    # Step 3: Guardrail nodes + edges to the capabilities they protect
    _add_guardrail_nodes(graph, result.guardrails, result.capabilities)

    # Step 4: Agent nodes + TOOL_OF edges + DELEGATES_TO / FEEDS_INTO edges
    _add_agent_nodes(graph, result.agent_profiles, result.crew_definitions,
                     result.agent_relationships)

    # Step 5: Mark trust boundary crossings on all edges
    _mark_trust_crossings(graph)

    # Step 6: Compute uncontrolled paths and risk surface
    graph.uncontrolled_paths = find_uncontrolled_paths(graph)
    graph.risk_surface = compute_risk_surface(graph)

    return graph
```

#### Step 1: Capability nodes → data store / external service inference

For each capability, create ONE capability node. Then infer the connected node based on kind:

```python
# INFERENCE TABLE — capability kind → connected node type + edge type
#
# data_access  →  DATA_STORE node  ←──READS_FROM── capability
# outbound     →  EXTERNAL_SERVICE node  ──SENDS_TO──→ from capability
# destructive  →  DATA_STORE node  ──WRITES_TO──→ from capability
# code_exec    →  (no connected node; self-contained risk)
# financial    →  EXTERNAL_SERVICE("payment_provider") ──SENDS_TO──→ from capability
```

**Data store inference from library/tool name:**

```python
DATA_STORE_MAP = {
    # library or tool_name → (node_id, label, trust_level, data_sensitivity)
    "psycopg2":        ("ds_postgres",     "PostgreSQL",       "internal",   "personal"),
    "pymongo":         ("ds_mongodb",      "MongoDB",          "internal",   "personal"),
    "sqlite3":         ("ds_sqlite",       "SQLite",           "internal",   "internal"),
    "redis":           ("ds_redis",        "Redis",            "internal",   "internal"),
    "GmailGetThread":  ("ds_gmail_inbox",  "Gmail inbox",      "restricted", "personal"),
    "GmailToolkit":    ("ds_gmail_inbox",  "Gmail inbox",      "restricted", "personal"),
    "CSVSearchTool":   ("ds_local_csv",    "Local CSV files",  "internal",   "unknown"),
    "TXTSearchTool":   ("ds_local_txt",    "Local text files", "internal",   "unknown"),
    "FileReadTool":    ("ds_local_files",  "Local filesystem", "internal",   "unknown"),
    "FileManagementToolkit": ("ds_local_files", "Local filesystem", "internal", "unknown"),
    "RagTool":         ("ds_vector_store", "Vector store",     "internal",   "unknown"),
    "chromadb":        ("ds_vector_store", "Vector store",     "internal",   "unknown"),
}

EXTERNAL_SERVICE_MAP = {
    # library or tool_name → (node_id, label, trust_level, data_sensitivity)
    "requests":             ("ext_http",        "HTTP endpoint",    "external", "unknown"),
    "httpx":                ("ext_http",        "HTTP endpoint",    "external", "unknown"),
    "urllib":               ("ext_http",        "HTTP endpoint",    "external", "unknown"),
    "SerperDevTool":        ("ext_serper",      "Serper API",       "external", "public"),
    "TavilySearchResults":  ("ext_tavily",      "Tavily API",       "external", "public"),
    "WebsiteSearchTool":    ("ext_web_search",  "Web search",       "external", "public"),
    "ScrapeWebsiteTool":    ("ext_web_scrape",  "Web scraper",      "external", "public"),
    "GmailToolkit":         ("ext_gmail_out",   "Gmail outbound",   "external", "personal"),
    "slack_sdk":            ("ext_slack",       "Slack",            "external", "internal"),
    "smtplib":              ("ext_smtp",        "SMTP outbound",    "external", "personal"),
    "stripe":               ("ext_stripe",      "Stripe",           "external", "financial"),
    "twilio":               ("ext_twilio",      "Twilio SMS",       "external", "personal"),
}
```

**Critical: GmailToolkit creates BOTH a data_store node (inbox) AND an external node (outbound).** The data_access capability links to ds_gmail_inbox. The outbound capability links to ext_gmail_out. This is what makes the exfiltration path visible.

**Deduplication:** If two capabilities point to the same inferred node (e.g., two files both use SerperDevTool), reuse the existing node. Create the edge from the capability to the shared node.

**Capability node IDs:** `cap_{tool_or_library}_{kind}_{source_file_hash[:8]}` — unique per file to avoid collapsing capabilities from different projects/crews.

When there are multiple capabilities of the same kind from the same tool across different files, each gets its own node. This is critical for monorepo scanning where the same tool appears in independent projects.

#### Step 2: MCP server nodes

```python
for mcp in result.mcp_servers:
    node_id = f"mcp_{mcp.name.lower().replace(' ', '_')}"
    node = GraphNode(
        id=node_id, node_type=NodeType.MCP_SERVER,
        label=mcp.name, trust_level="external" if mcp.is_remote else "internal",
        mcp_auth=mcp.has_auth, mcp_pinned=mcp.is_pinned, mcp_remote=mcp.is_remote,
    )
    graph.nodes[node_id] = node
    # MCP servers are called by capabilities that reference them
    # (connect in agent step if tool_names reference MCP servers)
```

#### Step 3: Guardrail nodes + connecting edges

```python
def _add_guardrail_nodes(graph, guardrails, capabilities):
    for guard in guardrails:
        node_id = f"guard_{guard.kind}_{guard.line_number}"
        node = GraphNode(
            id=node_id, node_type=NodeType.GUARDRAIL,
            label=f"{guard.kind} guardrail", trust_level="internal",
            guardrail_kind=guard.kind, guardrail_active=guard.has_usage,
            source_file=guard.source_file,
        )
        graph.nodes[node_id] = node

        # Connect guardrail to capabilities it protects
        # Match by: same source_file, or covers_tools overlap
        for cap in capabilities:
            connected = False
            # Same file = likely covers
            if _same_project(guard.source_file, cap.source_file):
                if guard.covers_tools and cap.function_name in guard.covers_tools:
                    connected = True
                elif guard.kind == "output_filter" and cap.kind == "outbound":
                    connected = True
                elif guard.kind == "hitl" and cap.kind in ("destructive", "outbound", "financial"):
                    connected = True
                elif guard.kind == "validation" and _same_file(guard.source_file, cap.source_file):
                    connected = True

            if connected:
                edge_type = EdgeType.FILTERED_BY if guard.kind == "output_filter" else EdgeType.GATED_BY
                graph.edges.append(GraphEdge(
                    source=_cap_node_id(cap), target=node_id,
                    edge_type=edge_type, has_control=True,
                    control_type=guard.kind,
                ))
```

**`_same_project` helper:** Two files are in the same project if they share a common parent directory up to 3 levels deep. For monorepos like crewAI-examples, `crews/stock_analysis/src/.../crew.py` and `crews/stock_analysis/src/.../tools/sec_tools.py` are the same project, but `crews/stock_analysis/...` and `flows/email_auto_responder/...` are NOT.

```python
def _same_project(file_a: str, file_b: str) -> bool:
    """Check if two files belong to the same sub-project."""
    parts_a = Path(file_a).parts
    parts_b = Path(file_b).parts
    # Find the deepest common prefix with at least 2 directory components
    common = 0
    for pa, pb in zip(parts_a, parts_b):
        if pa == pb:
            common += 1
        else:
            break
    return common >= 2  # At least share a top-level + one sub-level directory
```

#### Step 4: Agent nodes + relationship edges

```python
def _add_agent_nodes(graph, agent_profiles, crew_defs, agent_relationships):
    # Create agent nodes
    for agent in agent_profiles:
        agent_id = f"agent_{agent.name.lower().replace(' ', '_')}"
        node = GraphNode(
            id=agent_id, node_type=NodeType.AGENT,
            label=agent.role or agent.name, trust_level="internal",
            framework=agent.framework, source_file=agent.source_file,
            # data_sensitivity inferred from tools
            data_sensitivity=_infer_agent_sensitivity(agent, graph),
        )
        graph.nodes[agent_id] = node

        # TOOL_OF edges: connect agent to its capabilities
        for tool_name in agent.tool_names:
            for nid, n in graph.nodes.items():
                if n.node_type == NodeType.CAPABILITY and n.label == tool_name:
                    graph.edges.append(GraphEdge(
                        source=nid, target=agent_id,
                        edge_type=EdgeType.TOOL_OF, has_control=False,
                    ))

    # FEEDS_INTO edges: from crew definitions (sequential process)
    for crew in crew_defs:
        if crew.process_type == "sequential" and len(crew.agent_names) > 1:
            for i in range(len(crew.agent_names) - 1):
                src = f"agent_{crew.agent_names[i].lower().replace(' ', '_')}"
                tgt = f"agent_{crew.agent_names[i+1].lower().replace(' ', '_')}"
                if src in graph.nodes and tgt in graph.nodes:
                    graph.edges.append(GraphEdge(
                        source=src, target=tgt,
                        edge_type=EdgeType.FEEDS_INTO, has_control=False,
                    ))

        # Hierarchical process: manager delegates to all agents
        if crew.process_type == "hierarchical" and crew.has_manager:
            manager_id = f"agent_{crew.agent_names[0].lower().replace(' ', '_')}"
            for agent_name in crew.agent_names[1:]:
                agent_id = f"agent_{agent_name.lower().replace(' ', '_')}"
                if manager_id in graph.nodes and agent_id in graph.nodes:
                    graph.edges.append(GraphEdge(
                        source=manager_id, target=agent_id,
                        edge_type=EdgeType.DELEGATES_TO, has_control=False,
                    ))

    # SHARES_TOOL edges: agents that share the same tool
    for rel in agent_relationships:
        if rel.relationship_type == "shares_tool":
            src = f"agent_{rel.source_agent.lower().replace(' ', '_')}"
            tgt = f"agent_{rel.target_agent.lower().replace(' ', '_')}"
            if src in graph.nodes and tgt in graph.nodes:
                graph.edges.append(GraphEdge(
                    source=src, target=tgt,
                    edge_type=EdgeType.SHARES_TOOL, has_control=False,
                    data_sensitivity=_tool_sensitivity(rel.shared_resource),
                ))

    # Explicit relationships from parser output
    for rel in agent_relationships:
        if rel.relationship_type in ("delegates_to", "feeds_into"):
            src = f"agent_{rel.source_agent.lower().replace(' ', '_')}"
            tgt = f"agent_{rel.target_agent.lower().replace(' ', '_')}"
            if src in graph.nodes and tgt in graph.nodes:
                edge_type = EdgeType.DELEGATES_TO if rel.relationship_type == "delegates_to" else EdgeType.FEEDS_INTO
                # Don't duplicate if already added from crew_defs
                exists = any(e.source == src and e.target == tgt and e.edge_type == edge_type for e in graph.edges)
                if not exists:
                    graph.edges.append(GraphEdge(
                        source=src, target=tgt,
                        edge_type=edge_type, has_control=False,
                    ))
```

#### Step 5: Trust boundary crossings

```python
TRUST_LEVELS = {"restricted": 3, "internal": 2, "external": 1, "unknown": 0}

def _mark_trust_crossings(graph):
    for edge in graph.edges:
        src_node = graph.nodes.get(edge.source)
        tgt_node = graph.nodes.get(edge.target)
        if not src_node or not tgt_node:
            continue
        src_level = TRUST_LEVELS.get(src_node.trust_level, 0)
        tgt_level = TRUST_LEVELS.get(tgt_node.trust_level, 0)
        if src_level != tgt_level:
            edge.trust_crossing = True
            edge.crossing_direction = "outward" if src_level > tgt_level else "inward"
```

---

## GRAPH PATHFINDER: `stratum/graph/pathfinder.py`

This module finds uncontrolled paths through the graph — paths from sensitive data sources to external sinks with no guardrails in between.

```python
def find_uncontrolled_paths(graph: RiskGraph) -> list[RiskPath]:
    """Find all paths from data sources to external sinks with no guardrails."""
    # Identify source nodes (data stores with sensitivity != "public")
    sources = [n for n in graph.nodes.values()
               if n.node_type == NodeType.DATA_STORE
               and n.data_sensitivity in ("personal", "financial", "credentials", "internal")]

    # Identify sink nodes (external services)
    sinks = {n.id for n in graph.nodes.values()
             if n.node_type == NodeType.EXTERNAL_SERVICE}

    # BFS from each source, following edges, collecting paths
    paths = []
    for source in sources:
        visited = set()
        queue = [(source.id, [source.id], [], 0)]  # (current, path, edges, crossings)

        while queue:
            current, path, edge_list, crossings = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)

            # Found a source→sink path
            if current in sinks and len(path) > 1:
                has_control = any(e.has_control for e in edge_list)
                if not has_control:
                    missing = _infer_missing_controls(edge_list)
                    paths.append(RiskPath(
                        node_ids=path, edges=edge_list, hops=len(edge_list),
                        source_sensitivity=source.data_sensitivity,
                        destination_trust=graph.nodes[current].trust_level,
                        missing_controls=missing,
                        trust_crossings=crossings,
                        plain_english=_path_to_english(graph, path),
                    ))
                continue  # Don't extend past sinks

            # Follow outgoing edges
            for edge in graph.edges:
                if edge.source == current and edge.target not in visited:
                    new_crossings = crossings + (1 if edge.trust_crossing else 0)
                    queue.append((edge.target, path + [edge.target],
                                 edge_list + [edge], new_crossings))

    # Deduplicate: keep unique by (source, sink) pair, prefer longest path
    paths = _deduplicate_paths(paths)

    # Sort by: most trust crossings first, then most hops, then source sensitivity
    SENSITIVITY_RANK = {"financial": 4, "credentials": 3, "personal": 2, "internal": 1}
    paths.sort(key=lambda p: (p.trust_crossings, p.hops,
               SENSITIVITY_RANK.get(p.source_sensitivity, 0)), reverse=True)
    return paths[:20]  # Cap at 20

def compute_risk_surface(graph: RiskGraph) -> RiskSurface:
    """Compute aggregate risk surface metrics from the graph."""
    edges_needing = sum(1 for e in graph.edges if e.trust_crossing)
    edges_controlled = sum(1 for e in graph.edges if e.trust_crossing and e.has_control)

    return RiskSurface(
        total_nodes=len(graph.nodes),
        total_edges=len(graph.edges),
        uncontrolled_path_count=len(graph.uncontrolled_paths),
        max_path_hops=max((p.hops for p in graph.uncontrolled_paths), default=0),
        sensitive_data_types=list({n.data_sensitivity for n in graph.nodes.values()
                                   if n.data_sensitivity not in ("unknown", "public")}),
        external_sink_count=sum(1 for n in graph.nodes.values()
                                if n.node_type == NodeType.EXTERNAL_SERVICE),
        edges_with_controls=edges_controlled,
        edges_needing_controls=edges_needing,
        control_coverage_pct=round(edges_controlled / edges_needing * 100, 1) if edges_needing else 100.0,
        trust_boundary_crossings=sum(1 for e in graph.edges if e.trust_crossing),
        outward_crossings=sum(1 for e in graph.edges if e.crossing_direction == "outward"),
        inward_crossings=sum(1 for e in graph.edges if e.crossing_direction == "inward"),
    )

def _path_to_english(graph: RiskGraph, node_ids: list[str]) -> str:
    """Convert a path of node IDs to a readable string."""
    labels = []
    for nid in node_ids:
        node = graph.nodes.get(nid)
        if node:
            suffix = f" ({node.data_sensitivity})" if node.data_sensitivity not in ("unknown", "public") else ""
            labels.append(f"{node.label}{suffix}")
    return " → ".join(labels)
```

---

## PHASE 2: AGENT RELATIONSHIPS + GUARDRAIL MAPPING

### New Parser: `stratum/parsers/agents.py`

This parser extracts crew definitions, agent ordering, and inter-agent relationships.

```python
"""Extract agent relationships from CrewAI, LangGraph, and other frameworks."""

def extract_crew_definitions(python_files: list[tuple[str, str, ast.Module]]) -> list[CrewDefinition]:
    """Extract crew/flow definitions that group agents together.

    For CrewAI:
    - Find Crew() calls with agents=[...] and tasks=[...]
    - Detect process= parameter (sequential/hierarchical)
    - Find @CrewBase decorated classes with @agent/@task methods

    For LangGraph:
    - Find StateGraph().add_node() sequences
    - Extract edge definitions from .add_edge() and .add_conditional_edges()

    Returns ordered list of CrewDefinitions.
    """
```

**CrewAI crew extraction logic:**

```python
def _extract_crewai_crews(file_path: str, content: str, tree: ast.Module) -> list[CrewDefinition]:
    crews = []

    # Pattern 1: Direct Crew() instantiation
    # Look for: Crew(agents=[agent1, agent2], tasks=[...], process=Process.sequential)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_name(node.func, "Crew"):
            agents = _extract_list_arg(node, "agents")
            process = _extract_keyword_str(node, "process", default="sequential")
            has_manager = _has_keyword(node, "manager_llm") or _has_keyword(node, "manager_agent")

            if agents:
                crews.append(CrewDefinition(
                    name=_infer_crew_name(file_path),
                    framework="CrewAI",
                    agent_names=agents,
                    process_type="hierarchical" if has_manager else process,
                    source_file=file_path,
                    has_manager=has_manager,
                    delegation_enabled=any(_agent_allows_delegation(tree, a) for a in agents),
                ))

    # Pattern 2: @CrewBase class with @agent methods (CrewAI v2 pattern)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and _has_decorator(node, "CrewBase"):
            agent_methods = [n.name for n in node.body
                           if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                           and _has_decorator(n, "agent")]
            task_methods = [n.name for n in node.body
                          if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                          and _has_decorator(n, "task")]
            if agent_methods:
                crews.append(CrewDefinition(
                    name=node.name,
                    framework="CrewAI",
                    agent_names=agent_methods,
                    process_type="sequential",  # Default; override if process= found in @crew method
                    source_file=file_path,
                ))

    return crews
```

**Shared tool detection:**

```python
def detect_shared_tools(agent_profiles: list[AgentDefinition]) -> list[AgentRelationship]:
    """Find agents that share the same tool — a compounding risk signal."""
    tool_to_agents: dict[str, list[str]] = {}
    for agent in agent_profiles:
        for tool in agent.tool_names:
            tool_to_agents.setdefault(tool, []).append(agent.name)

    relationships = []
    for tool, agents in tool_to_agents.items():
        if len(agents) > 1:
            # Create pairwise relationships
            for i, a in enumerate(agents):
                for b in agents[i+1:]:
                    relationships.append(AgentRelationship(
                        source_agent=a, target_agent=b,
                        relationship_type="shares_tool",
                        shared_resource=tool,
                    ))
    return relationships
```

**Cross-crew flow detection (for monorepos):**

```python
def detect_cross_crew_flows(crew_defs: list[CrewDefinition],
                            python_files: list[tuple[str, str]]) -> list[AgentRelationship]:
    """Detect flows between crews — one crew's output feeding another's input.

    Heuristic: Look for Flow classes (@start, @listen, @router) that reference
    multiple crew classes. The @listen decorator implies data flow from one
    crew's output to another crew's input.
    """
    relationships = []

    for file_path, content in python_files:
        try:
            tree = ast.parse(content)
        except SyntaxError:
            continue

        # Find classes with @start/@listen decorators (CrewAI Flows)
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue

            # Collect crew references and flow connections
            start_methods = []
            listen_methods = []
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if _has_decorator(item, "start"):
                        start_methods.append(item)
                    if _has_decorator(item, "listen"):
                        listen_methods.append(item)

            # @listen(method_name) implies method_name's output → this method's input
            for listener in listen_methods:
                source_crew = _extract_listen_source(listener)
                target_crew = _infer_crew_from_method_body(listener, tree)
                if source_crew and target_crew and source_crew != target_crew:
                    relationships.append(AgentRelationship(
                        source_agent=source_crew,
                        target_agent=target_crew,
                        relationship_type="feeds_into",
                        source_file=file_path,
                    ))

    return relationships
```

### Guardrail `covers_tools` Population

Update `stratum/parsers/capabilities.py` — when detecting guardrails, populate `covers_tools`:

**For `output_pydantic` / `output_type` guardrails (CrewAI):**
```python
# When we find Task(..., output_pydantic=SomeModel)
# The task has an agent= assignment. That agent has tools.
# The guardrail covers those tools.
# Logic: find the Task's agent keyword → resolve to Agent definition → get tool list
```

**For `human_input=True` guardrails (CrewAI):**
```python
# Task(..., human_input=True) → covers all tools of the assigned agent
```

**For `isinstance` checks:**
```python
# These are generic validation — covers tools in the same function/file
# Set covers_tools to the tool names used in that function
```

**For `interrupt_before` guardrails (LangGraph):**
```python
# graph.compile(interrupt_before=["tool_name"]) → covers exactly those tools
```

**Implementation: in the guardrail detection loop, after creating a GuardrailSignal, attempt to resolve which tools it covers by looking at the surrounding AST context:**

```python
def _resolve_guardrail_coverage(guard: GuardrailSignal, tree: ast.Module,
                                 capabilities: list[Capability]) -> list[str]:
    """Determine which tools a guardrail protects."""
    covered = []

    if "output_pydantic" in guard.detail or "human_input" in guard.detail:
        # Find the Task() call at this line, extract agent=
        task_node = _find_call_at_line(tree, guard.line_number, "Task")
        if task_node:
            agent_name = _extract_keyword_str(task_node, "agent")
            if agent_name:
                # Find agent's tools
                covered = _find_agent_tools(tree, agent_name)

    elif "interrupt_before" in guard.detail:
        # Extract the list of tool names from the interrupt_before= argument
        covered = _parse_interrupt_list(guard.detail)

    elif "isinstance" in guard.detail:
        # Covers capabilities in the same file
        covered = [c.function_name for c in capabilities
                   if _same_file(c.source_file, guard.source_file)]

    return covered
```

---

## PHASE 3: BUSINESS + OPERATIONAL RISK RULES

### `stratum/rules/business_risk.py`

**These rules use the graph + capabilities + agent profiles. They do NOT invent risk. Every finding must point to concrete code.**

```python
"""Business risk rules — risks that impact the organization beyond technical security."""

def evaluate_business_risks(result: ScanResult) -> list[Finding]:
    findings = []
    findings.extend(_check_autonomous_external_comms(result))
    findings.extend(_check_financial_without_approval(result))
    findings.extend(_check_no_audit_trail(result))
    findings.extend(_check_unstructured_decisions(result))
    return findings
```

#### STRATUM-BR01: Autonomous External Communication

```python
def _check_autonomous_external_comms(result: ScanResult) -> list[Finding]:
    """Agents that send external messages without human review."""
    findings = []

    # Find outbound capabilities that send to humans (email, Slack, SMS, etc.)
    HUMAN_FACING = {"smtplib", "slack_sdk", "twilio", "GmailToolkit", "sendgrid"}

    human_outbound = [c for c in result.capabilities
                      if c.kind == "outbound"
                      and (c.library in HUMAN_FACING or c.function_name in HUMAN_FACING)]

    if not human_outbound:
        return []

    # Check if any of these are gated by HITL or output_filter
    for cap in human_outbound:
        has_hitl = any(
            g.kind in ("hitl", "output_filter")
            and (cap.function_name in g.covers_tools or _same_project(g.source_file, cap.source_file))
            for g in result.guardrails
        )
        if not has_hitl:
            # Find which agent owns this capability (if any)
            owning_agent = _find_owning_agent(cap, result.agent_profiles)
            agent_context = f" via agent '{owning_agent.role}'" if owning_agent else ""

            severity = "HIGH" if cap.confidence == "confirmed" else "MEDIUM"

            findings.append(Finding(
                id="STRATUM-BR01",
                severity=severity,
                confidence=cap.confidence,
                category="business",
                title=f"Agent sends external messages without human review",
                path=f"agent reasoning → {cap.function_name} → {_outbound_target(cap)}{agent_context}",
                description=(
                    f"Your agent sends messages to real humans via {cap.library or cap.function_name} "
                    f"with no review step. A hallucinated response, wrong information, or "
                    f"inappropriate tone goes directly to recipients."
                ),
                evidence=[f"{cap.source_file}:{cap.line_number}"],
                scenario=(
                    f"The agent drafts an email response to a customer complaint. "
                    f"It hallucinates a refund promise that doesn't match company policy. "
                    f"The email is sent immediately via {cap.function_name} — no one reviewed it."
                ),
                business_context="Reputation damage, incorrect commitments, potential liability.",
                remediation=_framework_remediation(result.detected_frameworks, "add_hitl", cap.function_name),
                effort="low",
                finding_class="business",
                owasp_id="ASI09",
                owasp_name="Human-Agent Trust Exploitation",
                quick_fix_type="add_hitl",
            ))

    return _deduplicate_findings(findings, "STRATUM-BR01")
```

#### STRATUM-BR02: Financial Action Without Approval

```python
def _check_financial_without_approval(result: ScanResult) -> list[Finding]:
    """Financial operations (payments, refunds, invoicing) with no approval gate."""

    FINANCIAL_LIBRARIES = {"stripe", "paypal", "braintree", "adyen", "square"}

    financial_caps = [c for c in result.capabilities
                      if c.kind == "financial"
                      or c.library in FINANCIAL_LIBRARIES
                      or (c.kind == "outbound" and any(f in (c.library or "").lower()
                          for f in ("stripe", "paypal", "payment", "invoice")))]

    if not financial_caps:
        return []

    findings = []
    for cap in financial_caps:
        has_approval = any(
            g.kind == "hitl"
            and (cap.function_name in g.covers_tools or _same_project(g.source_file, cap.source_file))
            for g in result.guardrails
        )
        if not has_approval:
            severity = "HIGH" if cap.confidence == "confirmed" else "MEDIUM"
            findings.append(Finding(
                id="STRATUM-BR02",
                severity=severity,
                confidence=cap.confidence,
                category="business",
                title="Financial operation with no approval gate",
                path=f"agent reasoning → {cap.function_name} → payment action, no approval",
                description=(
                    f"Your agent can trigger financial operations via {cap.library or cap.function_name} "
                    f"with no human approval step. A reasoning error or prompt injection "
                    f"could trigger unauthorized transactions."
                ),
                evidence=[f"{cap.source_file}:{cap.line_number}"],
                scenario=(
                    f"The agent processes a refund request. A prompt injection in the customer message "
                    f"changes the amount from $50 to $5,000. The charge is processed immediately."
                ),
                business_context="Direct financial loss, chargebacks, regulatory scrutiny.",
                remediation=_framework_remediation(result.detected_frameworks, "add_hitl", cap.function_name),
                effort="low",
                finding_class="business",
                owasp_id="ASI09",
                owasp_name="Human-Agent Trust Exploitation",
                quick_fix_type="add_hitl",
            ))
    return _deduplicate_findings(findings, "STRATUM-BR02")
```

#### STRATUM-BR03: No Audit Trail for Consequential Actions

```python
def _check_no_audit_trail(result: ScanResult) -> list[Finding]:
    """Consequential actions (destructive, financial, outbound) with no observability."""

    OBSERVABILITY_LIBRARIES = {
        "langsmith", "langfuse", "arize", "phoenix", "opentelemetry",
        "mlflow", "wandb", "helicone", "braintrust",
    }

    has_observability = any(
        any(obs in (c.library or "") for obs in OBSERVABILITY_LIBRARIES)
        for c in result.capabilities
    )
    # Also check env vars
    obs_env_vars = {"LANGCHAIN_TRACING_V2", "LANGFUSE_SECRET_KEY", "LANGFUSE_PUBLIC_KEY",
                    "LANGSMITH_API_KEY", "ARIZE_API_KEY", "OTEL_EXPORTER_OTLP_ENDPOINT",
                    "HELICONE_API_KEY", "BRAINTRUST_API_KEY"}
    if not has_observability:
        has_observability = any(ev.name in obs_env_vars for ev in result.env_vars)

    if has_observability:
        return []

    consequential = [c for c in result.capabilities
                     if c.kind in ("destructive", "financial", "outbound")
                     and c.confidence == "confirmed"]

    if len(consequential) < 2:
        return []

    return [Finding(
        id="STRATUM-BR03",
        severity="MEDIUM",
        confidence="confirmed",
        category="business",
        title=f"No audit trail for {len(consequential)} consequential actions",
        path=f"{len(consequential)} confirmed actions → no logging → no forensic trail",
        description=(
            f"Your agent performs {len(consequential)} confirmed consequential actions "
            f"(deletions, external sends, financial ops) but has no observability "
            f"library or tracing configured. When something goes wrong, there's no "
            f"trail to reconstruct what happened."
        ),
        evidence=["(no observability imports or env vars found)"],
        scenario=(
            f"A customer reports they received a wrong email from your agent. "
            f"You have no logs of what the agent sent, what prompt generated it, "
            f"or what data it accessed. You can't even confirm whether the email was sent."
        ),
        business_context="Compliance risk, inability to investigate incidents, no accountability.",
        remediation=(
            "Add observability. Options:\n"
            "  Langfuse (open source): pip install langfuse\n"
            "  LangSmith: set LANGCHAIN_TRACING_V2=true\n"
            "  OpenTelemetry: vendor-neutral, self-hostable."
        ),
        effort="low",
        finding_class="governance",
        owasp_id="ASI05",
        owasp_name="Insufficient Sandboxing / Control",
    )]
```

#### STRATUM-BR04: Decision-Making Without Structured Output

```python
def _check_unstructured_decisions(result: ScanResult) -> list[Finding]:
    """Agents making classification/approval decisions without structured output.

    Only fires when we can confirm an agent with decision-like role has no
    output_pydantic or output_type on its tasks.
    """
    DECISION_KEYWORDS = {"approv", "classif", "scor", "evaluat", "filter", "triage",
                         "review", "assess", "judge", "rate", "rank"}

    findings = []
    for agent in result.agent_profiles:
        role_lower = (agent.role or "").lower()
        name_lower = (agent.name or "").lower()
        combined = role_lower + " " + name_lower

        is_decision_agent = any(kw in combined for kw in DECISION_KEYWORDS)
        if not is_decision_agent:
            continue

        # Check if this agent's tasks have structured output
        has_structured = any(
            g.kind == "validation"
            and "output_pydantic" in g.detail
            and _same_project(g.source_file, agent.source_file)
            for g in result.guardrails
        )

        if not has_structured:
            findings.append(Finding(
                id="STRATUM-BR04",
                severity="MEDIUM",
                confidence="probable",
                category="business",
                title=f"Decision agent '{agent.role or agent.name}' has no structured output",
                path=f"input → {agent.name} (decision-making) → unstructured output → downstream action",
                description=(
                    f"Agent '{agent.role or agent.name}' appears to make classification or "
                    f"evaluation decisions but produces unstructured output. Downstream consumers "
                    f"have no schema to validate against, making results inconsistent and unexplainable."
                ),
                evidence=[agent.source_file],
                scenario=(
                    f"The agent evaluates a candidate and outputs free text. "
                    f"Sometimes it says 'approved', sometimes 'looks good', sometimes 'pass'. "
                    f"The downstream system can't reliably parse the decision."
                ),
                business_context="Inconsistent decisions, unexplainable outcomes, audit failure.",
                remediation=_framework_remediation(result.detected_frameworks, "add_structured_output", agent.name),
                effort="low",
                finding_class="business",
                owasp_id="ASI10",
                owasp_name="Rogue Agents",
            ))

    return findings[:3]  # Cap at 3, don't overwhelm
```

### `stratum/rules/operational_risk.py`

```python
"""Operational risk rules — things that cause outages, cost overruns, or degraded service."""

def evaluate_operational_risks(result: ScanResult) -> list[Finding]:
    findings = []
    findings.extend(_check_single_provider(result))
    findings.extend(_check_no_cost_controls(result))
    findings.extend(_check_error_handling(result))
    findings.extend(_check_timeouts(result))
    findings.extend(_check_checkpointing(result))
    return findings
```

#### STRATUM-OP01: Single Model Provider Dependency

```python
def _check_single_provider(result: ScanResult) -> list[Finding]:
    """All agents depend on a single LLM provider with no fallback."""

    # Detect providers from env vars and imports
    PROVIDERS = {
        "openai": ["OPENAI_API_KEY", "ChatOpenAI", "openai"],
        "anthropic": ["ANTHROPIC_API_KEY", "ChatAnthropic", "anthropic"],
        "google": ["GOOGLE_API_KEY", "ChatGoogleGenerativeAI", "google"],
        "azure": ["AZURE_OPENAI_API_KEY", "AzureChatOpenAI"],
    }

    detected_providers = set()
    for provider, signals in PROVIDERS.items():
        for signal in signals:
            if any(signal in (ev.name or "") for ev in result.env_vars):
                detected_providers.add(provider)
            if any(signal in (c.library or "") or signal in (c.evidence or "")
                   for c in result.capabilities):
                detected_providers.add(provider)

    if len(detected_providers) != 1:
        return []

    provider = detected_providers.pop()
    return [Finding(
        id="STRATUM-OP01",
        severity="MEDIUM",
        confidence="confirmed",
        category="operational",
        title=f"All agents depend on {provider} — no fallback provider",
        path=f"{len(result.agent_profiles)} agents → {provider} → single point of failure",
        description=(
            f"Every agent in this project runs on {provider}. "
            f"A provider outage, rate limit, or API deprecation halts everything simultaneously."
        ),
        evidence=[f"env: {provider.upper()}_API_KEY"],
        scenario=(
            f"{provider.capitalize()} has a 4-hour outage (this has happened multiple times). "
            f"All {len(result.agent_profiles)} agents stop responding. "
            f"Users get errors. Workflows stall mid-execution."
        ),
        business_context="Service availability risk, vendor lock-in.",
        remediation=(
            f"Add a fallback provider. Use litellm for provider abstraction:\n"
            f"  pip install litellm\n"
            f"  from litellm import completion\n"
            f"  response = completion(model='{provider}/gpt-4', fallbacks=['anthropic/claude-3.5-sonnet'])"
        ),
        effort="med",
        finding_class="reliability",
        owasp_id="ASI08",
        owasp_name="Cascading Failures",
    )]
```

#### STRATUM-OP02: No Cost Controls

```python
def _check_no_cost_controls(result: ScanResult) -> list[Finding]:
    """No max_iterations, max_tokens, or rate limiting detected."""

    # Check for cost control signals in guardrails and env vars
    COST_SIGNALS = {"max_iter", "max_rpm", "max_tokens", "rate_limit",
                    "recursion_limit", "max_turns", "budget"}

    has_cost_control = any(
        any(sig in (g.detail or "").lower() for sig in COST_SIGNALS)
        for g in result.guardrails
    )

    if has_cost_control:
        return []

    # Only fire if there are enough capabilities to be concerning
    if result.total_capabilities < 5:
        return []

    return [Finding(
        id="STRATUM-OP02",
        severity="MEDIUM",
        confidence="confirmed",
        category="operational",
        title="No cost controls on agent execution",
        path=f"{result.total_capabilities} capabilities × no iteration limit → unbounded spend",
        description=(
            f"No max_iterations, max_rpm, rate_limit, or token budget detected across "
            f"{result.total_capabilities} capabilities. A reasoning loop or retry storm "
            f"can generate thousands of API calls."
        ),
        evidence=["(no cost control signals found)"],
        scenario=(
            "The agent enters a retry loop trying to parse a malformed response. "
            "Each retry makes an LLM call. After 2,000 iterations, you have a $500 API bill "
            "and no useful output."
        ),
        business_context="Surprise cost, resource exhaustion.",
        remediation=_framework_remediation(result.detected_frameworks, "add_cost_controls", ""),
        effort="low",
        finding_class="reliability",
        owasp_id="ASI08",
        owasp_name="Cascading Failures",
    )]
```

**(STRATUM-008 error handling and STRATUM-009 timeouts already exist and work. Keep them.)**

**(STRATUM-010 checkpointing already exists. Keep it but improve the remediation to be framework-aware.)**

---

## PHASE 4: COMPOUNDING RISK RULES

### `stratum/rules/compounding_risk.py`

**This is the thesis differentiator. These rules find risks that only exist because of agent interactions — no single agent is dangerous alone, but together they create emergent risk.**

**Every compounding finding must explain: "Agent A does X. Agent B does Y. Together, they create Z risk that neither has alone."**

```python
"""Compounding risk rules — emergent risks from agent interactions.

These rules require the graph. They look for structural patterns where
individually acceptable agent configurations combine to create risks
that no single agent analysis would catch.
"""

def evaluate_compounding_risks(result: ScanResult) -> list[Finding]:
    findings = []
    findings.extend(_check_shared_tool_different_trust(result))
    findings.extend(_check_chain_amplification(result))
    findings.extend(_check_cross_boundary_delegation(result))
    findings.extend(_check_uncoordinated_external_writes(result))
    return findings
```

#### STRATUM-CR01: Shared Tool, Different Trust Contexts

```python
def _check_shared_tool_different_trust(result: ScanResult) -> list[Finding]:
    """Two agents share a tool but operate in different trust contexts.

    Example: An email_filter_agent (processes untrusted external email) and
    an email_response_writer (sends external messages) both use GmailToolkit.
    The filter agent's compromised context can influence the writer's outbound
    messages through the shared tool's state or configuration.

    This is the pattern behind EchoLeak: the ingestion agent and the action
    agent share the same tool/API surface with no isolation between them.
    """
    findings = []

    # Group agents by shared tools
    tool_agents: dict[str, list[AgentDefinition]] = {}
    for agent in result.agent_profiles:
        for tool in agent.tool_names:
            tool_agents.setdefault(tool, []).append(agent)

    for tool_name, agents in tool_agents.items():
        if len(agents) < 2:
            continue

        # Check if agents have different trust contexts
        # Trust context inferred from: does agent process external input?
        ingestion_agents = [a for a in agents if _processes_external_input(a, result)]
        action_agents = [a for a in agents if _performs_actions(a, result)]

        for ingest in ingestion_agents:
            for actor in action_agents:
                if ingest.name == actor.name:
                    continue

                # This is a compounding risk: ingestion + action on same tool
                findings.append(Finding(
                    id="STRATUM-CR01",
                    severity="HIGH",
                    confidence="confirmed" if _both_confirmed(ingest, actor, result) else "probable",
                    category="compounding",
                    title=f"Shared tool '{tool_name}' bridges untrusted input to external action",
                    path=(
                        f"untrusted input → {ingest.role or ingest.name} → [{tool_name}] "
                        f"→ {actor.role or actor.name} → external action"
                    ),
                    description=(
                        f"Agent '{ingest.role or ingest.name}' processes external/untrusted input "
                        f"and shares '{tool_name}' with agent '{actor.role or actor.name}', "
                        f"which performs external actions. A prompt injection in the input can "
                        f"propagate through the shared tool context to trigger unauthorized actions."
                    ),
                    evidence=[ingest.source_file, actor.source_file],
                    scenario=(
                        f"A crafted email arrives. '{ingest.name}' processes it and its context "
                        f"is now influenced by the injected instructions. '{actor.name}' shares "
                        f"the same tool ({tool_name}) and acts on the contaminated context — "
                        f"sending a response the attacker designed."
                    ),
                    business_context=(
                        "This is the architectural pattern behind real-world AI exfiltration incidents. "
                        "No individual agent is misconfigured — the risk emerges from the interaction."
                    ),
                    remediation=(
                        f"Isolate trust contexts between agents:\n"
                        f"  1. Use separate tool instances for {ingest.name} and {actor.name}\n"
                        f"  2. Add an output filter on {ingest.name} before passing to {actor.name}\n"
                        f"  3. Add human_input=True on {actor.name}'s outbound tasks"
                    ),
                    effort="med",
                    finding_class="compounding",
                    owasp_id="ASI01",
                    owasp_name="Agent Goal Hijacking",
                    references=["https://embracethered.com/blog/posts/2024/m365-copilot-echo-leak/"],
                ))

    return _deduplicate_findings(findings, "STRATUM-CR01")
```

#### STRATUM-CR02: Chain Amplification — Error Propagation Across Agent Chain

```python
def _check_chain_amplification(result: ScanResult) -> list[Finding]:
    """Sequential agent chains where errors/hallucinations amplify through each step.

    In a sequential crew with no validation between agents, Agent 1's hallucination
    becomes Agent 2's ground truth, which becomes Agent 3's confident assertion.
    Each step strips uncertainty markers and adds false confidence.
    """
    findings = []

    for crew in result.crew_definitions:
        if crew.process_type != "sequential" or len(crew.agent_names) < 3:
            continue

        # Check for inter-agent validation
        # Validation = output_pydantic on intermediate tasks, or validation guardrails
        # between agents
        intermediate_agents = crew.agent_names[1:-1]
        has_intermediate_validation = False
        for agent_name in intermediate_agents:
            has_validation = any(
                g.kind == "validation"
                and "output_pydantic" in g.detail
                and _agent_in_guardrail_scope(agent_name, g, result)
                for g in result.guardrails
            )
            if has_validation:
                has_intermediate_validation = True
                break

        if not has_intermediate_validation:
            chain_str = " → ".join(crew.agent_names)
            findings.append(Finding(
                id="STRATUM-CR02",
                severity="MEDIUM",
                confidence="probable",
                category="compounding",
                title=f"{len(crew.agent_names)}-agent chain with no intermediate validation",
                path=f"{chain_str} (no validation between steps)",
                description=(
                    f"Crew '{crew.name}' runs {len(crew.agent_names)} agents sequentially "
                    f"with no structured output validation between steps. "
                    f"A hallucination in step 1 propagates through the chain, "
                    f"gaining false confidence at each step."
                ),
                evidence=[crew.source_file],
                scenario=(
                    f"'{crew.agent_names[0]}' hallucinates a data point. "
                    f"'{crew.agent_names[1]}' treats it as fact and builds analysis on it. "
                    f"By the time '{crew.agent_names[-1]}' produces the final output, "
                    f"the hallucination is deeply embedded and presented with high confidence."
                ),
                business_context=(
                    "Compounding hallucination risk. Each unvalidated step amplifies errors. "
                    "The final output may be confidently wrong."
                ),
                remediation=(
                    f"Add structured output validation between steps:\n"
                    f"  task = Task(\n"
                    f"      description=\"...\",\n"
                    f"+     output_pydantic=IntermediateResult,  # schema validates between steps\n"
                    f"  )"
                ),
                effort="med",
                finding_class="compounding",
                owasp_id="ASI10",
                owasp_name="Rogue Agents",
            ))

    return findings
```

#### STRATUM-CR03: Cross-Boundary Delegation

```python
def _check_cross_boundary_delegation(result: ScanResult) -> list[Finding]:
    """An agent with low-privilege tools delegates to an agent with high-privilege tools.

    Or: an agent that processes untrusted input can delegate to an agent that
    performs destructive/financial/outbound actions.
    """
    findings = []

    for rel in result.agent_relationships:
        if rel.relationship_type not in ("delegates_to", "feeds_into"):
            continue

        source = _find_agent(rel.source_agent, result.agent_profiles)
        target = _find_agent(rel.target_agent, result.agent_profiles)
        if not source or not target:
            continue

        source_cap_kinds = _agent_cap_kinds(source, result)
        target_cap_kinds = _agent_cap_kinds(target, result)

        # Check for privilege escalation: source has read-only, target has write/external
        source_is_reader = source_cap_kinds <= {"data_access", "outbound"}
        target_has_power = target_cap_kinds & {"destructive", "financial"}

        if source_is_reader and target_has_power:
            findings.append(Finding(
                id="STRATUM-CR03",
                severity="HIGH",
                confidence="probable",
                category="compounding",
                title=f"'{source.name}' can influence '{target.name}' which has destructive capabilities",
                path=(
                    f"{source.role or source.name} ({', '.join(source_cap_kinds)}) "
                    f"→ {target.role or target.name} ({', '.join(target_cap_kinds)})"
                ),
                description=(
                    f"Agent '{source.role or source.name}' feeds into or delegates to "
                    f"'{target.role or target.name}', which has {', '.join(target_cap_kinds & {'destructive', 'financial'})} "
                    f"capabilities. A compromise of the upstream agent's reasoning can "
                    f"trigger destructive actions through the downstream agent."
                ),
                evidence=[source.source_file, target.source_file],
                scenario=(
                    f"'{source.name}' is tricked via prompt injection into requesting a destructive action. "
                    f"'{target.name}' receives this as a legitimate instruction from a trusted peer "
                    f"and executes the action — because there's no privilege boundary between them."
                ),
                business_context="Privilege escalation through agent chain. Same pattern as ServiceNow Now Assist incident.",
                remediation=(
                    f"Add an approval gate between {source.name} and {target.name}:\n"
                    f"  - Validate {source.name}'s output schema before passing to {target.name}\n"
                    f"  - Add human_input=True on {target.name}'s destructive tasks\n"
                    f"  - Log all cross-agent delegations for audit"
                ),
                effort="med",
                finding_class="compounding",
                owasp_id="ASI01",
                owasp_name="Agent Goal Hijacking",
                references=["https://sombrainc.com/blog/llm-security-risks-2026"],
            ))

    return _deduplicate_findings(findings, "STRATUM-CR03")
```

#### STRATUM-CR04: Uncoordinated External Writes

```python
def _check_uncoordinated_external_writes(result: ScanResult) -> list[Finding]:
    """Multiple agents write to the same external service with no coordination.

    Example: One agent sends email via GmailToolkit AND another agent sends
    Slack messages via slack_sdk — both operating on the same user request
    with no deduplication, ordering, or consistency guarantee.
    """
    findings = []

    # Group outbound capabilities by external target (coarse)
    target_caps: dict[str, list[tuple[Capability, str]]] = {}  # target → [(cap, agent_name)]
    for cap in result.capabilities:
        if cap.kind != "outbound":
            continue
        target = _outbound_target(cap)
        owning_agent = _find_owning_agent(cap, result.agent_profiles)
        agent_name = owning_agent.name if owning_agent else "unknown"
        target_caps.setdefault(target, []).append((cap, agent_name))

    # Look for different agents writing to the same target class
    COMMS_TARGETS = {"Gmail outbound", "Slack", "SMTP outbound", "Twilio SMS"}
    for target, caps_and_agents in target_caps.items():
        if target not in COMMS_TARGETS:
            continue
        unique_agents = set(agent for _, agent in caps_and_agents if agent != "unknown")
        if len(unique_agents) < 2:
            continue

        agent_list = ", ".join(unique_agents)
        findings.append(Finding(
            id="STRATUM-CR04",
            severity="MEDIUM",
            confidence="probable",
            category="compounding",
            title=f"Multiple agents send to {target} with no coordination",
            path=f"{agent_list} → {target} (no dedup, no ordering)",
            description=(
                f"Agents {agent_list} all send messages via {target} with no coordination layer. "
                f"A single user action could trigger multiple, inconsistent messages — "
                f"or the same message sent twice."
            ),
            evidence=[c.source_file for c, _ in caps_and_agents],
            scenario=(
                f"A user request triggers two agents. Both decide to respond via {target}. "
                f"The recipient gets two messages with slightly different information, "
                f"creating confusion about which is authoritative."
            ),
            business_context="Brand inconsistency, customer confusion, message fatigue.",
            remediation=(
                f"Add a coordination layer:\n"
                f"  - Route all {target} messages through a single outbound agent\n"
                f"  - Add deduplication on recipient+topic within a time window\n"
                f"  - Use a message queue with exactly-once delivery"
            ),
            effort="med",
            finding_class="compounding",
            owasp_id="ASI08",
            owasp_name="Cascading Failures",
        ))

    return findings
```

### Helper Functions for Compounding Rules

```python
def _processes_external_input(agent: AgentDefinition, result: ScanResult) -> bool:
    """Does this agent process untrusted/external input?"""
    # Check role/name for input-processing signals
    INPUT_SIGNALS = {"filter", "read", "ingest", "parse", "receive",
                     "scan", "fetch", "scrape", "monitor", "watch"}
    role_lower = (agent.role or "").lower() + " " + (agent.name or "").lower()
    if any(sig in role_lower for sig in INPUT_SIGNALS):
        return True

    # Check if agent's tools include data_access from external sources
    for tool in agent.tool_names:
        for cap in result.capabilities:
            if cap.function_name == f"[{tool}]" or cap.function_name == tool:
                if cap.kind == "data_access" and cap.trust_level == "external":
                    return True
    return False

def _performs_actions(agent: AgentDefinition, result: ScanResult) -> bool:
    """Does this agent perform external/consequential actions?"""
    ACTION_SIGNALS = {"write", "send", "respond", "action", "execute",
                      "draft", "post", "notify", "dispatch", "create"}
    role_lower = (agent.role or "").lower() + " " + (agent.name or "").lower()
    if any(sig in role_lower for sig in ACTION_SIGNALS):
        return True

    for tool in agent.tool_names:
        for cap in result.capabilities:
            if cap.function_name == f"[{tool}]" or cap.function_name == tool:
                if cap.kind in ("outbound", "destructive", "financial"):
                    return True
    return False

def _agent_cap_kinds(agent: AgentDefinition, result: ScanResult) -> set[str]:
    """Get the set of capability kinds for an agent's tools."""
    kinds = set()
    for tool in agent.tool_names:
        for cap in result.capabilities:
            if cap.function_name == f"[{tool}]" or cap.function_name == tool:
                kinds.add(cap.kind)
    return kinds
```

---

## PHASE 5: INCIDENT MATCHING + FRAMEWORK-AWARE REMEDIATION

### Enhanced Incident Matching: `stratum/knowledge/incidents.py`

Update the incident matching function to produce `IncidentMatch` objects with `match_reason`:

```python
INCIDENT_DB = [
    {
        "id": "ECHOLEAK-2025",
        "name": "Microsoft Copilot EchoLeak",
        "date": "2025-Q1",
        "impact": "$200M+ est. across 160+ reported incidents",
        "attack_summary": "Zero-click prompt injection via email. Copilot ingested crafted email, extracted data from OneDrive/SharePoint/Teams, and exfiltrated it through trusted Microsoft domains.",
        "source_url": "https://embracethered.com/blog/posts/2024/m365-copilot-echo-leak/",
        # Match patterns:
        "required_cap_kinds": ["data_access", "outbound"],
        "tool_signals": ["gmail", "email", "outlook", "inbox", "thread"],
        "pattern": "data_ingestion_to_outbound",
    },
    {
        "id": "SLACK-AI-EXFIL-2024",
        "name": "Slack AI Data Exfiltration",
        "date": "2024-H2",
        "impact": "Private channel data leaked via crafted message links",
        "attack_summary": "Hidden instructions in Slack messages caused AI assistant to insert malicious link. Clicking it sent private channel data to attacker's server.",
        "source_url": "https://promptarmor.substack.com/p/data-exfiltration-from-slack-ai-via",
        "required_cap_kinds": ["data_access", "outbound"],
        "tool_signals": ["slack", "chat", "message", "channel"],
        "pattern": "data_ingestion_to_outbound",
    },
    {
        "id": "SERVICENOW-NOWASSIST-2025",
        "name": "ServiceNow Now Assist Privilege Escalation",
        "date": "2025-H2",
        "impact": "Cross-tenant case file exfiltration",
        "attack_summary": "Second-order prompt injection: low-privilege agent tricks high-privilege agent into exporting case files to external URL.",
        "source_url": "https://sombrainc.com/blog/llm-security-risks-2026",
        "required_cap_kinds": ["data_access", "outbound"],
        "tool_signals": [],  # Pattern-based, not tool-specific
        "pattern": "cross_agent_privilege_escalation",
    },
    {
        "id": "DOCKER-GORDON-2025",
        "name": "Docker Ask Gordon Prompt Injection",
        "date": "2025-Q4",
        "impact": "Sensitive data exfiltration via poisoned Docker Hub metadata",
        "attack_summary": "Prompt injection via crafted Docker Hub repository metadata. AI assistant auto-executed tools to fetch payloads from attacker-controlled servers without user consent.",
        "source_url": "https://www.docker.com/blog/docker-security-advisory-ask-gordon/",
        "required_cap_kinds": ["outbound"],
        "tool_signals": ["fetch", "http", "requests", "scrape", "search"],
        "pattern": "auto_tool_execution",
    },
]

def match_incidents(result: ScanResult) -> list[IncidentMatch]:
    """Match scan results against known incident patterns and explain WHY."""
    matches = []
    cap_kinds = {c.kind for c in result.capabilities if c.confidence == "confirmed"}
    tool_names = {(c.library or "").lower() for c in result.capabilities}
    tool_names.update({(c.function_name or "").lower().strip("[]") for c in result.capabilities})

    for incident in INCIDENT_DB:
        # Check required capability kinds
        if not all(k in cap_kinds for k in incident["required_cap_kinds"]):
            continue

        # Compute confidence based on pattern + tool match
        confidence = 0.5  # base: capability kinds match
        tool_matches = [sig for sig in incident["tool_signals"]
                       if any(sig in tn for tn in tool_names)]
        if tool_matches:
            confidence += 0.25

        # Pattern-specific boosts
        if incident["pattern"] == "cross_agent_privilege_escalation":
            if any(r.relationship_type in ("delegates_to", "feeds_into")
                   for r in result.agent_relationships):
                confidence += 0.25

        if incident["pattern"] == "data_ingestion_to_outbound":
            # Check if there's a data_access→outbound path in the graph
            if any(p.source_sensitivity in ("personal", "financial")
                   for p in result.graph.uncontrolled_paths):
                confidence += 0.25

        if confidence < 0.5:
            continue

        confidence = min(confidence, 1.0)

        # Generate match_reason — the key differentiator
        match_reason = _generate_match_reason(incident, result, tool_matches)
        matching_files = _get_matching_files(incident, result, tool_matches)

        matches.append(IncidentMatch(
            incident_id=incident["id"],
            name=incident["name"],
            date=incident["date"],
            impact=incident["impact"],
            confidence=confidence,
            attack_summary=incident["attack_summary"],
            source_url=incident["source_url"],
            match_reason=match_reason,
            matching_capabilities=[c.function_name for c in result.capabilities
                                   if c.kind in incident["required_cap_kinds"]
                                   and c.confidence == "confirmed"][:5],
            matching_files=matching_files[:5],
        ))

    matches.sort(key=lambda m: m.confidence, reverse=True)
    return matches


def _generate_match_reason(incident: dict, result: ScanResult,
                           tool_matches: list[str]) -> str:
    """Generate a human-readable explanation of WHY this incident pattern matched."""

    if incident["pattern"] == "data_ingestion_to_outbound":
        # Find the most specific data source and outbound target
        data_sources = [c for c in result.capabilities if c.kind == "data_access"]
        outbound_targets = [c for c in result.capabilities if c.kind == "outbound"]

        source_name = data_sources[0].function_name if data_sources else "data source"
        target_name = outbound_targets[0].function_name if outbound_targets else "external service"

        return (
            f"Your code reads data via {source_name} and sends it externally via "
            f"{target_name} — the same data→external pattern that enabled "
            f"{incident['name']}. In that incident, {incident['attack_summary'].split('.')[0].lower()}."
        )

    elif incident["pattern"] == "cross_agent_privilege_escalation":
        agents_with_power = [a for a in result.agent_profiles
                            if _agent_cap_kinds(a, result) & {"destructive", "financial", "outbound"}]
        agent_name = agents_with_power[0].name if agents_with_power else "a high-privilege agent"
        return (
            f"Your agent architecture has cross-agent delegation where one agent can "
            f"influence {agent_name}'s actions — similar to the {incident['name']} pattern "
            f"where a low-privilege agent tricked a high-privilege agent into exfiltrating data."
        )

    elif incident["pattern"] == "auto_tool_execution":
        http_tools = [c for c in result.capabilities
                     if c.kind == "outbound" and c.library in ("requests", "httpx")]
        tool_name = http_tools[0].function_name if http_tools else "HTTP tools"
        return (
            f"Your agent auto-executes {tool_name} to fetch external content — "
            f"the same pattern as {incident['name']}. In that incident, "
            f"poisoned metadata triggered tools to fetch attacker-controlled payloads."
        )

    return f"Architectural similarity to {incident['name']}."
```

### Framework-Aware Remediation: `stratum/knowledge/remediation.py`

```python
"""Generate framework-specific remediation snippets."""

REMEDIATIONS = {
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


def _framework_remediation(detected_frameworks: list[str], fix_type: str,
                           tool_name: str = "") -> str:
    """Return framework-specific remediation based on detected frameworks."""
    fixes = REMEDIATIONS.get(fix_type, {})

    # Try detected frameworks in order
    for fw in detected_frameworks:
        if fw in fixes:
            return fixes[fw].replace("{tool_name}", tool_name)

    return fixes.get("_default", "See framework documentation for remediation guidance.")
```

---

## PHASE 6: TELEMETRY + OUTPUT + SCANNER INTEGRATION

### Enriched Telemetry: `stratum/telemetry/profile.py`

```python
@dataclass
class TelemetryProfile:
    # Existing fields (keep all):
    topology_signature: str
    archetype: str
    archetype_confidence: float
    framework_fingerprint: list[str]
    capability_fingerprint: dict[str, int]

    # NEW fields:
    agent_count: int = 0
    crew_count: int = 0
    agent_role_diversity: float = 0.0       # Unique roles / total agents
    max_chain_length: int = 0               # Longest sequential agent chain
    shared_tool_pairs: int = 0              # Number of agent pairs sharing tools
    trust_boundary_crossings: int = 0
    outward_crossings: int = 0              # Data leaving internal boundaries
    control_coverage_pct: float = 0.0       # Edges with controls / edges needing controls
    guardrail_to_capability_ratio: float = 0.0
    has_observability: bool = False
    has_cost_controls: bool = False
    risk_category_counts: dict[str, int] = field(default_factory=dict)
    # {"security": 2, "business": 1, "operational": 3, "compounding": 1}

def build_telemetry_profile(result: ScanResult) -> TelemetryProfile:
    """Build enriched telemetry profile for risk map."""
    base = _build_base_profile(result)  # existing logic

    # Enrich with new fields
    base.agent_count = len(result.agent_profiles)
    base.crew_count = len(result.crew_definitions)

    unique_roles = len({a.role for a in result.agent_profiles if a.role})
    base.agent_role_diversity = round(unique_roles / max(base.agent_count, 1), 2)

    base.max_chain_length = max(
        (len(c.agent_names) for c in result.crew_definitions
         if c.process_type == "sequential"), default=0
    )

    base.shared_tool_pairs = sum(
        1 for r in result.agent_relationships if r.relationship_type == "shares_tool"
    )

    if result.graph.risk_surface:
        base.trust_boundary_crossings = result.graph.risk_surface.trust_boundary_crossings
        base.outward_crossings = result.graph.risk_surface.outward_crossings
        base.control_coverage_pct = result.graph.risk_surface.control_coverage_pct

    base.guardrail_to_capability_ratio = round(
        result.guardrail_count / max(result.total_capabilities, 1), 2
    )

    # Count findings by category
    all_findings = result.top_paths + result.signals
    for f in all_findings:
        cat = f.category or f.finding_class or "unknown"
        base.risk_category_counts[cat] = base.risk_category_counts.get(cat, 0) + 1

    return base
```

### Terminal Output Updates: `stratum/output/terminal.py`

Add two new output sections:

**1. Graph topology summary (appears after findings):**

```
 ─── TOPOLOGY ─────────────────────────────────────────────────

  32 nodes · 47 edges · 12 trust boundary crossings
  Control coverage: 23% (3 of 13 crossing edges have guardrails)

  Data flows:
    Gmail inbox (personal)  ──▶  GmailGetThread  ──▶  GmailToolkit  ──▶  Gmail outbound    ⚠ no filter
    Gmail inbox (personal)  ──▶  GmailGetThread  ──▶  slack_sdk     ──▶  Slack             ⚠ no filter
    Gmail inbox (personal)  ──▶  GmailGetThread  ──▶  requests      ──▶  HTTP endpoint     ⚠ no filter

  Agent chains:
    email_filter_agent → email_action_agent → email_response_writer  (3 agents, 0 intermediate validations)
```

Show max 5 uncontrolled paths. Show max 3 agent chains.

**2. Incident matches with reasons (after topology):**

```
 ─── INCIDENT MATCHES ─────────────────────────────────────────

  ● Microsoft Copilot EchoLeak (confidence: 100%)
    Your email_auto_responder_flow reads untrusted email content and routes it
    through outbound tools — the same data→external pattern that enabled EchoLeak.
    Impact: $200M+ est. across 160+ reported incidents
    ↗ https://embracethered.com/blog/posts/2024/m365-copilot-echo-leak/

  ● Slack AI Data Exfiltration (confidence: 75%)
    Your code uses slack_sdk.chat_postMessage with agent-generated content —
    the same pattern that enabled data extraction via Slack AI.
    ↗ https://promptarmor.substack.com/p/data-exfiltration-from-slack-ai-via
```

**3. Summary line update:**

Current: `▸ 3 security paths · 1 business risk · 2 operational risks`
New: `▸ 1 critical · 1 high · 3 medium │ security: 2 · business: 2 · operational: 3 · compounding: 2`

### Scanner Integration: `stratum/scanner.py`

Add these steps to the scan pipeline, AFTER capabilities/guardrails/agents are collected, BEFORE risk scoring:

```python
# === NEW PATCH STEPS ===

# Step N+1: Extract crew definitions and agent relationships
from stratum.parsers.agents import (
    extract_crew_definitions, detect_shared_tools, detect_cross_crew_flows
)
crew_definitions = extract_crew_definitions(python_files_with_ast)
shared_tool_rels = detect_shared_tools(agent_profiles)
cross_crew_rels = detect_cross_crew_flows(crew_definitions, python_files)
agent_relationships = shared_tool_rels + cross_crew_rels

# Step N+2: Populate guardrail covers_tools
from stratum.parsers.capabilities import resolve_guardrail_coverage
for guard in guardrails:
    guard.covers_tools = resolve_guardrail_coverage(guard, ast_trees, capabilities)

# Step N+3: Build graph
from stratum.graph import build_graph
result.crew_definitions = crew_definitions
result.agent_relationships = agent_relationships
result.graph = build_graph(result)

# Step N+4: Run business risk rules
from stratum.rules.business_risk import evaluate_business_risks
business_findings = evaluate_business_risks(result)

# Step N+5: Run operational risk rules
from stratum.rules.operational_risk import evaluate_operational_risks
operational_findings = evaluate_operational_risks(result)

# Step N+6: Run compounding risk rules
from stratum.rules.compounding_risk import evaluate_compounding_risks
compounding_findings = evaluate_compounding_risks(result)

# Step N+7: Enhanced incident matching
from stratum.knowledge.incidents import match_incidents
result.incident_matches = match_incidents(result)

# Step N+8: Merge all findings into the engine
all_new_findings = business_findings + operational_findings + compounding_findings
# Run severity gating on all new findings
for f in all_new_findings:
    f = engine._gate_severity(f)
# Merge into top_paths/signals split
# top_paths: severity >= HIGH or category in ("security", "compounding")
# signals: everything else
```

### Updated Risk Score

Add compounding risk bonuses:

```python
# Existing scoring stays. Add:
# Bonus: shared tool bridges untrusted input to external action → +10
if any(f.id == "STRATUM-CR01" for f in all_findings):
    score += 10

# Bonus: 4+ agent chain with no intermediate validation → +5
if any(f.id == "STRATUM-CR02" for f in all_findings):
    score += 5

# Bonus: cross-boundary delegation to destructive agent → +10
if any(f.id == "STRATUM-CR03" for f in all_findings):
    score += 10

score = min(score, 100)
```

### JSON Output Update

When `--json` is used, the full output now includes:

```json
{
  "graph": {
    "nodes": [...],
    "edges": [...],        // ← THIS WAS MISSING
    "risk_surface": {...},
    "uncontrolled_paths": [...]
  },
  "incident_matches": [
    {
      "incident_id": "...",
      "match_reason": "...",      // ← THIS WAS MISSING
      "matching_capabilities": [],  // ← THIS WAS MISSING
      "matching_files": [],        // ← THIS WAS MISSING
      ...
    }
  ],
  "crew_definitions": [...],       // ← NEW
  "agent_relationships": [...]     // ← NEW
}
```

---

## VALIDATION TARGETS

### Against `test_project/`

Everything that currently passes must still pass. Additionally:
- STRATUM-BR03 should fire (no audit trail — test_project has no observability)
- STRATUM-OP02 should fire (no cost controls)
- Graph must have edges (not just nodes)
- Risk surface must show control_coverage_pct < 100

### Against `crewAI-examples/` (the real test)

After applying this patch, `stratum scan crewAI-examples/` must produce:

1. **STRATUM-001** (CRITICAL) — data exfiltration paths (same as before)
2. **STRATUM-002** (HIGH) — FileManagementToolkit no HITL (same as before)
3. **STRATUM-BR01** (HIGH) — Gmail/Slack outbound with no review (NEW)
4. **STRATUM-BR03** (MEDIUM) — no audit trail (NEW)
5. **STRATUM-BR04** (MEDIUM) — decision agents without structured output (NEW, at least 1 from email_filter or scorer agents)
6. **STRATUM-CR01** (HIGH) — shared GmailToolkit bridges email_filter → email_responder (NEW — the thesis finding)
7. **STRATUM-CR02** (MEDIUM) — sequential crews with no intermediate validation (NEW)
8. **STRATUM-OP01** (MEDIUM) — single provider dependency (NEW, if only OpenAI keys detected)
9. **STRATUM-OP02** (MEDIUM) — no cost controls (NEW)
10. Graph with **edges** serialized in JSON
11. Incident matches with **match_reason** populated
12. Risk score **70-85** (up from 65 due to compounding bonuses)
13. At least one finding in EACH category: security, business, operational, compounding

**The CR01 finding on crewAI-examples is the demo moment.** It should read something like:

> **Shared tool 'GmailToolkit' bridges untrusted input to external action**
> untrusted input → Email Filter Agent → [GmailToolkit] → Email Response Writer → external action
>
> Agent 'Email Filter Agent' processes external/untrusted input and shares 'GmailToolkit'
> with agent 'Email Response Writer', which performs external actions. A prompt injection
> in the input can propagate through the shared tool context to trigger unauthorized actions.
>
> *This is the architectural pattern behind real-world AI exfiltration incidents.
> No individual agent is misconfigured — the risk emerges from the interaction.*

---

## FILE STRUCTURE (after patch)

```
stratum/
├── __init__.py
├── cli.py                          # (existing, minor update for new flags)
├── scanner.py                      # (UPDATED: wire in new pipeline steps)
├── models.py                       # (UPDATED: new dataclasses)
├── parsers/
│   ├── __init__.py
│   ├── capabilities.py             # (UPDATED: guardrail coverage resolution)
│   ├── mcp.py                      # (existing)
│   ├── env.py                      # (existing)
│   └── agents.py                   # (NEW: crew/flow/relationship extraction)
├── knowledge/
│   ├── __init__.py
│   ├── db.py                       # (existing)
│   ├── incidents.py                # (UPDATED: match_reason generation)
│   └── remediation.py              # (NEW: framework-specific fix snippets)
├── rules/
│   ├── __init__.py
│   ├── engine.py                   # (UPDATED: wire new rule modules)
│   ├── paths.py                    # (existing security rules)
│   ├── business_risk.py            # (NEW)
│   ├── operational_risk.py         # (NEW)
│   └── compounding_risk.py         # (NEW)
├── graph/
│   ├── __init__.py                 # (NEW)
│   ├── builder.py                  # (NEW: directed graph construction)
│   └── pathfinder.py               # (NEW: uncontrolled path discovery)
├── output/
│   ├── __init__.py
│   └── terminal.py                 # (UPDATED: topology + incident sections)
└── telemetry/
    ├── __init__.py
    ├── profile.py                  # (UPDATED: enriched fields)
    └── history.py                  # (existing)
```

New files: 7 (agents.py, remediation.py, business_risk.py, operational_risk.py, compounding_risk.py, graph/builder.py, graph/pathfinder.py)
Updated files: 6 (models.py, capabilities.py, incidents.py, engine.py, scanner.py, terminal.py, profile.py)

---

## WHAT SUCCESS LOOKS LIKE

When a developer runs `stratum scan .` on a real multi-agent project:

1. **The graph is real.** JSON output has nodes AND edges. Topology section shows data flow paths with trust boundary crossings.
2. **Every risk category is represented.** Security findings from data flow analysis. Business findings from autonomous external comms. Operational findings from missing error handling. **Compounding findings from agent interactions that no single-agent analysis would catch.**
3. **The "oh shit" moment is doubled.** STRATUM-001 (data exfiltration) is the security punch. STRATUM-CR01 (shared tool bridges) is the thesis punch. Together they say: "your agents are individually fine, but together they've created the exact architecture that caused the Microsoft Copilot EchoLeak."
4. **Incident matches explain why.** Not just "similarity: 75%" but "Your code reads Gmail and sends via Slack — the same pattern that enabled EchoLeak."
5. **Remediation matches the framework.** CrewAI projects see `human_input=True`. LangGraph projects see `interrupt_before`. No more wrong-framework suggestions.
6. **Telemetry is rich enough for the risk map.** Agent counts, chain lengths, shared tool pairs, trust boundary crossings, control coverage — the data that, at 10,000 scans, reveals patterns nobody else has.

Generate ALL files. Complete. Functional. No placeholders. No stubs. Every rule fully implemented. Every graph edge computed. Every incident reason generated. Run `stratum scan test_project/` until it passes, then test against a real codebase.
