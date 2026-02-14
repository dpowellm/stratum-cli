# STRATUM CLI — Evaluation & Comprehensive Patch

## PART 1: DEEP EVALUATION

### A. Virality Potential

The question: Does the current scan output make someone screenshot it, share it, and tell their team to run it?

**What works:**

STRATUM-001 is a genuinely alarming finding. "Someone sends your agent a crafted email → agent forwards sensitive content to an attacker-controlled address" with an EchoLeak citation is the kind of sentence that makes an engineering lead stop scrolling. The Gmail inbox → 6 unguarded outbound paths visual is concrete. If someone posted this in a Slack channel with "just ran this on our agent code," people would click.

**What kills virality right now:**

1. **No visual topology.** The terminal output is text findings in a list. There's no flow diagram, no ASCII graph, no visual representation of "here's how data moves through your system." The graph has 89 nodes and 83 edges but the user never sees them. The "network topology for agents" thesis is invisible in the output. A wall of findings doesn't get screenshotted. A flow diagram showing `Gmail inbox ──▶ GmailGetThread ──▶ [6 outbound services] ⚠ NO FILTER` does.

2. **No blast radius quantification.** The stock_analysis crew has ScrapeWebsiteTool shared across 4 agents (financial_agent, research_analyst_agent, financial_analyst_agent, investment_advisor_agent). If that scraper returns poisoned data, 4 agents are compromised simultaneously. This is the most compelling possible finding for the Stratum thesis — "1+1=3" emergent risk — and it doesn't fire. Nobody is going to screenshot a finding they have to imagine.

3. **No "compared to the ecosystem" context.** The scan says control_coverage_pct: 0.0. But is that bad? The developer doesn't know. If the output said "Your project has 0% control coverage. The median across 2,847 scanned projects is 34%." — that's a different emotional response. That requires the aggregate telemetry dataset, which doesn't exist yet because the telemetry is too thin.

4. **No badge/shield for README.** `![Stratum Risk Score](https://stratum.dev/badge/65)` in a GitHub README is passive virality. Every visitor to the repo sees the score. Every fork carries it. This is a zero-effort feature that creates permanent surface area.

5. **No GitHub Actions / CI output.** The scanner runs locally. Most developers discover tools through CI. A GitHub Action that comments on PRs with "Stratum found 3 new risk paths introduced in this PR" is the adoption flywheel. It's also the forcing function for teams to install it project-wide, not individually.

6. **No shareable report URL.** `stratum scan . --share` → generates a public link to a rendered version of the scan result. The link is the share unit. Without it, sharing means screenshotting terminal output or copy-pasting JSON.

**Virality priority stack (effort vs. impact):**

| Feature | Effort | Virality Impact | Why |
|---|---|---|---|
| Flow map in terminal | Medium | **Very High** | The screenshot moment. ASCII diagram of data paths with ⚠ markers |
| Blast radius finding (CR01) | Medium | **Very High** | The finding that proves the thesis. Only exists via graph traversal |
| GitHub badge | Low | **High** | Passive viral surface on every repo |
| GitHub Action | Medium | **High** | Adoption flywheel, team-wide install forcing function |
| `--share` report URL | High | **Medium** | Requires hosted backend, but is the share unit |
| Ecosystem comparison | High | **Medium** | Requires N≥1000 scans in telemetry, long-term play |

**The minimum viable viral loop is: flow map + blast radius finding + badge.** That's what turns a scan into something that gets posted on Twitter/HN/Slack.

---

### B. Telemetry Evaluation: The 20/10 Dataset

The goal: collect enough anonymized signal from free-tier scans to identify ~20 distinct risk patterns across ~10 architectural archetypes, creating the dataset that makes the enterprise product ("how does my agent architecture compare to similar deployments?") possible.

**What the current telemetry captures (5 fields):**

```json
{
  "topology_signature": "f9e0f129986fd183",
  "archetype": "multi_agent_orchestrator",
  "archetype_confidence": 0.9,
  "framework_fingerprint": ["CrewAI", "LangChain"],
  "capability_fingerprint": {"outbound": 18, "data_access": 11, "code_exec": 0, "destructive": 1}
}
```

**What this lets you say at N=10,000:** "67% of CrewAI projects have more than 10 outbound capabilities." That's it. You can't say anything about risk patterns, control effectiveness, architectural anti-patterns, or how similar projects compare.

**What you need to capture to build the 20/10 dataset:**

The minimum viable telemetry profile must answer these questions at scale:

1. **What does this project look like?** (Architecture signal)
   - Agent count, crew/flow count, task count
   - Framework combination (CrewAI only, LangChain only, hybrid)
   - Graph topology metrics: edge density, max fan-out from any node, max chain depth, clustering coefficient
   - Tool diversity: unique tool count, outbound/data_access ratio

2. **How risky is it?** (Risk signal)
   - Risk score
   - Finding count by category (security, business, operational, compounding)
   - Finding count by severity (CRITICAL, HIGH, MEDIUM, LOW)
   - Anonymized finding IDs that fired (STRATUM-001, STRATUM-CR01, etc. — which patterns appeared)
   - Incident match count and which incidents matched

3. **How controlled is it?** (Maturity signal)
   - Guardrail count by kind (validation, output_filter, hitl, rate_limit)
   - Control coverage percentage
   - Has checkpointing (boolean + type)
   - Has observability/tracing (boolean)
   - Has error handling ratio (handled_calls / total_calls)
   - Has human-in-the-loop on any path (boolean)

4. **What's the blast radius?** (Topology signal)
   - Max shared-tool fan-out (how many agents share one tool)
   - Uncontrolled path count
   - Trust boundary crossings (downward)
   - External sink count
   - Sensitive data types in flow (anonymized: "has_pii", "has_financial", not the data itself)

**Here's what the enriched telemetry profile should look like:**

```json
{
  "topology_signature": "f9e0f129986fd183",
  "schema_version": "0.2",
  "archetype": "multi_agent_orchestrator",
  "archetype_confidence": 0.9,
  
  "architecture": {
    "framework_fingerprint": ["CrewAI", "LangChain"],
    "agent_count": 53,
    "crew_count": 12,
    "task_count": 0,
    "unique_tool_count": 16,
    "capability_fingerprint": {"outbound": 18, "data_access": 11, "code_exec": 0, "destructive": 1, "financial": 0},
    "files_scanned": 116
  },
  
  "graph_topology": {
    "node_count": 89,
    "edge_count": 83,
    "edge_density": 0.021,
    "max_fan_out": 4,
    "max_chain_depth": 3,
    "agent_to_agent_edges": 0,
    "shared_tool_max_agents": 4,
    "external_sink_count": 6
  },
  
  "risk_profile": {
    "risk_score": 65,
    "findings_by_severity": {"critical": 1, "high": 1, "medium": 3, "low": 0},
    "findings_by_category": {"security": 1, "operational": 3, "business": 0, "compounding": 0},
    "finding_ids": ["STRATUM-001", "STRATUM-002", "STRATUM-008", "STRATUM-009", "STRATUM-010"],
    "incident_match_count": 4,
    "incident_ids": ["ECHOLEAK-2025", "SLACK-AI-EXFIL-2024", "SERVICENOW-NOWASSIST-2025", "DOCKER-GORDON-2025"]
  },
  
  "control_maturity": {
    "guardrail_count": 13,
    "guardrail_kinds": {"validation": 13, "output_filter": 0, "hitl": 0, "rate_limit": 0},
    "control_coverage_pct": 0.0,
    "has_checkpointing": false,
    "checkpoint_type": "none",
    "has_observability": false,
    "has_hitl_anywhere": false,
    "error_handling_ratio": 0.07
  },
  
  "data_sensitivity": {
    "has_pii": true,
    "has_financial": false,
    "has_credentials": false,
    "sensitive_data_types": ["personal"],
    "trust_boundary_crossings": 67,
    "downward_crossings": 44,
    "regulatory_surface": ["GDPR", "EU_AI_ACT", "NIST_AI_RMF"]
  }
}
```

**What this lets you say at N=1,000:**

- "Among multi_agent_orchestrator projects using CrewAI, the median risk score is 52. Your project scores 65 — higher than 78% of similar deployments."
- "Projects with 0% control coverage and >5 outbound capabilities have a 94% chance of having at least one CRITICAL finding."
- "The most common architectural anti-pattern is shared_tool_fan_out (43% of projects), where a single data source tool feeds 3+ agents."
- "Projects that add at least one HITL gate reduce their risk score by an average of 31 points."

**What this lets you say at N=10,000:**

- Benchmark reports by industry vertical (once you have org metadata from enterprise accounts)
- "Projects using this exact framework+tool combination tend to have these specific risks"
- Trend analysis: "Guardrail adoption increased 12% MoM across the ecosystem"
- The risk map: "Here's what the global attack surface of AI agent deployments looks like"

**That's the enterprise product.** The free CLI is the data collection mechanism. The telemetry is the moat.

**Critical telemetry constraints:**
- Everything must be anonymized. No file paths, no function names, no code content, no agent names.
- Counts, ratios, booleans, and anonymized IDs only.
- The topology_signature is a hash of the graph structure, not the graph itself.
- Opt-out via `--no-telemetry` must be respected.
- Schema versioning from day one. You will change this format.

---

## PART 2: COMPREHENSIVE PATCH

### Design Principles

1. **The graph is the only finding engine.** Every finding — security, business, operational, compounding — is a structural pattern discovered by traversing the directed graph. No parallel keyword-matching systems.

2. **A finding is non-generic when it can only be stated by having traced a specific path through a specific codebase.** "Your agent sends email without review" is generic. "email_response_writer bypasses email_filter_agent because it reads Gmail inbox directly via GmailGetThread — the filter doesn't sit on the data path" is non-generic.

3. **The flow map is the viral artifact.** Every scan outputs a visual topology that shows how data moves and where the gaps are.

4. **Telemetry captures architecture, not content.** Enough to build the risk map; nothing that identifies the user.

---

### What's Wrong with the Current Graph (Precise Numbers)

From analyzing the scan result:

- **83 edges total.** Of these:
  - 42 are `shares_with` — an exact Cartesian product of 7 data_access capabilities × 6 outbound capabilities. This is not topology. Every data_access cap has shares_with edges to every outbound cap regardless of whether they coexist in the same file, agent, or crew. **These 42 edges are noise.**
  - 27 are `tool_of` — capability→agent assignment. Real data, but only one direction.
  - 7 are `reads_from` — data store→capability. Real data.
  - 6 are `sends_to` — capability→external service. Real data.
  - 1 is `writes_to` — capability→data store. Real data.
- **0 controlled edges** (has_control: false on all 83).
- **0 agent-to-agent edges** (no delegates_to, feeds_into, or chain relationships).
- **0 guardrail-to-capability edges** (12 guardrail nodes, all disconnected).
- **53 agent nodes**, but 30 have no tool_of edges connecting them to anything.

**Effective topology after removing noise:** 41 real edges (reads_from + sends_to + writes_to + tool_of). That's a sparse graph with no chains, no control paths, and no compounding structure.

---

### File Structure After Patch

```
stratum/
├── __init__.py
├── cli.py                              # UPDATED: --share, --badge flags
├── scanner.py                          # UPDATED: full pipeline wiring
├── models.py                           # UPDATED: new dataclasses
├── parsers/
│   ├── __init__.py
│   ├── capabilities.py                 # UPDATED: guardrail coverage linking
│   ├── mcp.py                          # existing
│   ├── env.py                          # existing
│   └── agents.py                       # NEW: crew/flow extraction, agent ordering
├── knowledge/
│   ├── __init__.py
│   ├── db.py                           # existing
│   ├── incidents.py                    # UPDATED: match_reason from graph paths
│   └── remediation.py                  # NEW: framework-detected fix snippets
├── graph/
│   ├── __init__.py                     # NEW
│   ├── builder.py                      # NEW: directed graph construction
│   ├── pathfinder.py                   # NEW: uncontrolled path discovery, BFS
│   └── findings.py                     # NEW: graph-traversal finding generator
├── rules/
│   ├── __init__.py
│   ├── engine.py                       # UPDATED: integrate graph findings
│   ├── paths.py                        # UPDATED: delegate to graph for STRATUM-001/002
│   └── (other existing rule files)     # keep non-path rules unchanged
├── output/
│   ├── __init__.py
│   ├── terminal.py                     # UPDATED: flow map, blast radius, match_reason
│   └── flow_map.py                     # NEW: ASCII flow diagram renderer
├── telemetry/
│   ├── __init__.py
│   ├── profile.py                      # UPDATED: enriched 20/10 schema
│   ├── history.py                      # existing
│   └── share.py                        # UPDATED: badge endpoint support
└── badge/
    └── generator.py                    # NEW: SVG badge generation
```

New files: 7 (agents.py, remediation.py, graph/builder.py, graph/pathfinder.py, graph/findings.py, output/flow_map.py, badge/generator.py)
Updated files: 8 (models.py, capabilities.py, incidents.py, engine.py, scanner.py, terminal.py, profile.py, share.py, cli.py)

---

### HOW TO USE THIS PATCH

Add as `CLAUDE.md` alongside the existing codebase. Where this conflicts with existing code, this patch wins.

```
Message 1: "Patch Phase 1: Models + Agent Parser.
            Update stratum/models.py with new graph dataclasses and enriched telemetry model.
            Create stratum/parsers/agents.py — crew extraction, agent ordering, shared tool detection.
            Follow the spec exactly."

Message 2: "Patch Phase 2: Graph construction + pathfinding.
            Create stratum/graph/__init__.py, stratum/graph/builder.py, stratum/graph/pathfinder.py.
            The graph builder MUST produce agent-to-agent edges, guardrail-to-capability edges,
            and scoped shares_with edges. Remove the Cartesian product.
            Follow the spec exactly."

Message 3: "Patch Phase 3: Graph-driven findings.
            Create stratum/graph/findings.py — the module that traverses the graph and emits
            findings across all categories (security, business, operational, compounding).
            Update stratum/rules/engine.py to wire graph findings into the existing pipeline.
            Follow the spec exactly."

Message 4: "Patch Phase 4: Flow map + terminal output.
            Create stratum/output/flow_map.py — ASCII flow diagram renderer.
            Update stratum/output/terminal.py to render the flow map, blast radius,
            incident match_reason, and compounding findings.
            Follow the spec exactly."

Message 5: "Patch Phase 5: Telemetry enrichment + incident matching + remediation.
            Update stratum/telemetry/profile.py with the enriched 20/10 schema.
            Update stratum/knowledge/incidents.py with graph-path-derived match_reason.
            Create stratum/knowledge/remediation.py for framework-specific fixes.
            Follow the spec exactly."

Message 6: "Patch Phase 6: Badge + integration + validation.
            Create stratum/badge/generator.py for SVG badge output.
            Update stratum/cli.py with --badge flag.
            Update stratum/scanner.py to wire the full pipeline.
            Run stratum scan test_project/ and verify. Then test against crewAI-examples.
            Follow the spec exactly."
```

---

## PHASE 1: MODELS + AGENT PARSER

### New/Updated Dataclasses in `models.py`

Add these to the existing models file. Do not remove existing dataclasses.

```python
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# === GRAPH MODELS ===

class NodeType(str, Enum):
    CAPABILITY = "capability"
    DATA_STORE = "data_store"
    MCP_SERVER = "mcp_server"
    EXTERNAL_SERVICE = "external"
    GUARDRAIL = "guardrail"
    AGENT = "agent"

class EdgeType(str, Enum):
    READS_FROM = "reads_from"
    WRITES_TO = "writes_to"
    SENDS_TO = "sends_to"
    CALLS = "calls"
    TOOL_OF = "tool_of"
    DELEGATES_TO = "delegates_to"        # agent → agent (crew task ordering)
    FEEDS_INTO = "feeds_into"            # agent output → next agent input
    GATED_BY = "gated_by"               # capability/edge is controlled by guardrail
    FILTERED_BY = "filtered_by"          # data flow passes through guardrail
    SHARES_WITH = "shares_with"          # SCOPED: same-agent data_access → outbound only

class TrustLevel(str, Enum):
    PRIVILEGED = "privileged"
    RESTRICTED = "restricted"
    INTERNAL = "internal"
    EXTERNAL = "external"
    PUBLIC = "public"

@dataclass
class GraphNode:
    id: str
    node_type: NodeType
    label: str                              # Human-readable: "Gmail inbox", "Financial Agent"
    trust_level: TrustLevel
    data_sensitivity: str = "unknown"       # "pii", "financial", "credentials", "internal", "public", "unknown"
    source_file: str = ""                   # For provenance, not included in telemetry
    framework: str = ""                     # "CrewAI", "LangChain", etc.
    crew_id: str = ""                       # Which crew this agent belongs to
    metadata: dict = field(default_factory=dict)  # Flexible extra data

@dataclass
class GraphEdge:
    source: str                             # Node ID
    target: str                             # Node ID
    edge_type: EdgeType
    has_control: bool = False               # Is there a guardrail on this edge?
    control_id: str = ""                    # Which guardrail, if any
    data_sensitivity: str = "unknown"       # What kind of data flows here
    trust_boundary_crossed: bool = False    # Does this edge cross a trust boundary?
    crossing_direction: str = ""            # "upward" (safer) or "downward" (riskier)

@dataclass
class TracedPath:
    """A concrete path through the graph that represents a risk."""
    node_ids: list                          # Ordered list of node IDs in the path
    node_labels: list                       # Human-readable labels for display
    edge_types: list                        # Edge types along the path
    data_sensitivity: str = "unknown"       # Highest sensitivity along the path
    has_any_control: bool = False           # Is any edge in this path controlled?
    trust_crossings: int = 0               # Number of trust boundary crossings
    
    def to_display_string(self) -> str:
        """Render as: Gmail inbox ──▶ GmailGetThread ──▶ Serper API ⚠ no filter"""
        parts = []
        for i, label in enumerate(self.node_labels):
            parts.append(label)
            if i < len(self.node_labels) - 1:
                parts.append("──▶")
        suffix = " ⚠ no filter" if not self.has_any_control else ""
        return " ".join(parts) + suffix

@dataclass
class RiskGraph:
    nodes: list                             # list[GraphNode]
    edges: list                             # list[GraphEdge]
    traced_paths: list = field(default_factory=list)  # list[TracedPath] — discovered risk paths

@dataclass
class BlastRadius:
    """Quantifies the impact of a single node being compromised."""
    source_node_id: str
    source_label: str
    affected_agent_ids: list                # Agents that use this node
    affected_agent_labels: list
    downstream_external_ids: list           # External services reachable from those agents
    downstream_external_labels: list
    agent_count: int = 0
    external_count: int = 0
    
    def to_display_string(self) -> str:
        agents = ", ".join(self.affected_agent_labels)
        externals = ", ".join(self.downstream_external_labels)
        return f"{self.source_label} feeds {self.agent_count} agents — blast radius: {self.external_count} external services"


# === AGENT RELATIONSHIP MODELS ===

@dataclass
class CrewDefinition:
    """A group of agents working together with task ordering."""
    crew_id: str                            # Unique crew identifier
    name: str                               # Human-readable name
    framework: str                          # "CrewAI", "LangGraph", etc.
    source_file: str
    agent_names: list                       # Ordered list of agent names in the crew
    process_type: str = "sequential"        # "sequential", "hierarchical", "parallel"
    has_manager: bool = False
    manager_agent: str = ""

@dataclass
class AgentRelationship:
    """A relationship between two agents in a crew."""
    source_agent: str                       # Agent name
    target_agent: str                       # Agent name
    relationship_type: str                  # "delegates_to", "feeds_into", "managed_by"
    crew_id: str                            # Which crew this relationship exists in
    confidence: str = "confirmed"           # confidence level
    evidence: str = ""                      # What we saw in the code


# === ENRICHED TELEMETRY MODEL ===

@dataclass
class EnrichedTelemetryProfile:
    """The 20/10 telemetry schema. All fields anonymized — no file paths, no names, no code."""
    
    # Identity
    topology_signature: str = ""            # Hash of graph structure
    schema_version: str = "0.2"
    
    # Architecture
    archetype: str = ""                     # "single_agent", "multi_agent_orchestrator", etc.
    archetype_confidence: float = 0.0
    framework_fingerprint: list = field(default_factory=list)
    agent_count: int = 0
    crew_count: int = 0
    unique_tool_count: int = 0
    capability_fingerprint: dict = field(default_factory=dict)
    files_scanned: int = 0
    
    # Graph topology (anonymized structural metrics)
    node_count: int = 0
    edge_count: int = 0
    edge_density: float = 0.0
    max_fan_out: int = 0                    # Most agents sharing one tool
    max_chain_depth: int = 0                # Longest agent→agent chain
    agent_to_agent_edges: int = 0
    shared_tool_max_agents: int = 0
    external_sink_count: int = 0
    
    # Risk profile (anonymized)
    risk_score: int = 0
    findings_by_severity: dict = field(default_factory=dict)
    findings_by_category: dict = field(default_factory=dict)
    finding_ids: list = field(default_factory=list)     # Which STRATUM rules fired
    incident_match_count: int = 0
    incident_ids: list = field(default_factory=list)
    
    # Control maturity
    guardrail_count: int = 0
    guardrail_kinds: dict = field(default_factory=dict)
    control_coverage_pct: float = 0.0
    has_checkpointing: bool = False
    checkpoint_type: str = "none"
    has_observability: bool = False
    has_hitl_anywhere: bool = False
    error_handling_ratio: float = 0.0
    
    # Data sensitivity (anonymized)
    has_pii: bool = False
    has_financial: bool = False
    has_credentials: bool = False
    sensitive_data_types: list = field(default_factory=list)
    trust_boundary_crossings: int = 0
    downward_crossings: int = 0
    regulatory_surface: list = field(default_factory=list)


# === INCIDENT MATCH WITH REASON ===

@dataclass
class EnrichedIncidentMatch:
    """Incident match with graph-derived explanation."""
    incident_id: str
    name: str
    date: str
    impact: str
    confidence: float
    attack_summary: str
    source_url: str
    match_reason: str = ""                  # NEW: "Your email_auto_responder_flow reads untrusted email
                                            # content via GmailGetThread and routes it through 6 outbound
                                            # services with no filter — the same data→external pattern
                                            # that enabled EchoLeak."
    matched_paths: list = field(default_factory=list)  # TracedPath objects that triggered this match
```

### `parsers/agents.py` — NEW: Crew and Relationship Extraction

This parser discovers how agents are organized into crews and what order they execute in.

```python
"""
Agent relationship parser.

Discovers:
1. CrewAI Crew definitions — which agents are in each crew and in what order
2. Task ordering — which agent's output feeds into which agent's input
3. Shared tool detection — which agents share the same tool (scoped, not global)
4. Process type — sequential, hierarchical, parallel

Data sources:
- Python files containing Crew() instantiation
- YAML task config files (tasks.yaml)
- Python files with @task decorators

Does NOT:
- Parse agent role descriptions for keywords
- Infer relationships from agent names
- Guess at intent from docstrings
"""
```

**Core function:**

```python
def extract_crews(python_files: dict[str, str], yaml_files: dict[str, str]) -> tuple[list[CrewDefinition], list[AgentRelationship]]:
    """
    Args:
        python_files: {file_path: file_content} for all .py files
        yaml_files: {file_path: file_content} for all .yaml files
    Returns:
        (crews, relationships)
    """
```

**Detection strategy for CrewAI crews:**

1. **Find Crew() instantiation in Python AST.** Look for `Crew(agents=[...], tasks=[...])` calls. Extract the agent list and task list from the keyword arguments. The order of `tasks` determines execution order in sequential crews.

2. **Find `process=Process.sequential` or `process=Process.hierarchical`.** Default is sequential. If hierarchical, look for `manager_agent=` or `manager_llm=`.

3. **Match tasks to agents.** In CrewAI, each Task has an `agent=` parameter. Walk the `tasks` list to determine: task_1.agent → task_2.agent → task_3.agent. This gives you the `delegates_to` / `feeds_into` chain.

4. **YAML task configs.** In `config/tasks.yaml`, tasks are listed in order. Each task has an `agent:` field. The order in the YAML file is the execution order.

5. **@task decorator ordering.** In crew classes using `@task` decorators, the method order in the class determines task order (CrewAI convention). Each `@task` method typically assigns `self.agent_name()` as the agent.

**Detection strategy for shared tools within a crew:**

For each crew, collect the tools assigned to each agent. If two agents in the same crew share a tool, emit a `shares_with` relationship scoped to that crew. This is NOT a global cross-product — it means "agent A and agent B in crew X both have access to tool Y, so tool Y's input context is available to both."

**Output for crewAI-examples email_auto_responder_flow:**

```python
CrewDefinition(
    crew_id="email_filter_crew",
    name="Email Filter Crew",
    framework="CrewAI",
    source_file="flows/email_auto_responder_flow/.../email_filter_crew.py",
    agent_names=["email_filter_agent", "email_action_agent", "email_response_writer"],
    process_type="sequential"
)

# Relationships derived from task ordering:
AgentRelationship("email_filter_agent", "email_action_agent", "feeds_into", "email_filter_crew")
AgentRelationship("email_action_agent", "email_response_writer", "feeds_into", "email_filter_crew")
```

**Output for crewAI-examples stock_analysis:**

```python
CrewDefinition(
    crew_id="stock_analysis_crew",
    name="Stock Analysis Crew",
    framework="CrewAI",
    source_file="crews/stock_analysis/.../crew.py",
    agent_names=["financial_agent", "research_analyst_agent", "financial_analyst_agent", "investment_advisor_agent"],
    process_type="sequential"
)

# Shared tool relationships (scoped to this crew):
# financial_agent, research_analyst_agent, financial_analyst_agent all have ScrapeWebsiteTool
# → ScrapeWebsiteTool fan-out = 3 agents within this crew
```

---

## PHASE 2: GRAPH CONSTRUCTION + PATHFINDING

### `graph/builder.py` — Directed Graph Construction

The builder takes the existing ScanResult data (capabilities, agents, guardrails, MCP servers) plus the new crew/relationship data and constructs a proper directed graph.

```python
def build_graph(
    capabilities: list,          # Capability objects
    agents: list,                # AgentDefinition objects  
    guardrails: list,            # GuardrailSignal objects
    mcp_servers: list,           # MCPServer objects
    crews: list,                 # CrewDefinition objects (NEW)
    relationships: list,         # AgentRelationship objects (NEW)
    env_vars: list
) -> RiskGraph:
```

**Edge construction rules (in order):**

**Rule 1: Data store → Capability (reads_from)**
Same as current. For each data_access capability, create an edge from its inferred data store to the capability node.

Data store inference:
- GmailGetThread, GmailToolkit → `ds_gmail_inbox` (sensitivity: "personal")
- FileReadTool, FileManagementToolkit → `ds_local_filesystem` (sensitivity: "unknown")
- CSVSearchTool → `ds_csv_files` (sensitivity: "unknown")
- RagTool → `ds_vector_store` (sensitivity depends on content, default "internal")
- Database operations → `ds_database` (sensitivity: "internal" or "personal" if connection string suggests PII)

**Rule 2: Capability → External service (sends_to)**
Same as current. For each outbound capability, create an edge to its external service node.

External service inference:
- SerperDevTool → `ext_serper_api`
- TavilySearchResults → `ext_tavily_api`
- GmailToolkit (outbound) → `ext_gmail_outbound`
- slack_sdk → `ext_slack`
- requests/httpx → `ext_http_endpoint`
- ScrapeWebsiteTool → `ext_web_scraper`

**Rule 3: Capability → Agent (tool_of)**
Same as current but now bidirectional in the model. For each agent with assigned tools, create `tool_of` edges from the capability node to the agent node.

**Rule 4: Agent → Agent (delegates_to / feeds_into) — NEW**
From AgentRelationship objects. For each relationship in a crew, create an edge:
- Sequential crew: agent_1 `feeds_into` agent_2 `feeds_into` agent_3
- Hierarchical crew: manager `delegates_to` each worker agent

**Trust boundary crossing on agent→agent edges:**
If agent_1 has tool with trust_level="external" and agent_2 has tool with trust_level="internal", the edge crosses a trust boundary (downward, because data from an external source flows into an internally-trusted context).

**Rule 5: Guardrail → Capability (gated_by / filtered_by) — NEW**
This requires the guardrail coverage linking done in `capabilities.py` update.

For each guardrail with a non-empty `covers_tools` list:
- If the guardrail is `kind="hitl"` → create `gated_by` edge from the capability to the guardrail
- If the guardrail is `kind="validation"` or `kind="output_filter"` → create `filtered_by` edge

For capability→external edges where a guardrail exists on that capability:
- Set `has_control: True` on the edge
- Set `control_id` to the guardrail node ID

**Rule 6: Scoped shares_with — NEW (replaces Cartesian product)**
Within each crew (not globally), find agents that share a tool:
- For each crew, collect all tools assigned to all agents in that crew
- If tool T is assigned to agents A1, A2, A3 → create `shares_with` edges: T → A1, T → A2, T → A3
- The `shares_with` edge now means "this tool's input/output context is available to multiple agents in the same execution context"

**CRITICAL: Do NOT create the global Cartesian product.** The current 42 shares_with edges (7 data_access × 6 outbound) must be replaced by scoped edges within crews only.

**Rule 7: Capability → Data store (writes_to)**
Same as current. For destructive capabilities, create edges to their target data stores.

**Node creation:**
- Deduplicate nodes by semantic identity, not just ID. If GmailToolkit appears in 3 files, it's one capability node with edges to 3 different agents, not 3 capability nodes.
- Agent nodes get `crew_id` populated from CrewDefinition.
- All edges get `trust_boundary_crossed` computed by comparing source and target trust levels.
- All edges get `data_sensitivity` propagated: the highest sensitivity of any data that flows through.

**Data sensitivity propagation:**
Walk the graph from data stores outward. The sensitivity of a data store propagates through all edges that read from it:
- `ds_gmail_inbox` (personal) → GmailGetThread (personal) → all outbound caps reachable from the same agent (personal)
- Sensitivity propagates through agent→agent (feeds_into) edges: if agent_1 reads PII and feeds into agent_2, agent_2's downstream paths carry PII sensitivity.

---

### `graph/pathfinder.py` — Uncontrolled Path Discovery

```python
def find_uncontrolled_paths(graph: RiskGraph) -> list[TracedPath]:
    """
    BFS from every data store / external source to every external sink.
    Return paths where has_control is False on every edge.
    """

def find_blast_radii(graph: RiskGraph, crews: list) -> list[BlastRadius]:
    """
    For each capability node that is tool_of 2+ agents in the same crew,
    compute the blast radius: how many agents are affected, and what
    external services are reachable from those agents.
    """

def find_control_bypasses(graph: RiskGraph, crews: list) -> list[TracedPath]:
    """
    Find cases where a control agent exists but data flows around it.
    
    Pattern: In crew [A, B, C] where A is supposed to filter input for B and C,
    but B or C reads from the same data source as A directly (not through A).
    The control (A) is architecturally irrelevant because the data path bypasses it.
    
    Detection:
    1. For each crew, identify agents that have both data_access and outbound tools
    2. Check if any downstream agent in the chain has direct access to the same data source
       as an upstream agent
    3. If yes, the upstream agent's "filtering" is bypassed — the downstream agent
       reads the unfiltered source directly
    """

def compute_risk_surface(graph: RiskGraph) -> dict:
    """
    Aggregate metrics for the risk_surface field in ScanResult.
    
    Returns:
        total_nodes, total_edges, uncontrolled_path_count, max_path_hops,
        sensitive_data_types, external_sink_count, control_coverage_pct,
        trust_boundary_crossings, downward_crossings,
        max_fan_out, max_chain_depth, edge_density
    """
```

**Control coverage calculation:**

```
control_coverage_pct = (edges where has_control=True) / (edges where data flows from internal/restricted to external)
```

Only count edges that represent data flowing toward external services. Internal-to-internal edges don't need controls for this metric.

---

## PHASE 3: GRAPH-DRIVEN FINDINGS

### `graph/findings.py` — The Core

This is the single module that traverses the graph and emits all findings. It replaces the need for separate business_risk.py, operational_risk.py, compounding_risk.py modules.

```python
def generate_graph_findings(
    graph: RiskGraph,
    crews: list[CrewDefinition],
    blast_radii: list[BlastRadius],
    control_bypasses: list[TracedPath],
    uncontrolled_paths: list[TracedPath],
    detected_frameworks: list[str]
) -> list[Finding]:
```

**Finding: STRATUM-001 (CRITICAL) — Unguarded data-to-external path**
*Replaces current implementation with graph-derived version.*

Trigger: `uncontrolled_paths` contains paths from a sensitive data store (PII, credentials, financial) to an external sink with zero controlled edges.

Enhancement over current:
- Evidence is ONLY files in the actual path, not files from unrelated subprojects
- Path display uses TracedPath.to_display_string()
- If multiple paths share a common prefix, group them:
  ```
  Gmail inbox ──▶ GmailGetThread ──▶ GmailToolkit ──▶ Gmail outbound ⚠ no filter
                                  ──▶ slack_sdk ──▶ Slack ⚠ no filter
                                  ──▶ TavilySearchResults ──▶ Tavily API ⚠ no filter
  ```

Framework-aware remediation: detect if the project is CrewAI or LangGraph and emit the correct syntax.

**Finding: STRATUM-CR01 (HIGH/CRITICAL) — Shared tool blast radius — NEW**

Trigger: `blast_radii` contains an entry where `agent_count >= 3` AND the shared tool has trust_level="external" (meaning it ingests external data).

```
STRATUM-CR01 | CRITICAL | Shared tool blast radius

ScrapeWebsiteTool feeds 4 agents — blast radius: 3 external services

Web scraper ──▶ ScrapeWebsiteTool ──▶ Financial Agent ──▶ [Web search, HTTP endpoint]
                                  ──▶ Research Analyst ──▶ [Web scraper, SEC filing API]
                                  ──▶ Financial Analyst ──▶ [Web search, HTTP endpoint]
                                  ──▶ Investment Advisor ──▶ [Web search]

If ScrapeWebsiteTool returns poisoned data (prompt injection in scraped content),
4 agents are compromised simultaneously. Each has independent downstream actions,
so a single point of compromise fans out to 3 external services.

A single poisoned webpage would compromise your entire analysis pipeline.

Category: compounding
OWASP: ASI01 — Agent Goal Hijacking
```

**Severity gating:** CRITICAL if fan-out ≥ 3 agents AND at least one downstream path reaches an outbound service with `data_sensitivity != "public"`. HIGH if fan-out ≥ 2 agents.

**This finding can only exist because the graph traced the fan-out.** No checklist produces it. This is the demo finding for the Stratum thesis.

**Finding: STRATUM-CR02 (HIGH) — Control bypass — NEW**

Trigger: `control_bypasses` is non-empty.

```
STRATUM-CR02 | HIGH | Architectural control bypass

email_response_writer bypasses email_filter_agent — reads inbox directly

email_filter_agent is supposed to filter email input, but email_response_writer
reads Gmail inbox directly via GmailGetThread. The filter agent doesn't sit on
the data path — it runs in parallel, not as a gate.

Data flow showing the bypass:
  Gmail inbox ──▶ email_filter_agent (intended filter)
  Gmail inbox ──▶ email_response_writer (direct access, bypassing filter)

The filter is architecturally irrelevant. Malicious email content reaches
email_response_writer unfiltered regardless of what email_filter_agent does.

Category: compounding
OWASP: ASI05 — Insufficient Sandboxing / Control
```

**Detection logic:**
1. In crew `email_filter_crew`, agents are ordered: [email_filter_agent, email_action_agent, email_response_writer]
2. email_filter_agent has SerperDevTool
3. email_action_agent has GmailGetThread + TavilySearchResults  
4. email_response_writer has GmailGetThread + TavilySearchResults
5. Both email_action_agent and email_response_writer read Gmail inbox directly via GmailGetThread
6. If email_filter_agent is supposed to filter incoming email, it can't — the downstream agents have direct inbox access

The bypass is detected by: "a downstream agent in the crew chain has `reads_from` access to the same data store as an upstream agent, without going through the upstream agent."

**Finding: STRATUM-BR01 (MEDIUM) — Uncontrolled agent chain — NEW**

Trigger: A crew has ≥3 agents in a sequential chain with zero guardrails on any edge.

```
STRATUM-BR01 | MEDIUM | Uncontrolled 3-agent chain

email_filter_agent → email_action_agent → email_response_writer
No controls on any handoff. An error or hallucination at step 1
propagates unchecked through 2 more agents before reaching output.

Category: operational
```

**Finding: STRATUM-BR02 (MEDIUM) — No observability on consequential paths — NEW**

Trigger: A traced path reaches an external service with sensitivity != "public", the project has no telemetry/tracing detected, AND the path has ≥2 hops.

```
STRATUM-BR02 | MEDIUM | No observability on sensitive data path

Gmail inbox ──▶ GmailGetThread ──▶ Gmail outbound has no tracing.
If this path sends the wrong data, you won't know until someone reports it.

Category: business
```

**Finding: STRATUM-002 — Updated with framework-aware remediation**

If detected framework is CrewAI → remediation uses `human_input=True`
If detected framework is LangGraph → remediation uses `graph.compile(interrupt_before=[...])`

---

## PHASE 4: FLOW MAP + TERMINAL OUTPUT

### `output/flow_map.py` — ASCII Flow Diagram

The flow map is the viral artifact. It renders the graph as an ASCII diagram that shows data flow paths with risk markers.

```python
def render_flow_map(
    traced_paths: list[TracedPath],
    blast_radii: list[BlastRadius],
    control_bypasses: list[TracedPath],
    max_width: int = 100
) -> str:
    """
    Render a compact ASCII flow diagram showing:
    1. Data sources on the left
    2. Capabilities/agents in the middle
    3. External sinks on the right
    4. ⚠ markers on uncontrolled paths
    5. 🔴 markers on blast radius nodes
    
    Returns a string ready for Rich console output.
    """
```

**Target output for email_auto_responder_flow:**

```
╭─────────────────────────── DATA FLOW MAP ────────────────────────────╮
│                                                                      │
│  Gmail inbox (personal)                                              │
│    ├──▶ GmailGetThread ──▶ email_filter_agent                        │
│    │                       └──▶ email_action_agent                   │
│    │                            └──▶ email_response_writer           │
│    │                                 ├──▶ Gmail outbound  ⚠ no gate  │
│    │                                 └──▶ Tavily API  ⚠ no gate     │
│    ├──▶ GmailToolkit ──────────────────▶ Gmail outbound  ⚠ no gate  │
│    └──▶ [BYPASS] email_response_writer reads inbox directly          │
│                                                                      │
│  ⚠ 6 uncontrolled paths · 0% control coverage · 3 agents in chain  │
╰──────────────────────────────────────────────────────────────────────╯
```

**Target output for stock_analysis:**

```
╭─────────────────────────── DATA FLOW MAP ────────────────────────────╮
│                                                                      │
│  ScrapeWebsiteTool (external input)                                  │
│    ├──▶ Financial Agent ──▶ [Web search, HTTP endpoint]              │
│    ├──▶ Research Analyst ──▶ [Web scraper, SEC API]                  │
│    ├──▶ Financial Analyst ──▶ [Web search, HTTP endpoint]            │
│    └──▶ Investment Advisor ──▶ [Web search]                          │
│    🔴 BLAST RADIUS: 1 tool → 4 agents → 3 external services         │
│                                                                      │
│  ⚠ 4 uncontrolled paths · 0% control coverage · 4-agent fan-out    │
╰──────────────────────────────────────────────────────────────────────╯
```

**Rendering rules:**
1. Paths are grouped by shared data source prefix
2. External sinks are right-aligned with ⚠ markers
3. Blast radius nodes get 🔴 markers
4. Control bypasses get [BYPASS] callout
5. Summary line at bottom: uncontrolled path count, control coverage %, max chain/fan-out
6. Use Rich box drawing characters for clean terminal rendering
7. Max width defaults to terminal width, falls back to 100

### Terminal output updates in `terminal.py`

**Section order in terminal output:**

1. **Header** (existing) — scan info, frameworks, counts
2. **Flow Map** (NEW) — the ASCII diagram from flow_map.py
3. **Findings** (existing but enhanced):
   - Compounding findings (STRATUM-CR01, CR02) get a new "COMPOUNDING" section header
   - Business findings get "BUSINESS RISK" section header
   - Each finding includes the TracedPath display string
   - Incident matches now include `match_reason` inline under the finding
4. **Blast Radius Summary** (NEW) — if any blast_radii detected:
   ```
   🔴 BLAST RADIUS: ScrapeWebsiteTool → 4 agents → 3 external services
   ```
5. **Signals** (existing) — CONTEXT-001, TELEMETRY-003, etc.
6. **Risk Score** (existing)
7. **Quick Fixes** (existing)

**Incident match display (enhanced):**

Under STRATUM-001, instead of just listing incident names:

```
  📎 Matches real-world incident: Microsoft Copilot EchoLeak (2025-Q1)
     Your email_auto_responder_flow reads untrusted email content via GmailGetThread
     and routes it through 6 outbound services with no filter — the same
     data→external pattern that enabled EchoLeak.
     Impact: $200M+ est. across 160+ reported incidents
     Source: https://embracethered.com/blog/posts/2024/m365-copilot-echo-leak/
```

The `match_reason` is generated in Phase 5 by comparing the incident's attack pattern against the traced paths.

---

## PHASE 5: TELEMETRY + INCIDENT MATCHING + REMEDIATION

### `telemetry/profile.py` — Enriched 20/10 Schema

Replace the current 5-field telemetry profile with `EnrichedTelemetryProfile`.

```python
def build_telemetry_profile(
    scan_result,                # The full ScanResult
    graph: RiskGraph,
    crews: list[CrewDefinition],
    blast_radii: list[BlastRadius]
) -> EnrichedTelemetryProfile:
```

**Population logic:**

```python
profile = EnrichedTelemetryProfile()

# Architecture
profile.agent_count = len(scan_result.agent_definitions)
profile.crew_count = len(crews)
profile.unique_tool_count = len(set(
    t for a in scan_result.agent_definitions for t in a.tool_names
))
profile.capability_fingerprint = {
    "outbound": scan_result.outbound_count,
    "data_access": scan_result.data_access_count,
    "code_exec": scan_result.code_exec_count,
    "destructive": scan_result.destructive_count,
    "financial": scan_result.financial_count
}
profile.files_scanned = scan_result.files_scanned

# Graph topology
profile.node_count = len(graph.nodes)
profile.edge_count = len(graph.edges)
n = profile.node_count
profile.edge_density = profile.edge_count / (n * (n - 1)) if n > 1 else 0
profile.max_fan_out = max(
    (sum(1 for e in graph.edges if e.source == node.id and e.edge_type == EdgeType.TOOL_OF)
     for node in graph.nodes if node.node_type == NodeType.CAPABILITY),
    default=0
)
profile.max_chain_depth = max(
    (len(p.node_ids) for p in graph.traced_paths),
    default=0
)
profile.agent_to_agent_edges = sum(
    1 for e in graph.edges if e.edge_type in (EdgeType.DELEGATES_TO, EdgeType.FEEDS_INTO)
)
profile.shared_tool_max_agents = max(
    (br.agent_count for br in blast_radii),
    default=0
)
profile.external_sink_count = sum(
    1 for n in graph.nodes if n.node_type == NodeType.EXTERNAL_SERVICE
)

# Risk profile
profile.risk_score = scan_result.risk_score
profile.findings_by_severity = {
    "critical": sum(1 for f in scan_result.top_paths if f.severity == "CRITICAL"),
    "high": sum(1 for f in scan_result.top_paths if f.severity == "HIGH"),
    "medium": sum(1 for f in scan_result.top_paths if f.severity == "MEDIUM"),
    "low": sum(1 for f in scan_result.top_paths if f.severity == "LOW")
}
profile.findings_by_category = {}  # count by category field
profile.finding_ids = [f.id for f in scan_result.top_paths]
profile.incident_match_count = len(scan_result.incident_matches)
profile.incident_ids = [m.incident_id for m in scan_result.incident_matches]

# Control maturity
profile.guardrail_count = scan_result.guardrail_count
profile.guardrail_kinds = {}  # count guardrails by kind
profile.control_coverage_pct = graph.risk_surface.get("control_coverage_pct", 0.0)
profile.has_checkpointing = scan_result.checkpoint_type != "none"
profile.checkpoint_type = scan_result.checkpoint_type
profile.has_observability = any(
    s.id == "TELEMETRY-003" for s in scan_result.signals
) is False  # True if TELEMETRY-003 did NOT fire
profile.has_hitl_anywhere = any(g.kind == "hitl" for g in scan_result.guardrails)
handled = sum(1 for c in scan_result.capabilities if c.has_error_handling)
total = len(scan_result.capabilities)
profile.error_handling_ratio = handled / total if total > 0 else 0

# Data sensitivity
surface = graph.risk_surface
profile.has_pii = "personal" in surface.get("sensitive_data_types", [])
profile.has_financial = "financial" in surface.get("sensitive_data_types", [])
profile.has_credentials = "credentials" in surface.get("sensitive_data_types", [])
profile.sensitive_data_types = surface.get("sensitive_data_types", [])
profile.trust_boundary_crossings = surface.get("trust_boundary_crossings", 0)
profile.downward_crossings = surface.get("downward_crossings", 0)
# Map regulatory frameworks to short keys for anonymity
reg_map = {"GDPR Art. 35": "GDPR", "EU AI Act Art. 14": "EU_AI_ACT", ...}
profile.regulatory_surface = [reg_map.get(r, r) for r in surface.get("regulatory_frameworks", [])]
```

### `knowledge/incidents.py` — Match Reason Generation

Update the incident matching to generate `match_reason` from traced paths.

```python
def generate_match_reason(
    incident: IncidentRecord,
    traced_paths: list[TracedPath],
    agents: list,
    crews: list[CrewDefinition]
) -> str:
    """
    Generate a specific, path-derived explanation of WHY this incident matched.
    
    NOT a template string. The reason must reference specific nodes from the traced paths.
    
    Example output:
    "Your email_auto_responder_flow reads untrusted email content via GmailGetThread
    and routes it through 6 outbound services (Gmail outbound, Slack, Serper API,
    HTTP endpoint, Tavily API, WebsiteSearchTool) with no filter — the same
    data→external pattern that enabled EchoLeak."
    """
```

**Match reason generation logic:**

For each incident, the matching function already computes a confidence score. The `match_reason` extends this by:

1. Finding the traced_path(s) that triggered the match
2. Extracting the specific node labels from those paths
3. Identifying which crew/flow the path belongs to (if any)
4. Composing a sentence that names: the source (e.g., "email content via GmailGetThread"), the sink count and names, the missing control, and the connection to the incident pattern

**Pattern matching for known incidents:**

```python
INCIDENT_PATTERNS = {
    "ECHOLEAK-2025": {
        "pattern": "reads_from_sensitive + sends_to_external + no_hitl",
        "key_data_types": ["personal", "internal"],
        "key_sink_types": ["email", "messaging"],
        "reason_template": "Your {crew_name} reads {source_description} and routes it "
                          "through {sink_count} outbound services ({sink_names}) with no "
                          "filter — the same data→external pattern that enabled EchoLeak."
    },
    "SLACK-AI-EXFIL-2024": {
        "pattern": "reads_from_internal + sends_to_messaging + no_output_filter",
        "key_sink_types": ["messaging", "url"],
        "reason_template": "Your agents process {source_description} and can send content "
                          "to {sink_names}. Hidden instructions in input data could cause "
                          "exfiltration via crafted links — the same pattern behind the "
                          "Slack AI data exfiltration."
    },
    # ... etc for each incident
}
```

**CRITICAL:** The reason_template is populated with SPECIFIC data from the traced paths — real node labels, real counts, real crew names. If the template can't be populated with specific data (because no matching paths exist), the match is downgraded, not faked.

### `knowledge/remediation.py` — Framework-Specific Fixes

```python
def get_remediation(
    finding_id: str,
    detected_frameworks: list[str],
    affected_agents: list[str] = None,
    affected_tools: list[str] = None
) -> str:
    """
    Return framework-appropriate remediation code snippet.
    
    If CrewAI detected:
        STRATUM-001 → human_input=True on Task
        STRATUM-002 → human_input=True on Task
        STRATUM-CR01 → input validation on shared tool, or separate tool instances per agent
    
    If LangGraph detected:
        STRATUM-001 → graph.compile(interrupt_before=[...])
        STRATUM-002 → graph.compile(interrupt_before=[...])
    
    If both detected (hybrid):
        Show both, labeled by framework
    """
```

**Remediation snippets:**

```python
REMEDIATIONS = {
    "STRATUM-001": {
        "CrewAI": """Fix (CrewAI):
  task = Task(
      description="...",
+     human_input=True   # review before external calls
  )""",
        "LangGraph": """Fix (LangGraph):
  graph = workflow.compile(
+     interrupt_before=["send_email", "post_to_slack"]
  )"""
    },
    "STRATUM-002": {
        "CrewAI": """Fix (CrewAI):
  task = Task(
      description="...",
+     human_input=True   # approve before destructive action
  )""",
        "LangGraph": """Fix (LangGraph):
  graph = workflow.compile(
+     interrupt_before=["file_management"]
  )"""
    },
    "STRATUM-CR01": {
        "CrewAI": """Fix (CrewAI):
  Option 1 — Add input validation on the shared tool:
  
  class ValidatedScraper(BaseTool):
      def _run(self, url: str) -> str:
          raw = ScrapeWebsiteTool()._run(url)
+         if contains_injection_patterns(raw):
+             raise ValueError("Suspicious content detected")
          return raw
  
  Option 2 — Give each agent its own tool instance:
  
  financial_agent = Agent(
-     tools=[shared_scraper],
+     tools=[ScrapeWebsiteTool()],  # independent instance
  )""",
        "LangGraph": """Fix (LangGraph):
  # Validate tool output before passing to next node:
  def scrape_with_validation(state):
      result = scrape_tool.invoke(state["query"])
+     if not validate_content(result):
+         return {"error": "Content validation failed"}
      return {"scraped_content": result}"""
    }
}
```

---

## PHASE 6: BADGE + CLI + WIRING

### `badge/generator.py` — SVG Badge

```python
def generate_badge_svg(risk_score: int, finding_count: int) -> str:
    """
    Generate an SVG badge for README embedding.
    
    Colors:
    - score 0-30: green (#4c1)
    - score 31-60: yellow (#dfb317)
    - score 61-80: orange (#fe7d37)
    - score 81-100: red (#e05d44)
    
    Format: "stratum | risk: 65 · 5 findings"
    
    Returns SVG string.
    """
```

Output: a shields.io-compatible SVG that can be embedded as:
```markdown
![Stratum Risk Score](./stratum-badge.svg)
```

### `cli.py` Updates

Add flags:
- `--badge` → generate `stratum-badge.svg` in the scanned directory
- `--json` → existing, now includes enriched telemetry and graph with traced paths

### `scanner.py` — Full Pipeline Wiring

The updated scan pipeline:

```python
def scan(directory: str, options: ScanOptions) -> ScanResult:
    # Phase 1: Existing detection (capabilities, guardrails, MCP, env)
    capabilities = scan_capabilities(directory)
    guardrails = scan_guardrails(directory)
    mcp_servers = scan_mcp(directory)
    env_findings = scan_env(directory)
    agents = scan_agents(directory)
    
    # Phase 2: NEW — Crew and relationship extraction
    crews, relationships = extract_crews(python_files, yaml_files)
    
    # Phase 3: NEW — Graph construction
    graph = build_graph(capabilities, agents, guardrails, mcp_servers, crews, relationships, env_findings)
    
    # Phase 4: NEW — Path discovery
    uncontrolled_paths = find_uncontrolled_paths(graph)
    blast_radii = find_blast_radii(graph, crews)
    control_bypasses = find_control_bypasses(graph, crews)
    risk_surface = compute_risk_surface(graph)
    
    graph.traced_paths = uncontrolled_paths
    
    # Phase 5: NEW — Graph-driven findings
    graph_findings = generate_graph_findings(
        graph, crews, blast_radii, control_bypasses, uncontrolled_paths, detected_frameworks
    )
    
    # Phase 6: Existing rules (non-path rules unchanged)
    rule_findings = evaluate_rules(capabilities, guardrails, mcp_servers, env_findings)
    
    # Phase 7: Merge findings, deduplicate
    all_findings = merge_and_dedup(graph_findings, rule_findings)
    
    # Phase 8: NEW — Enriched incident matching
    incident_matches = match_incidents(capabilities, graph)
    for match in incident_matches:
        match.match_reason = generate_match_reason(match, uncontrolled_paths, agents, crews)
    
    # Phase 9: Score
    risk_score = calculate_risk_score(all_findings, capabilities, guardrails, mcp_servers)
    
    # Phase 10: NEW — Enriched telemetry
    telemetry = build_telemetry_profile(scan_result, graph, crews, blast_radii)
    
    # Phase 11: Build result
    return ScanResult(
        # ... existing fields ...
        graph=graph,
        crews=crews,
        blast_radii=blast_radii,
        telemetry_profile=telemetry,
        incident_matches=incident_matches
    )
```

---

## VALIDATION TARGETS

### On test_project/ (existing fixture)

1. Findings in all 4 categories: security, business, operational, compounding
2. At least one CRITICAL finding from confirmed evidence
3. Zero CRITICAL findings from HEURISTIC evidence
4. Flow map renders with ⚠ markers
5. Risk score 80-90

### On crewAI-examples (real-world validation)

1. **STRATUM-001 (CRITICAL)** fires on email_auto_responder_flow with evidence ONLY from that flow's files
2. **STRATUM-CR01 (HIGH or CRITICAL)** fires on stock_analysis — "ScrapeWebsiteTool feeds 4 agents"
3. **STRATUM-CR02 (HIGH)** fires on email_auto_responder_flow — "email_response_writer bypasses email_filter_agent"
4. **Flow map** renders for at least 2 distinct flows/crews
5. **Incident match_reason** for EchoLeak references specific Gmail paths and the email crew name
6. **shares_with edges < 10** (scoped to crews, not 42-edge Cartesian product)
7. **agent-to-agent edges > 0** (at least the email crew chain and stock_analysis chain)
8. **guardrail edges: at least some guardrails connected** (covers_tools populated where AST can determine it)
9. **Enriched telemetry** has all fields populated
10. **Risk score 70-85** (compounding findings add bonuses)
11. **STRATUM-002 remediation** uses `human_input=True` (CrewAI), not `graph.compile(...)` (LangGraph)
12. **Badge SVG** generates with correct score color

### The Demo Moment

The CR01 finding on stock_analysis should read something like:

```
🔴 STRATUM-CR01 | CRITICAL | Shared tool blast radius

ScrapeWebsiteTool feeds 4 agents — blast radius: 3 external services

  ScrapeWebsiteTool (external input)
    ├──▶ Financial Agent ──▶ [Web search, HTTP endpoint]
    ├──▶ Research Analyst ──▶ [Web scraper, SEC API]
    ├──▶ Financial Analyst ──▶ [Web search, HTTP endpoint]
    └──▶ Investment Advisor ──▶ [Web search]

If ScrapeWebsiteTool returns poisoned data (prompt injection in scraped content),
4 agents are compromised simultaneously: Financial Agent, Research Analyst Agent,
Financial Analyst Agent, Investment Advisor Agent. Each has independent downstream
actions, so a single point of compromise fans out to 3 external services.

A single poisoned webpage would compromise your entire analysis pipeline.

  📎 Matches: Docker Ask Gordon Prompt Injection (2025-Q4)
     Your stock_analysis crew processes external web content via ScrapeWebsiteTool
     and distributes it to 4 agents with no content validation — the same
     untrusted-input→tool-execution pattern that enabled the Docker Gordon exploit.

  Category: compounding
  OWASP: ASI01 — Agent Goal Hijacking
  
  Fix (CrewAI):
    class ValidatedScraper(BaseTool):
        def _run(self, url: str) -> str:
            raw = ScrapeWebsiteTool()._run(url)
            if contains_injection_patterns(raw):
                raise ValueError("Suspicious content detected")
            return raw
```

That finding can only exist because the graph traced the fan-out from one shared node. No checklist produces it. **That's the screenshot. That's the tweet. That's the VC slide.**

---

## RISK SCORE UPDATES

Add compounding finding bonuses:

```python
# Existing
SEVERITY_SCORES = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
BONUS_ZERO_GUARDRAILS = 15
BONUS_KNOWN_CVE = 20
BONUS_FINANCIAL_NO_HITL = 10
BONUS_ZERO_ERROR_HANDLING = 5

# NEW
BONUS_BLAST_RADIUS_3_PLUS = 10      # Any blast radius with 3+ agents
BONUS_CONTROL_BYPASS = 8            # Any architectural control bypass detected
BONUS_ZERO_AGENT_CHAIN_CONTROLS = 5 # Sequential chain with 0 controls on handoffs
```

---

## WHAT DOES NOT CHANGE

- Capability detection (AST parsing, framework tool detection) — unchanged
- MCP scanning — unchanged
- Env var scanning — unchanged
- Non-path rules (STRATUM-003 through STRATUM-007) — unchanged
- History/diff system — unchanged
- `--no-telemetry` flag — unchanged, now respects enriched profile
- Quick fix type annotations — unchanged
- Dedup contract — unchanged (finding.id + sorted evidence)
- Confidence gating — unchanged (CRITICAL requires CONFIRMED)

---

## TELEMETRY BACKEND (Minimum Viable)

For the telemetry to actually flow, you need one endpoint:

```
POST /v1/profiles
Content-Type: application/json
Body: EnrichedTelemetryProfile (JSON)
→ INSERT into telemetry_profiles → return 202
```

Stack: Supabase (free tier gives you Postgres + REST API), Fly.io, or a single Vercel serverless function. 20 minutes of work. Then set `STRATUM_TELEMETRY_ENDPOINT` in the code.

The badge endpoint is separate:

```
GET /badge/:topology_signature
→ Return cached SVG badge for this project's most recent scan
```

This can be the same Supabase project with an Edge Function. The badge URL in the README points to this endpoint, so every visitor to the GitHub repo triggers a badge render.

---

## SUMMARY: WHAT THIS PATCH DELIVERS

| Before | After |
|---|---|
| 42 noise shares_with edges (Cartesian product) | Scoped shares_with within crews only |
| 0 agent-to-agent edges | Crew-derived chains (feeds_into, delegates_to) |
| 0 guardrail edges | Guardrail-to-capability linking where AST can determine it |
| 0 compounding findings | CR01 (blast radius), CR02 (control bypass), BR01 (uncontrolled chain) |
| 0 business findings | BR02 (no observability on sensitive paths) |
| No flow map | ASCII topology diagram in every scan |
| No incident match_reason | Path-specific explanation of why incident matched |
| LangGraph remediation for CrewAI code | Framework-detected remediation |
| 5-field telemetry | 30+ field enriched profile for 20/10 dataset |
| Evidence cites unrelated files | Evidence scoped to the actual traced path |
| No badge | SVG badge for README |
