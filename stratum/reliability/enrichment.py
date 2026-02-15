"""Graph enrichment layer for reliability analysis.

Runs AFTER graph construction, BEFORE finding engines.
Annotates nodes/edges with reliability-relevant metadata.
All enrichments are additive — they populate fields, never overwrite.
"""
from __future__ import annotations

import ast
import re

from stratum.graph.models import EdgeType, GraphEdge, GraphNode, NodeType, RiskGraph
from stratum.models import TrustLevel


# ---------------------------------------------------------------------------
# Capability enrichment: reversibility, subtype, side effects
# ---------------------------------------------------------------------------

# Tools/libraries that produce irreversible side effects
IRREVERSIBLE_PATTERNS = {
    "outbound", "financial",  # capability kinds
}
IRREVERSIBLE_LIBRARIES = {
    "requests", "httpx", "urllib", "smtplib", "stripe", "paypalrestsdk",
    "square", "braintree", "twilio", "sendgrid",
}
CONDITIONAL_LIBRARIES = {
    "psycopg2", "sqlalchemy", "pymongo", "sqlite3", "redis",
}

# Subtype inference from function/tool names
SUBTYPE_PATTERNS = {
    "approve": r"(?i)(approv|accept|confirm|authorize)",
    "reject": r"(?i)(reject|deny|decline|block|refuse)",
    "categorize": r"(?i)(categoriz|classif|label|tag|sort|triage)",
    "route": r"(?i)(route|dispatch|assign|forward|direct)",
    "recommend": r"(?i)(recommend|suggest|propos|advise)",
    "selection_tool": r"(?i)(select|choose|pick|filter|rank|score)",
}


def enrich_graph(graph: RiskGraph, py_files: list[tuple[str, str]] | None = None) -> None:
    """Run all enrichment passes on the graph. Mutates in place."""
    _enrich_capabilities(graph)
    _enrich_agents(graph, py_files)
    _enrich_data_stores(graph, py_files)
    _detect_observability_sinks(graph, py_files)
    _enrich_edge_metadata(graph, py_files)
    _compute_implicit_authority(graph)
    _compute_error_boundaries(graph)
    _compute_shared_state_conflicts(graph)


# ---------------------------------------------------------------------------
# Capability analysis
# ---------------------------------------------------------------------------

def _enrich_capabilities(graph: RiskGraph) -> None:
    """Populate reversibility, subtype, regulatory_category on capability nodes."""
    for node in graph.nodes.values():
        if node.node_type != NodeType.CAPABILITY:
            continue

        # Reversibility
        if not node.reversibility:
            cap_id = node.id
            kind = cap_id.rsplit("_", 1)[-1] if "_" in cap_id else ""
            lib = node.framework.lower() if node.framework else ""

            if kind in IRREVERSIBLE_PATTERNS or lib in IRREVERSIBLE_LIBRARIES:
                node.reversibility = "irreversible"
            elif lib in CONDITIONAL_LIBRARIES or kind == "destructive":
                node.reversibility = "conditional"
            elif kind in ("data_access", "file_system"):
                node.reversibility = "reversible"
            else:
                node.reversibility = "irreversible"  # default conservative

        # Subtype
        if not node.subtype:
            label = node.label.lower()
            matched = False
            for stype, pattern in SUBTYPE_PATTERNS.items():
                if re.search(pattern, label):
                    node.subtype = stype
                    matched = True
                    break
            if not matched:
                node.subtype = "general"

        # Regulatory category
        if not node.regulatory_category:
            cap_kind = node.id.rsplit("_", 1)[-1] if "_" in node.id else ""
            if cap_kind == "financial":
                node.regulatory_category = "financial"
            elif node.data_sensitivity in ("personal", "credentials"):
                node.regulatory_category = "personal_data"
            elif cap_kind == "outbound":
                node.regulatory_category = "communications"

        # External service flag
        if not node.external_service:
            cap_kind = node.id.rsplit("_", 1)[-1] if "_" in node.id else ""
            lib = node.framework.lower() if node.framework else ""
            if cap_kind in ("outbound", "financial") or lib in IRREVERSIBLE_LIBRARIES:
                node.external_service = True

        # Data mutation flag
        if not node.data_mutation:
            cap_kind = node.id.rsplit("_", 1)[-1] if "_" in node.id else ""
            lib = node.framework.lower() if node.framework else ""
            if cap_kind in ("destructive", "financial") or lib in CONDITIONAL_LIBRARIES:
                node.data_mutation = True

        # Human visible (outbound-facing capabilities)
        if not node.human_visible:
            label = node.label.lower()
            if re.search(r"(?i)(email|slack|discord|teams|notify|alert|report|dashboard)", label):
                node.human_visible = True

        # Idempotent inference
        if node.idempotent is None:
            cap_kind = node.id.rsplit("_", 1)[-1] if "_" in node.id else ""
            if cap_kind in ("data_access", "file_system") and node.subtype in ("query", "general"):
                node.idempotent = True
            elif cap_kind in ("destructive", "financial", "outbound"):
                node.idempotent = False


# ---------------------------------------------------------------------------
# Agent analysis
# ---------------------------------------------------------------------------

def _enrich_agents(graph: RiskGraph, py_files: list[tuple[str, str]] | None = None) -> None:
    """Populate error_handling_pattern, timeout_config, model_pinned, etc."""
    # Build source file content lookup
    file_contents: dict[str, str] = {}
    if py_files:
        for fpath, content in py_files:
            file_contents[fpath] = content

    for node in graph.nodes.values():
        if node.node_type != NodeType.AGENT:
            continue

        src = node.source_file
        content = file_contents.get(src, "")
        if not content:
            # Try without leading path
            for fpath, fcontent in file_contents.items():
                if fpath.endswith(src) or src.endswith(fpath):
                    content = fcontent
                    break

        # Error handling pattern
        if not node.error_handling_pattern and content:
            node.error_handling_pattern = _detect_error_pattern(content)

        # Timeout config
        if not node.timeout_config and content:
            node.timeout_config = _detect_timeout(content)

        # Model pinned
        if not node.model_pinned and content:
            node.model_pinned = _detect_model_pinned(content)

        # Prompt dynamic
        if not node.prompt_dynamic and content:
            node.prompt_dynamic = _detect_dynamic_prompt(content)

        # Objective tag inference from role/goal keywords
        if not node.objective_tag and content:
            node.objective_tag = _infer_objective_tag(content, node.label)

        # makes_decisions: agents with approve/reject/route capabilities
        if not node.makes_decisions:
            agent_tools = _get_agent_tools(graph, node.id)
            node.makes_decisions = any(
                graph.nodes[tid].subtype in ("approve", "reject", "categorize", "route")
                for tid in agent_tools
                if tid in graph.nodes
            )

        # max_iterations detection
        if node.max_iterations is None and content:
            m = re.search(r"max_iter\w*\s*=\s*(\d+)", content)
            if m:
                node.max_iterations = int(m.group(1))

        # delegation_enabled detection
        if not node.delegation_enabled and content:
            if re.search(r"(?i)(allow_delegation\s*=\s*True|delegation_enabled\s*=\s*True)", content):
                node.delegation_enabled = True

        # human_input_enabled detection
        if not node.human_input_enabled and content:
            if re.search(r"(?i)(human_input\s*=\s*True|interrupt_before|human_in_the_loop)", content):
                node.human_input_enabled = True

        # LLM model detection
        if not node.llm_model and content:
            m = re.search(r'(?:llm|model)\s*=\s*["\']([^"\']+)["\']', content)
            if m:
                node.llm_model = m.group(1)

        # Temperature detection
        if node.temperature is None and content:
            m = re.search(r'temperature\s*=\s*([0-9.]+)', content)
            if m:
                try:
                    node.temperature = float(m.group(1))
                except ValueError:
                    pass

        # Output schema detection
        if not node.output_schema and content:
            m = re.search(r'output_pydantic\s*=\s*(\w+)', content)
            if m:
                node.output_schema = m.group(1)
            else:
                m = re.search(r'output_json\s*=\s*(\w+)', content)
                if m:
                    node.output_schema = m.group(1)

        # Memory enabled detection
        if not node.memory_enabled and content:
            if re.search(r"(?i)(memory\s*=\s*True|MemorySaver|ConversationBufferMemory)", content):
                node.memory_enabled = True


def _detect_error_pattern(content: str) -> str:
    """Detect error handling pattern from source code."""
    has_try = "try:" in content or "try :" in content
    has_except = "except" in content

    if not has_try and not has_except:
        return "fail_loud"

    # Check for default-on-error: except block returns a default value
    if re.search(r"except.*:\s*\n\s*return\s+(\[\]|{}|None|""|\'\"|0|False)", content):
        return "default_on_error"

    # Check for retry patterns
    if re.search(r"(?i)(retry|retries|max_retries|backoff|tenacity)", content):
        if re.search(r"except.*:\s*\n\s*return", content):
            return "retry_then_default"
        return "fail_loud"

    # Check for silent swallow: except: pass
    if re.search(r"except.*:\s*\n\s*(pass|\.\.\.)\s*$", content, re.MULTILINE):
        return "fail_silent"

    return "fail_loud"


def _detect_timeout(content: str) -> bool:
    """Detect if any timeout mechanism is configured."""
    timeout_patterns = [
        r"max_execution_time\s*=",
        r"step_timeout\s*=",
        r"timeout\s*=\s*\d",
        r"max_iter\s*=",
        r"circuit_breaker",
        r"asyncio\.wait_for",
        r"func_timeout",
    ]
    return any(re.search(p, content) for p in timeout_patterns)


def _detect_model_pinned(content: str) -> bool:
    """Detect if model version is explicitly pinned."""
    # Pinned: model="gpt-4-0613", model="claude-3-sonnet-20240229"
    if re.search(r'model\s*=\s*["\'][\w-]+-\d{4,}', content):
        return True
    # Pinned via env var is also intentional
    if re.search(r'model\s*=\s*os\.environ', content):
        return True
    return False


def _detect_dynamic_prompt(content: str) -> bool:
    """Detect if prompt template uses dynamic interpolation."""
    # f-strings, .format(), % formatting in prompt/goal/backstory
    prompt_context = re.findall(
        r'(?:prompt|goal|backstory|system_message|instructions)\s*=\s*(.{1,200})',
        content, re.DOTALL,
    )
    for ctx in prompt_context:
        if re.search(r'(f["\']|\.format\(|%\s*\()', ctx):
            return True
    return False


def _infer_objective_tag(content: str, agent_label: str) -> str:
    """Infer objective tag from agent role description."""
    # Look for goal/objective/role keywords near the agent definition
    objective_patterns = [
        (r"(?i)maximiz\w+\s+(\w+)", "maximize_"),
        (r"(?i)minimiz\w+\s+(\w+)", "minimize_"),
        (r"(?i)optimiz\w+\s+(\w+)", "optimize_"),
        (r"(?i)increas\w+\s+(\w+)", "increase_"),
        (r"(?i)reduc\w+\s+(\w+)", "reduce_"),
        (r"(?i)improv\w+\s+(\w+)", "improve_"),
    ]
    for pattern, prefix in objective_patterns:
        m = re.search(pattern, content)
        if m:
            return prefix + m.group(1).lower()
    return ""


def _get_agent_tools(graph: RiskGraph, agent_id: str) -> list[str]:
    """Get tool node IDs for an agent."""
    return [
        e.source for e in graph.edges
        if e.edge_type == EdgeType.TOOL_OF and e.target == agent_id
    ]


# ---------------------------------------------------------------------------
# Data store analysis
# ---------------------------------------------------------------------------

def _enrich_data_stores(graph: RiskGraph, py_files: list[tuple[str, str]] | None = None) -> None:
    """Populate concurrency_control on data store nodes."""
    file_contents: dict[str, str] = {}
    if py_files:
        for fpath, content in py_files:
            file_contents[fpath] = content

    all_content = "\n".join(file_contents.values())

    for node in graph.nodes.values():
        if node.node_type != NodeType.DATA_STORE:
            continue

        if not node.concurrency_control:
            label = node.label.lower()
            if "redis" in label:
                node.concurrency_control = "lock"  # Redis supports distributed locks
            elif "postgres" in label or "sql" in label:
                node.concurrency_control = "version"  # SQL has transactions
            elif re.search(r"(?i)(lock|mutex|semaphore|atomic)", all_content):
                node.concurrency_control = "lock"
            else:
                node.concurrency_control = "none"

        # Persistence
        if not node.persistence:
            label = node.label.lower()
            if any(k in label for k in ("redis", "cache", "memcached")):
                node.persistence = "ephemeral"
            elif any(k in label for k in ("postgres", "mysql", "mongo", "sqlite", "s3", "dynamo")):
                node.persistence = "persistent"
            elif any(k in label for k in ("session", "context", "state")):
                node.persistence = "session"
            else:
                node.persistence = "persistent"

        # Access pattern
        if not node.access_pattern:
            has_read = any(
                e.edge_type == EdgeType.READS_FROM and e.source == node.id
                for e in graph.edges
            )
            has_write = any(
                e.edge_type == EdgeType.WRITES_TO and e.target == node.id
                for e in graph.edges
            )
            if has_read and has_write:
                node.access_pattern = "read_write"
            elif has_read:
                node.access_pattern = "read_only"
            elif has_write:
                node.access_pattern = "write_only"

        # Schema defined
        if not node.schema_defined:
            label = node.label.lower()
            if any(k in label for k in ("postgres", "mysql", "sqlite", "sql")):
                node.schema_defined = True
            elif re.search(r"(?i)(schema|model|pydantic|TypedDict)", all_content):
                node.schema_defined = True

        # Contains PII
        if node.contains_pii is None:
            if node.data_sensitivity in ("personal", "credentials"):
                node.contains_pii = True
            else:
                node.contains_pii = False

        # Freshness mechanism
        if not node.freshness_mechanism:
            label = node.label.lower()
            if "redis" in label or "cache" in label:
                node.freshness_mechanism = "ttl"
            elif node.ttl_configured:
                node.freshness_mechanism = "ttl"
            else:
                node.freshness_mechanism = "none"

        # Store domain
        if not node.store_domain:
            label = node.label.lower()
            if any(k in label for k in ("user", "customer", "profile", "account")):
                node.store_domain = "user_data"
            elif any(k in label for k in ("order", "payment", "transaction", "invoice")):
                node.store_domain = "financial"
            elif any(k in label for k in ("log", "audit", "event", "metric")):
                node.store_domain = "operational"
            elif any(k in label for k in ("config", "setting", "preference")):
                node.store_domain = "configuration"


# ---------------------------------------------------------------------------
# Observability sink detection
# ---------------------------------------------------------------------------

OBSERVABILITY_PATTERNS = {
    "langsmith": (r"(?i)(langsmith|LangSmithCallbackHandler|LANGCHAIN_TRACING_V2)", "langsmith"),
    "opentelemetry": (r"(?i)(opentelemetry|OTLPSpanExporter|TracerProvider)", "opentelemetry"),
    "datadog": (r"(?i)(ddtrace|datadog)", "datadog"),
    "wandb": (r"(?i)(wandb|WandbCallbackHandler)", "wandb"),
    "logging": (r"logging\.(getLogger|basicConfig|info|warning|error|debug)", "logging"),
}


def _detect_observability_sinks(
    graph: RiskGraph,
    py_files: list[tuple[str, str]] | None = None,
) -> None:
    """Detect observability sinks and add OBSERVABILITY_SINK nodes + observed_by edges."""
    if not py_files:
        return

    all_content = "\n".join(content for _, content in py_files)
    detected_sinks: dict[str, str] = {}  # sink_name -> type

    for name, (pattern, obs_type) in OBSERVABILITY_PATTERNS.items():
        if re.search(pattern, all_content):
            detected_sinks[name] = obs_type

    for sink_name, obs_type in detected_sinks.items():
        sink_id = f"obs_{sink_name}"
        if sink_id not in graph.nodes:
            graph.nodes[sink_id] = GraphNode(
                id=sink_id,
                node_type=NodeType.OBSERVABILITY_SINK,
                label=f"{sink_name.title()} ({obs_type})",
                trust_level=TrustLevel.INTERNAL,
                observability_type=obs_type,
                captures_decision_rationale=(obs_type in ("langsmith", "opentelemetry")),
            )

        # Connect agents to this sink via observed_by edges
        # For LangSmith: typically observes the whole graph, so connect all agents
        # For logging: only if logger is in same file as agent
        for nid, node in list(graph.nodes.items()):
            if node.node_type != NodeType.AGENT:
                continue

            should_connect = False
            if obs_type in ("langsmith", "opentelemetry", "datadog", "wandb"):
                should_connect = True  # Global observability covers all agents
            elif obs_type == "logging":
                # Only connect if logging is in same file as agent
                for fpath, content in py_files:
                    if (fpath.endswith(node.source_file) or node.source_file.endswith(fpath)):
                        if re.search(OBSERVABILITY_PATTERNS["logging"][0], content):
                            should_connect = True
                            break

            if should_connect:
                edge_exists = any(
                    e.source == nid and e.target == sink_id
                    and e.edge_type == EdgeType.OBSERVED_BY
                    for e in graph.edges
                )
                if not edge_exists:
                    graph.edges.append(GraphEdge(
                        source=nid,
                        target=sink_id,
                        edge_type=EdgeType.OBSERVED_BY,
                        has_control=False,
                    ))


# ---------------------------------------------------------------------------
# Edge metadata enrichment
# ---------------------------------------------------------------------------

def _enrich_edge_metadata(
    graph: RiskGraph,
    py_files: list[tuple[str, str]] | None = None,
) -> None:
    """Populate schema_validated, scoped on edges."""
    all_content = ""
    if py_files:
        all_content = "\n".join(content for _, content in py_files)

    # Check for structured output patterns
    has_pydantic_output = bool(re.search(r"output_pydantic\s*=", all_content))
    has_output_json = bool(re.search(r"output_json\s*=", all_content))
    has_typed_state = bool(re.search(r"class\s+\w+State\s*\(TypedDict\)", all_content))

    for edge in graph.edges:
        if edge.edge_type == EdgeType.FEEDS_INTO:
            # Schema validated if pydantic output or typed state exists
            if has_pydantic_output or has_output_json or has_typed_state:
                edge.schema_validated = True

        elif edge.edge_type == EdgeType.DELEGATES_TO:
            # Scoped if delegation has explicit tool constraints
            # Check for tools= parameter on Task or conditional tool filtering
            if re.search(r"tools\s*=\s*\[", all_content):
                edge.scoped = True

        elif edge.edge_type == EdgeType.READS_FROM:
            # Purpose limited if the read has explicit scoping
            if re.search(r"(?i)(purpose_limit|data_minimiz|need_to_know)", all_content):
                edge.purpose_limited = True

    # Preserves uncertainty check on feeds_into edges
    has_confidence_output = bool(re.search(
        r"(?i)(confidence|uncertainty|probability|score|likelihood)", all_content
    ))
    for edge in graph.edges:
        if edge.edge_type == EdgeType.FEEDS_INTO and has_confidence_output:
            src = graph.nodes.get(edge.source)
            if src and src.output_schema:
                if re.search(r"(?i)(confidence|uncertainty|score)", src.output_schema):
                    edge.preserves_uncertainty = True


# ---------------------------------------------------------------------------
# Computed edges: implicit_authority_over (transitive closure)
# ---------------------------------------------------------------------------

def _compute_implicit_authority(graph: RiskGraph) -> None:
    """Compute implicit_authority_over edges via transitive closure.

    For each agent, compute capabilities reachable through delegation chains
    but not directly assigned. Add IMPLICIT_AUTHORITY_OVER edges for escalated caps.
    """
    # Build agent -> direct tools map
    agent_direct_tools: dict[str, set[str]] = {}
    for edge in graph.edges:
        if edge.edge_type == EdgeType.TOOL_OF:
            agent_direct_tools.setdefault(edge.target, set()).add(edge.source)

    # Build delegation adjacency
    delegation_adj: dict[str, set[str]] = {}
    for edge in graph.edges:
        if edge.edge_type in (EdgeType.DELEGATES_TO, EdgeType.FEEDS_INTO):
            delegation_adj.setdefault(edge.source, set()).add(edge.target)

    # For each agent, compute transitive reachable agents
    for agent_id in list(agent_direct_tools.keys()):
        if agent_id not in graph.nodes:
            continue
        if graph.nodes[agent_id].node_type != NodeType.AGENT:
            continue

        direct_tools = agent_direct_tools.get(agent_id, set())
        reachable_agents = _bfs_reachable(agent_id, delegation_adj)

        # Collect tools of reachable agents
        escalated_tools: set[str] = set()
        for reached_id in reachable_agents:
            reached_tools = agent_direct_tools.get(reached_id, set())
            escalated_tools.update(reached_tools - direct_tools)

        # Add implicit_authority_over edges for escalated capabilities
        for tool_id in escalated_tools:
            tool_node = graph.nodes.get(tool_id)
            if not tool_node:
                continue
            # Only flag high-risk escalations
            kind = tool_id.rsplit("_", 1)[-1] if "_" in tool_id else ""
            if kind in ("financial", "destructive", "outbound", "code_exec"):
                edge_exists = any(
                    e.source == agent_id and e.target == tool_id
                    and e.edge_type == EdgeType.IMPLICIT_AUTHORITY_OVER
                    for e in graph.edges
                )
                if not edge_exists:
                    graph.edges.append(GraphEdge(
                        source=agent_id,
                        target=tool_id,
                        edge_type=EdgeType.IMPLICIT_AUTHORITY_OVER,
                        has_control=False,
                    ))


def _bfs_reachable(start: str, adjacency: dict[str, set[str]]) -> set[str]:
    """BFS from start node, return all reachable nodes (excluding start)."""
    visited: set[str] = set()
    queue = list(adjacency.get(start, set()))
    while queue:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        queue.extend(adjacency.get(current, set()) - visited)
    return visited


# ---------------------------------------------------------------------------
# Computed edges: error_boundary
# ---------------------------------------------------------------------------

def _compute_error_boundaries(graph: RiskGraph) -> None:
    """Mark error boundaries on feeds_into edges.

    If source agent has error_handling_pattern in (default_on_error, fail_silent),
    the feeds_into edge becomes an error boundary.
    """
    for edge in graph.edges:
        if edge.edge_type != EdgeType.FEEDS_INTO:
            continue
        src = graph.nodes.get(edge.source)
        if not src or src.node_type != NodeType.AGENT:
            continue
        if src.error_handling_pattern in ("default_on_error", "fail_silent"):
            # Add an explicit ERROR_BOUNDARY edge parallel to the feeds_into
            boundary_exists = any(
                e.source == edge.source and e.target == edge.target
                and e.edge_type == EdgeType.ERROR_BOUNDARY
                for e in graph.edges
            )
            if not boundary_exists:
                graph.edges.append(GraphEdge(
                    source=edge.source,
                    target=edge.target,
                    edge_type=EdgeType.ERROR_BOUNDARY,
                    has_control=False,
                ))


def _compute_shared_state_conflicts(graph: RiskGraph) -> None:
    """Compute shared_state_conflict edges for agent pairs both writing to same data store.

    For each data_store D:
      Collect all agents with writes_to edges to D
      For each pair (A, B) where A != B:
        If no arbitrated_by edge exists for (A, B):
          Create edge: shared_state_conflict(A <-> B)
    """
    # Build data_store -> writing agents map
    ds_writers: dict[str, set[str]] = {}
    for edge in graph.edges:
        if edge.edge_type == EdgeType.WRITES_TO:
            tgt = graph.nodes.get(edge.target)
            src = graph.nodes.get(edge.source)
            if tgt and tgt.node_type == NodeType.DATA_STORE:
                # Source could be agent or capability; find the owning agent
                if src and src.node_type == NodeType.AGENT:
                    ds_writers.setdefault(edge.target, set()).add(edge.source)
                elif src and src.node_type == NodeType.CAPABILITY:
                    # Find agent that owns this capability
                    for tool_edge in graph.edges:
                        if (tool_edge.edge_type == EdgeType.TOOL_OF
                                and tool_edge.source == edge.source):
                            ds_writers.setdefault(edge.target, set()).add(tool_edge.target)

    # Check for arbitrated_by edges
    arbitrated_pairs: set[tuple[str, str]] = set()
    for edge in graph.edges:
        if edge.edge_type == EdgeType.ARBITRATED_BY:
            arbitrated_pairs.add((edge.source, edge.target))

    # Create shared_state_conflict edges
    for ds_id, writers in ds_writers.items():
        writer_list = sorted(writers)
        for i, a in enumerate(writer_list):
            for b in writer_list[i + 1:]:
                pair = (min(a, b), max(a, b))
                if pair in arbitrated_pairs or (pair[1], pair[0]) in arbitrated_pairs:
                    continue
                # Check if conflict edge already exists
                conflict_exists = any(
                    e.edge_type == EdgeType.SHARED_STATE_CONFLICT
                    and ((e.source == a and e.target == b)
                         or (e.source == b and e.target == a))
                    for e in graph.edges
                )
                if not conflict_exists:
                    graph.edges.append(GraphEdge(
                        source=a,
                        target=b,
                        edge_type=EdgeType.SHARED_STATE_CONFLICT,
                        has_control=False,
                    ))
