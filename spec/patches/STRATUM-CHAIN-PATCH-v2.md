# STRATUM CHAIN PATCH v2

## THE PRIORITY CALL

The previous patch had the right architecture and the wrong order. It invested in distribution infrastructure (badge, GitHub Action, upload API, dashboard) for a product that only works for 20% of the audience.

The corrected priority: make the scanner work for most developers first, then distribute it.

```
WRONG ORDER (previous patch):
  Sprint 1: pip + terminal + badge + git context + LLM detect + env vars + vector stores
  Sprint 2: GitHub Action + upload API + telemetry
  Sprint 3: Dashboard
  Sprint 4: LangGraph + batch scan

RIGHT ORDER (this patch):
  Sprint 1: LangGraph + LangChain ReAct parsers + connectable surfaces
  Sprint 2: pip + terminal redesign + telemetry
  Sprint 3: GitHub Action + upload API
  Sprint 4: Dashboard + batch scan
```

Why: if 400 people scan their code and 280 get "this doesn't understand my project," nothing else matters. The badge doesn't get embedded. The GitHub Action doesn't get installed. The dashboard has no data. Framework breadth is the multiplier on everything downstream.

---

## THE FUNNEL MATH

Current state (CrewAI only):
```
1000 pip installs → 400 successful scans
  CrewAI:       80 (20%)  → full scan, 13 findings  ✓
  LangGraph:    60 (15%)  → tools only, 5 findings   ✗
  LangChain:   120 (30%)  → tools only, 5 findings   ✗
  AutoGen:      20 (5%)   → tools only, 5 findings   ✗
  Custom:       80 (20%)  → tools only, 5 findings   ✗
  No agents:    40 (10%)  → empty scan                ✗

Satisfaction: 80/400 = 20%
```

After this patch (CrewAI + LangGraph full, LangChain partial):
```
  CrewAI:       80 (20%)  → full scan, 13 findings    ✓
  LangGraph:    60 (15%)  → full scan, 13 findings    ✓ NEW
  LangChain:   120 (30%)  → partial scan, 9 findings  △ NEW
  AutoGen:      20 (5%)   → tools only, 5 findings    ✗
  Custom:       80 (20%)  → tools only, 5 findings    ✗
  No agents:    40 (10%)  → empty scan                 ✗

Satisfaction: 260/400 = 65%
```

3.25× improvement. Every downstream metric — badge adoption, Action installs, dashboard signups — multiplied by 3.25.

---

## SPRINT 1: FRAMEWORK PARSERS + CONNECTABLE SURFACES

### 1A. Scanner Architecture: Framework Dispatcher

The scanner currently has CrewAI parsing hardwired into the pipeline. Step 4 needs to become a dispatcher.

```python
# scanner.py — the framework dispatch

def scan(directory: str) -> ScanResult:
    # Steps 1-3: framework-agnostic (unchanged)
    files = discover_files(directory)
    asts = parse_asts(files)
    capabilities = detect_capabilities(asts)
    guardrails = detect_guardrails(asts)
    
    # Step 4: framework-specific parsing (NEW DISPATCHER)
    detected_frameworks = detect_frameworks(asts, files)
    
    crews = []
    agents = []
    relationships = []
    llm_models = []
    
    if "CrewAI" in detected_frameworks:
        cr_crews, cr_agents, cr_rels = parse_crewai(asts, files)
        crews.extend(cr_crews)
        agents.extend(cr_agents)
        relationships.extend(cr_rels)
    
    if "LangGraph" in detected_frameworks:
        lg_crews, lg_agents, lg_rels = parse_langgraph(asts, files)
        crews.extend(lg_crews)
        agents.extend(lg_agents)
        relationships.extend(lg_rels)
    
    if "LangChain" in detected_frameworks:
        lc_crews, lc_agents, lc_rels = parse_langchain_agents(asts, files)
        crews.extend(lc_crews)
        agents.extend(lc_agents)
        relationships.extend(lc_rels)
    
    # Connectable surfaces: detect during AST walk (piggybacked, not separate pass)
    llm_models = detect_llm_models(asts, files)      # NEW
    env_var_names = detect_env_var_names(asts, files)  # NEW
    vector_stores = detect_vector_stores(asts)         # NEW
    
    # Steps 5-8: framework-agnostic (unchanged)
    graph = build_graph(agents, capabilities, relationships, guardrails)
    findings, signals = generate_findings(graph, crews, agents, capabilities)
    risk_score = compute_risk_score(findings, signals, guardrails)
    profile = build_scan_profile(...)
    
    # Determine parse quality
    if crews:  # At least one framework fully parsed
        parse_quality = "full"
    elif agents:  # Agents detected but no crew/graph structure
        parse_quality = "partial"
    elif capabilities:  # Only tools/capabilities detected
        parse_quality = "tools_only"
    else:
        parse_quality = "empty"
    
    return ScanResult(
        ...,
        framework_parse_quality=parse_quality,
        llm_models=llm_models,
        env_var_names=env_var_names,
        vector_stores=vector_stores,
    )
```

The intermediate structures are already defined:
- `CrewDefinition`: name, framework, agent_names, process_type, source_file, has_manager, delegation_enabled
- `AgentDefinition`: name, role, framework, source_file, tool_names
- `AgentRelationship`: source_agent, target_agent, relationship_type, shared_resource, source_file

Each framework parser produces these same structures. Steps 5-8 (graph, findings, scoring, profile) don't care which framework produced them.

### 1B. LangGraph Parser

LangGraph has **explicit** graph topology. This is actually easier to parse than CrewAI (where graph topology is inferred from task ordering).

```python
# parsers/langgraph_parser.py

"""
Detect LangGraph StateGraph definitions and convert to Stratum's model.

LangGraph patterns:
  graph = StateGraph(AgentState)
  graph.add_node("researcher", research_fn)
  graph.add_node("writer", write_fn)
  graph.add_edge("researcher", "writer")
  graph.add_edge(START, "researcher")
  graph.add_conditional_edges("writer", route_fn, {"continue": "researcher", "end": END})
  compiled = graph.compile(checkpointer=MemorySaver(), interrupt_before=["writer"])

Mapping:
  StateGraph       → CrewDefinition (one graph = one crew)
  add_node         → AgentDefinition (one node = one agent)
  add_edge         → AgentRelationship (feeds_into)
  conditional_edge → AgentRelationship (feeds_into, conditional=True)
  compile(checkpointer=) → has_checkpointing = True
  compile(interrupt_before=) → has_hitl = True
  Tool bindings on node functions → agent.tool_names
"""

import ast
from typing import Optional


def parse_langgraph(asts: dict, files: list) -> tuple:
    """
    Returns (crews, agents, relationships) from LangGraph StateGraph definitions.
    """
    all_crews = []
    all_agents = []
    all_rels = []
    
    for filepath, tree in asts.items():
        graphs = _find_stategraphs(tree, filepath)
        
        for graph in graphs:
            # Resolve nodes and edges by tracing method calls on the graph variable
            _resolve_graph_structure(tree, graph)
            
            # Convert to Stratum model
            crew = CrewDefinition(
                name=graph.var_name or f"graph_{filepath_stem(filepath)}",
                framework="LangGraph",
                agent_names=[n.name for n in graph.nodes],
                process_type="graph",
                source_file=filepath,
                has_manager=False,
                delegation_enabled=False,
            )
            all_crews.append(crew)
            
            for node in graph.nodes:
                # Detect tools bound to this node's function
                tool_names = _detect_node_tools(tree, node.func_name, filepath)
                
                agent = AgentDefinition(
                    name=node.name,
                    role=node.name,
                    framework="LangGraph",
                    source_file=filepath,
                    tool_names=tool_names,
                )
                all_agents.append(agent)
            
            for edge in graph.edges:
                if edge.source in ("__start__", "START") or edge.target in ("__end__", "END"):
                    continue
                rel = AgentRelationship(
                    source_agent=edge.source,
                    target_agent=edge.target,
                    relationship_type="feeds_into",
                    shared_resource=None,
                    source_file=filepath,
                )
                all_rels.append(rel)
            
            # Detect control patterns
            if graph.has_checkpointer:
                # Will be picked up by maturity scoring
                pass
            if graph.interrupt_before:
                # Will be picked up by HITL detection
                pass
    
    return all_crews, all_agents, all_rels


def _find_stategraphs(tree: ast.Module, filepath: str) -> list:
    """Find all StateGraph(...) instantiations."""
    graphs = []
    
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        
        call = node.value
        if not isinstance(call, ast.Call):
            continue
        
        # Match: graph = StateGraph(...)
        func_name = _get_call_name(call)
        if func_name != "StateGraph":
            continue
        
        var_name = _get_assign_target(node)
        
        graphs.append(LangGraphDef(
            var_name=var_name,
            source_file=filepath,
            state_class=_get_first_arg_name(call),
            nodes=[],
            edges=[],
            has_checkpointer=False,
            interrupt_before=[],
        ))
    
    return graphs


def _resolve_graph_structure(tree: ast.Module, graph: 'LangGraphDef'):
    """
    Walk the AST to find add_node, add_edge, add_conditional_edges,
    and compile calls on this graph variable.
    """
    var = graph.var_name
    
    for node in ast.walk(tree):
        call = None
        
        # Expression statement: graph.add_node(...)
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call = node.value
        # Assignment: compiled = graph.compile(...)
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            call = node.value
        
        if call is None:
            continue
        
        method = _get_method_call(call, var)
        if method is None:
            continue
        
        if method == "add_node":
            node_name = _get_string_arg(call, 0)
            func_name = _get_arg_name(call, 1)
            if node_name:
                graph.nodes.append(GraphNode(name=node_name, func_name=func_name))
        
        elif method == "add_edge":
            src = _get_string_or_const(call, 0)
            dst = _get_string_or_const(call, 1)
            if src and dst:
                graph.edges.append(GraphEdge(source=src, target=dst))
        
        elif method == "add_conditional_edges":
            src = _get_string_or_const(call, 0)
            # Third arg is the routing dict: {"continue": "node_a", "end": END}
            mapping = _get_dict_values(call, 2)
            for target in mapping:
                if target not in ("__end__", "END"):
                    graph.edges.append(GraphEdge(source=src, target=target))
        
        elif method == "compile":
            for kw in call.keywords:
                if kw.arg == "checkpointer" and not _is_none(kw.value):
                    graph.has_checkpointer = True
                if kw.arg == "interrupt_before":
                    graph.interrupt_before = _extract_string_list(kw.value)


def _detect_node_tools(tree: ast.Module, func_name: str, filepath: str) -> list:
    """
    Find tools bound to a LangGraph node function.
    
    Patterns:
      def research_fn(state):
          tools = [SearchTool(), CalcTool()]
          result = model.bind_tools(tools).invoke(...)
    
    Or:
      research_fn = create_react_agent(model, tools=[...])
    """
    if not func_name:
        return []
    
    tool_names = []
    
    for node in ast.walk(tree):
        # Pattern 1: function definition with tool instantiation inside
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    name = _get_call_name(child)
                    if name and name.endswith("Tool"):
                        tool_names.append(name)
                    # bind_tools([...])
                    if _get_call_name(child) == "bind_tools":
                        tool_names.extend(_extract_tool_names_from_list(child.args))
        
        # Pattern 2: assignment to func_name using create_react_agent etc.
        if isinstance(node, ast.Assign) and _get_assign_target(node) == func_name:
            if isinstance(node.value, ast.Call):
                for kw in node.value.keywords:
                    if kw.arg == "tools":
                        tool_names.extend(_extract_tool_names_from_list([kw.value]))
    
    return list(set(tool_names))


# --- Helper data classes ---

class LangGraphDef:
    def __init__(self, var_name, source_file, state_class, nodes, edges,
                 has_checkpointer, interrupt_before):
        self.var_name = var_name
        self.source_file = source_file
        self.state_class = state_class
        self.nodes = nodes
        self.edges = edges
        self.has_checkpointer = has_checkpointer
        self.interrupt_before = interrupt_before

class GraphNode:
    def __init__(self, name, func_name=None):
        self.name = name
        self.func_name = func_name

class GraphEdge:
    def __init__(self, source, target):
        self.source = source
        self.target = target
```

**What this unlocks:**

On LangGraph projects, the scanner now produces:
- crew_definitions: one per StateGraph (with real agent names from add_node)
- agent_definitions: one per node (with tool_names from function analysis)
- relationships: feeds_into edges from add_edge (more accurate than CrewAI — explicit, not inferred)
- has_checkpointing: from compile(checkpointer=)
- has_hitl: from compile(interrupt_before=)

All 13 finding rules fire because they operate on crews/agents/relationships, not on CrewAI-specific structures. blast_radii work (scoped per graph). CR05 fires (shared tools within a graph). The maturity score is more accurate (LangGraph projects often HAVE checkpointing).

framework_parse_quality = "full".

### 1C. LangChain ReAct Parser

LangChain ReAct doesn't have explicit graph structure. But it has enough signal for 8-9 of 13 findings.

```python
# parsers/langchain_parser.py

"""
Detect LangChain agent patterns and convert to Stratum's model.

Patterns:
  1. AgentExecutor(agent=..., tools=[...])
  2. create_react_agent(llm, tools, prompt)
  3. create_openai_functions_agent(llm, tools, prompt)
  4. create_tool_calling_agent(llm, tools)
  5. initialize_agent(tools, llm, agent=AgentType.ZERO_SHOT_REACT)

Each AgentExecutor/create_*_agent = one agent.
Multiple in the same file or project = multi-agent system.
"""

import ast

AGENT_FACTORY_FUNCTIONS = {
    "create_react_agent",
    "create_openai_functions_agent",
    "create_tool_calling_agent",
    "create_openai_tools_agent",
    "create_structured_chat_agent",
    "create_json_chat_agent",
    "create_xml_agent",
    "initialize_agent",
}


def parse_langchain_agents(asts: dict, files: list) -> tuple:
    """
    Returns (crews, agents, relationships).
    
    LangChain doesn't have crews/graphs, so we create synthetic groupings:
    - All agents in the same file = one "crew" (they likely work together)
    - If only one agent in the whole project, it's a single-agent crew
    """
    # First pass: find all agent definitions across all files
    file_agents = {}  # filepath → [AgentDef]
    
    for filepath, tree in asts.items():
        agents_in_file = []
        
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if not isinstance(node.value, ast.Call):
                continue
            
            call = node.value
            func_name = _get_call_name(call)
            var_name = _get_assign_target(node)
            
            # Pattern 1: AgentExecutor(agent=..., tools=[...])
            if func_name == "AgentExecutor":
                tools = _extract_tools_kwarg(call)
                agents_in_file.append(LCAgentDef(
                    var_name=var_name or "agent",
                    agent_type="AgentExecutor",
                    tools=tools,
                    source_file=filepath,
                    line=node.lineno,
                ))
            
            # Pattern 2: create_react_agent(...) and similar
            elif func_name in AGENT_FACTORY_FUNCTIONS:
                tools = _extract_tools_arg(call)
                agents_in_file.append(LCAgentDef(
                    var_name=var_name or func_name,
                    agent_type=func_name,
                    tools=tools,
                    source_file=filepath,
                    line=node.lineno,
                ))
        
        if agents_in_file:
            file_agents[filepath] = agents_in_file
    
    # Second pass: group into synthetic crews
    all_crews = []
    all_agents = []
    all_rels = []
    
    for filepath, agents_in_file in file_agents.items():
        stem = filepath_stem(filepath)
        
        if len(agents_in_file) > 1:
            # Multiple agents in one file → they're a system
            crew_name = f"{stem}_agents"
            process_type = "sequential"  # Assume sequential, conservative
            
            # Create feeds_into relationships based on definition order
            # (Best we can do without explicit wiring)
            for i in range(len(agents_in_file) - 1):
                all_rels.append(AgentRelationship(
                    source_agent=agents_in_file[i].var_name,
                    target_agent=agents_in_file[i + 1].var_name,
                    relationship_type="feeds_into",
                    shared_resource=None,
                    source_file=filepath,
                ))
        else:
            crew_name = f"{stem}_agent"
            process_type = "single"
        
        crew = CrewDefinition(
            name=crew_name,
            framework="LangChain",
            agent_names=[a.var_name for a in agents_in_file],
            process_type=process_type,
            source_file=filepath,
            has_manager=False,
            delegation_enabled=False,
        )
        all_crews.append(crew)
        
        for agent_def in agents_in_file:
            agent = AgentDefinition(
                name=agent_def.var_name,
                role=agent_def.var_name,
                framework="LangChain",
                source_file=filepath,
                tool_names=agent_def.tools,
            )
            all_agents.append(agent)
    
    # Cross-file agents: if agents in different files share tools, create shares_tool rels
    all_tool_owners = {}  # tool_name → [agent_name]
    for filepath, agents_in_file in file_agents.items():
        for agent_def in agents_in_file:
            for tool in agent_def.tools:
                if tool not in all_tool_owners:
                    all_tool_owners[tool] = []
                all_tool_owners[tool].append(agent_def.var_name)
    
    for tool_name, owners in all_tool_owners.items():
        if len(owners) >= 2:
            for i in range(len(owners)):
                for j in range(i + 1, len(owners)):
                    all_rels.append(AgentRelationship(
                        source_agent=owners[i],
                        target_agent=owners[j],
                        relationship_type="shares_tool",
                        shared_resource=tool_name,
                        source_file="",
                    ))
    
    return all_crews, all_agents, all_rels


def _extract_tools_kwarg(call: ast.Call) -> list:
    """Extract tool names from tools=[...] keyword arg."""
    for kw in call.keywords:
        if kw.arg == "tools":
            return _extract_tool_names(kw.value)
    return []


def _extract_tools_arg(call: ast.Call) -> list:
    """Extract tool names from positional or keyword tools arg."""
    # Most create_*_agent functions: create_react_agent(llm, tools, prompt)
    # tools is typically arg[1]
    if len(call.args) >= 2:
        return _extract_tool_names(call.args[1])
    return _extract_tools_kwarg(call)


def _extract_tool_names(node) -> list:
    """Extract tool names from a list expression: [SearchTool(), CalcTool()]."""
    names = []
    if isinstance(node, ast.List):
        for elt in node.elts:
            if isinstance(elt, ast.Call):
                name = _get_call_name(elt)
                if name:
                    names.append(name)
            elif isinstance(elt, ast.Name):
                names.append(elt.id)
    elif isinstance(node, ast.Name):
        # tools is a variable reference, can't resolve statically
        names.append(f"${node.id}")  # Mark as unresolved
    return names


class LCAgentDef:
    def __init__(self, var_name, agent_type, tools, source_file, line):
        self.var_name = var_name
        self.agent_type = agent_type
        self.tools = tools
        self.source_file = source_file
        self.line = line
```

**Parse quality: "partial"** (not "full" because feeds_into edges are inferred from definition order, not explicit wiring. CR06 bypass detection won't fire because there's no filter/gate concept in flat ReAct agents.)

**What fires on LangChain ReAct projects (8-9 of 13):**
- STRATUM-001: YES (unguarded data-to-external — tool detection works)
- STRATUM-002: YES (destructive no gate — tool detection works)
- CR05: YES (blast radius — if multiple agents share tools)
- CR01: YES (shared tool bridges — from cross-file tool sharing)
- BR01: YES (external messages no review — from capability detection)
- STRATUM-008: YES (no error handling)
- STRATUM-009: YES (no timeout)
- STRATUM-010: YES (no checkpointing)
- CR02: YES (chain no validation — if multiple agents in sequence)
- CR06: NO (bypass — no filter/gate concept)
- CR06.1: NO (same)

### 1D. Connectable Surfaces (Piggybacked on Parser Work)

These are detected during the same AST walk. No extra file I/O.

**LLM Model Detection:**

```python
def detect_llm_models(asts: dict, files: list) -> list:
    """
    Detect LLM model references from Python ASTs and YAML configs.
    Returns [{"model": "gpt-4o", "provider": "openai"}].
    """
    results = []
    
    MODEL_CLASSES = {
        "ChatOpenAI": "openai", "AzureChatOpenAI": "azure",
        "ChatAnthropic": "anthropic", "ChatGoogleGenerativeAI": "google",
        "Ollama": "ollama", "ChatOllama": "ollama",
        "ChatMistralAI": "mistral", "ChatGroq": "groq",
        "ChatBedrock": "aws",
    }
    
    for filepath, tree in asts.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func_name = _get_call_name(node)
            provider = MODEL_CLASSES.get(func_name)
            if not provider:
                continue
            for kw in node.keywords:
                if kw.arg in ("model", "model_name"):
                    model = _extract_string(kw.value)
                    if model and _looks_like_model_name(model):
                        results.append({"model": model, "provider": provider})
    
    # Also scan YAML files for CrewAI llm: directives
    for filepath in files:
        if filepath.endswith((".yaml", ".yml")):
            try:
                with open(filepath) as f:
                    for line in f:
                        if line.strip().startswith("llm:"):
                            value = line.split(":", 1)[1].strip().strip("\"'")
                            if "/" in value:
                                provider, model = value.split("/", 1)
                            else:
                                model = value
                                provider = _infer_provider(model)
                            if _looks_like_model_name(model):
                                results.append({"model": model, "provider": provider})
            except (IOError, UnicodeDecodeError):
                continue
    
    # Deduplicate
    seen = set()
    deduped = []
    for r in results:
        key = (r["model"], r["provider"])
        if key not in seen:
            seen.add(key)
            deduped.append(r)
    
    return deduped
```

**Env Var Name Detection (with specificity classification):**

```python
# Env vars are classified by specificity to reduce Phase 3 noise

UNIVERSAL_ENV_VARS = {
    # Every AI project has these — useless for cross-project connections
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY",
    "LANGCHAIN_API_KEY", "LANGSMITH_API_KEY",
}

SPECIFIC_ENV_VARS_PREFIXES = {
    # These indicate specific service instances — useful for connections
    "PINECONE_": "vector_store",
    "WEAVIATE_": "vector_store",
    "CHROMA_": "vector_store",
    "QDRANT_": "vector_store",
    "SLACK_": "messaging",
    "DISCORD_": "messaging",
    "TWILIO_": "messaging",
    "GMAIL_": "email",
    "SENDGRID_": "email",
    "STRIPE_": "financial",
    "PLAID_": "financial",
    "POSTGRES_": "database",
    "DATABASE_URL": "database",
    "MONGODB_": "database",
    "REDIS_": "database",
    "SUPABASE_": "database",
    "AWS_": "cloud",
    "GCP_": "cloud",
}

def detect_env_var_names(asts: dict, files: list) -> list:
    """
    Returns [{"name": "PINECONE_API_KEY", "specificity": "specific", "category": "vector_store"}].
    Never captures values.
    """
    names = {}  # name → {"specificity", "category"}
    
    # From Python ASTs: os.environ["KEY"], os.getenv("KEY")
    for filepath, tree in asts.items():
        for node in ast.walk(tree):
            key = _extract_env_var_access(node)
            if key:
                names[key] = _classify_env_var(key)
    
    # From .env.example / .env.template files (never real .env)
    for filepath in files:
        basename = os.path.basename(filepath)
        if basename in (".env.example", ".env.template", ".env.sample"):
            try:
                with open(filepath) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            key = line.split("=")[0].strip()
                            if key and key == key.upper():  # Looks like an env var
                                names[key] = _classify_env_var(key)
            except (IOError, UnicodeDecodeError):
                continue
    
    return [{"name": k, **v} for k, v in sorted(names.items())]


def _classify_env_var(key: str) -> dict:
    key_upper = key.upper()
    if key_upper in UNIVERSAL_ENV_VARS:
        return {"specificity": "universal", "category": "llm_api"}
    for prefix, category in SPECIFIC_ENV_VARS_PREFIXES.items():
        if key_upper.startswith(prefix) or key_upper == prefix.rstrip("_"):
            return {"specificity": "specific", "category": category}
    return {"specificity": "unknown", "category": "unknown"}
```

The specificity classification solves the "every project has OPENAI_API_KEY" problem. Phase 3 cross-project connection inference only uses `specificity: "specific"` env vars. `PINECONE_API_KEY` in two projects = meaningful connection. `OPENAI_API_KEY` in two projects = noise.

**Vector Store Detection** (from import analysis — already available):

```python
VECTOR_STORE_IMPORTS = {
    "pinecone": "pinecone",
    "chromadb": "chroma",
    "weaviate": "weaviate",
    "qdrant_client": "qdrant",
    "faiss": "faiss",
    "pymilvus": "milvus",
    "pgvector": "pgvector",
    "lancedb": "lancedb",
    "langchain_community.vectorstores": "langchain_vectorstore",
}

def detect_vector_stores(asts: dict) -> list:
    """Detect vector store usage from imports."""
    found = set()
    for filepath, tree in asts.items():
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                module = ""
                if isinstance(node, ast.ImportFrom) and node.module:
                    module = node.module
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        module = alias.name
                for pattern, store_name in VECTOR_STORE_IMPORTS.items():
                    if pattern in module:
                        found.add(store_name)
    return sorted(found)
```

### 1E. New Profile Fields

```python
# Add to ScanProfile dataclass:

# --- Project identity (populated by scanner + CI context) ---
project_name: str = ""
repo_url: str = ""
org_id: str = ""
branch: str = ""
commit_sha: str = ""
scan_source: str = "cli"

# --- Parse quality ---
framework_parse_quality: str = "unknown"  # "full" | "partial" | "tools_only" | "empty"

# --- LLM dependencies (Phase 3 connectable surface) ---
llm_models: list = field(default_factory=list)      # [{"model": "gpt-4o", "provider": "openai"}]
llm_providers: list = field(default_factory=list)    # ["openai", "anthropic"]
llm_model_count: int = 0
has_multiple_providers: bool = False

# --- Env var names (Phase 3 connectable surface) ---
env_var_names: list = field(default_factory=list)    # [{"name": "...", "specificity": "...", "category": "..."}]
env_var_names_specific: list = field(default_factory=list)  # Only "specific" ones (for connection inference)

# --- Vector stores (Phase 3 connectable surface) ---
vector_stores: list = field(default_factory=list)    # ["pinecone", "chroma"]
has_vector_store: bool = False

# --- Stable project identifier (for rescan tracking) ---
project_hash: str = ""  # hash(git_remote OR directory_name) — STABLE across code changes
```

**project_hash vs topology_signature:** topology_signature changes when the code changes (it hashes the graph). project_hash is stable — it identifies the project, not the code state. Rescan tracking uses project_hash. Graph fingerprinting uses topology_signature. Both exist. They serve different purposes.

```python
def _compute_project_hash(directory: str) -> str:
    """
    Stable identifier for a project. Does NOT change when code changes.
    Based on git remote URL (if available) or directory name.
    """
    remote_url = _detect_git_remote(directory)
    if remote_url:
        return hashlib.sha256(remote_url.encode()).hexdigest()[:16]
    dir_name = os.path.basename(os.path.abspath(directory))
    return hashlib.sha256(dir_name.encode()).hexdigest()[:16]
```

---

## SPRINT 2: TERMINAL + PIP + TELEMETRY

### 2A. Terminal Redesign

Fully specified in STRATUM-TERMINAL-REDESIGN.md and STRATUM-10-10-PATCH.md. Summary:

- action_groups.py: 13 findings → 7 actions → 3 that matter
- risk_bar.py: visual score bar
- flow_map.py: per-crew ASCII diagrams
- code_block.py: bordered code snippets
- terminal.py: orchestrator (action groups → flow maps → one-liners)
- verbose.py, quiet.py: --verbose and --quiet modes
- --badge flag: generates stratum-badge.svg

No changes from previous specs. Just moved to Sprint 2 because it's useless without framework breadth.

### 2B. pip Package

```toml
# pyproject.toml
[project]
name = "stratum-cli"
version = "0.3.0"
description = "AI agent security scanner"
readme = "README.md"
license = {text = "MIT"}
requires-python = ">=3.9"
dependencies = [
    "click>=8.0",
    "pyyaml>=6.0",
    "rich>=13.0",
]

[project.scripts]
stratum = "stratum.cli:main"

[build-system]
requires = ["setuptools>=68.0"]
build-backend = "setuptools.backends._legacy:_Backend"
```

### 2C. Usage Telemetry

```python
@dataclass
class UsagePing:
    """
    ~200 bytes. Sent once per scan. Anonymous. Opt-in.
    
    This is NOT the full profile. It's a lightweight signal
    for PMF measurement and framework prioritization.
    """
    # Scanner identity
    v: str                      # scanner version
    os: str                     # "darwin" | "linux" | "windows"
    py: str                     # python version
    
    # Project signal (anonymous)
    project_hash: str           # STABLE across code changes (for rescan tracking)
    sig: str                    # topology_signature (for graph fingerprinting)
    
    # Framework signal (most important for prioritization)
    fw: list                    # ["CrewAI", "LangGraph"]
    parse_quality: str          # "full" | "partial" | "tools_only" | "empty"
    
    # Value signal
    agents: int
    crews: int
    findings: int
    max_sev: str                # "critical" | "high" | "medium" | "low" | "none"
    score: int
    
    # Fix rate signal (for PMF measurement)
    findings_by_cat: dict       # {"security": 2, "compounding": 5, ...} (aggregate, not identifying)
    
    # Adoption signal
    scan_source: str            # "cli" | "github_action" | "gitlab_ci" | "ci"
    duration_ms: int
    files: int
    
    # Debug signal
    error: str                  # null if success; "TypeError: in graph_builder" if failed
    error_module: str           # "graph_builder" | "crewai_parser" | "finding_gen"
```

**The rescan/fix tracking query (the most important PMF signal):**

```sql
-- Find projects that rescanned AND improved
WITH project_scans AS (
    SELECT project_hash, score, parse_quality, received_at,
           LAG(score) OVER (PARTITION BY project_hash ORDER BY received_at) as prev_score,
           ROW_NUMBER() OVER (PARTITION BY project_hash ORDER BY received_at) as scan_num
    FROM usage_pings
    WHERE project_hash IS NOT NULL
)
SELECT 
    COUNT(DISTINCT project_hash) FILTER (WHERE scan_num > 1) as rescan_projects,
    COUNT(DISTINCT project_hash) FILTER (WHERE score < prev_score) as improved_projects,
    COUNT(DISTINCT project_hash) as total_projects,
    -- PMF signal: what % of rescans show improvement?
    ROUND(
        COUNT(DISTINCT project_hash) FILTER (WHERE score < prev_score) * 100.0 /
        NULLIF(COUNT(DISTINCT project_hash) FILTER (WHERE scan_num > 1), 0)
    , 1) as fix_rate_pct
FROM project_scans;
```

If fix_rate > 40%, the scanner is driving behavior change. That's PMF.

**The framework investment query:**

```sql
-- Where are we losing people?
SELECT fw_element as framework,
       parse_quality,
       COUNT(*) as scans,
       AVG(findings) as avg_findings,
       COUNT(*) FILTER (WHERE scan_num = 1) as first_scans,
       COUNT(*) FILTER (WHERE scan_num > 1) as rescans,
       ROUND(COUNT(*) FILTER (WHERE scan_num > 1) * 100.0 / COUNT(*), 1) as rescan_pct
FROM usage_pings, UNNEST(fw) as fw_element
LEFT JOIN (
    SELECT project_hash, ROW_NUMBER() OVER (PARTITION BY project_hash ORDER BY received_at) as scan_num
    FROM usage_pings
) sub USING (project_hash)
GROUP BY fw_element, parse_quality
ORDER BY scans DESC;

-- Expected output:
-- LangChain | partial    | 120 | 8.5  | 100 | 20 | 16.7%
-- CrewAI    | full       |  80 | 12.3 |  50 | 30 | 37.5%  ← highest rescan rate
-- LangGraph | full       |  60 | 11.8 |  40 | 20 | 33.3%
-- AutoGen   | tools_only |  20 | 4.1  |  18 |  2 | 10.0%  ← low value, low rescan
```

This tells you: CrewAI and LangGraph users rescan at 3× the rate of AutoGen users. Don't invest in AutoGen yet.

### 2D. Telemetry Consent

First scan shows:
```
Stratum collects anonymous usage data (framework, finding count, risk score).
No code, file paths, or personal data is sent. Disable: stratum config telemetry off
```

Stored in `~/.stratum/config.json`:
```json
{"telemetry": true, "first_run": false}
```

If `telemetry: false`, nothing is sent. No nagging.

---

## SPRINT 3: GITHUB ACTION + UPLOAD

### 3A. GitHub Action

Unchanged from previous patch. Key point: the Action does three things:
1. Runs the scan (Phase 1 value)
2. Posts a PR comment (Phase 1 distribution inside teams)
3. Uploads the profile (Phase 2 data pipeline)

The profile upload injects CI context:
```python
profile['project_name'] = github.event.repository.name
profile['repo_url'] = f"https://github.com/{github.repository}"
profile['org_id'] = github.repository_owner
profile['branch'] = github.ref_name
profile['commit_sha'] = github.sha[:12]
profile['scan_source'] = "github_action"
```

### 3B. Upload API

Supabase. One table. Org-scoped RLS. Same as previous patch.

The only addition: the API rejects profiles with `framework_parse_quality: "empty"`. No point storing empty scans.

### 3C. What Triggers Phase 2

Phase 2 doesn't require a dashboard. Phase 2 requires the **data structure** that makes a dashboard possible.

The Phase 2 trigger is: `SELECT COUNT(DISTINCT repo_url) FROM profiles WHERE org_id = 'acme'` returns >= 3.

At that point, even a static HTML report generated from a SQL query is a "dashboard." The engineering lead sees their fleet for the first time. You email it to them. You ask if they'd pay for it. That's the Phase 2 PMF test.

Don't build a dashboard app in Sprint 3. Generate a static report from the data and email it to orgs that hit the 3-repo threshold. If they respond with "YES I need this," build the dashboard.

---

## SPRINT 4: BATCH SCAN + ECOSYSTEM DATA

### 4A. Batch Scan Pipeline

Unchanged from previous specs. Scan 50K GitHub repos. Store profiles in Supabase.

With LangGraph + LangChain parsers, expected full-quality profiles go from ~8K to ~17K. Partial-quality (LangChain) adds another ~10K. Total usable: ~27K profiles.

### 4B. Ecosystem Report

"State of AI Agent Security 2026" — generated from batch scan data.

Key statistics:
- % of projects with no HITL
- % of projects matching breach patterns
- Model dependency concentration
- Average maturity score by framework
- Blast radius distribution

This report is:
1. Content marketing (HN, Twitter, LinkedIn)
2. The enterprise pitch deck ("here's what the ecosystem looks like, here's where you sit")
3. Proof that the intelligence database has value

---

## WHAT THIS PATCH DOES NOT INCLUDE (AND WHY)

**AutoGen parser.** 5% of the audience. Build it when telemetry shows AutoGen users attempting scans and bouncing.

**Dashboard web app.** Build it when 3+ orgs hit the 3-repo threshold from organic GitHub Action adoption. Until then, a static HTML report proves the concept without engineering investment.

**Runtime SDK.** Phase 4. 6+ months out. The graph model is already compatible. Don't build it until you have paying enterprise customers asking for it.

**LCEL chain parsing.** LangChain chain composition (prompt | llm | parser) is detectable but produces minimal graph structure (linear chains). The AgentExecutor parser covers the high-value patterns. LCEL chains can be added later as a refinement.

**Shareable report URLs.** Requires hosted infrastructure. The badge + PR comment handle distribution for now. Shareable URLs come with the dashboard.

---

## SCANNER BUG FIXES (CARRIED FORWARD)

These are from the 10/10 patch evaluation. They apply regardless of framework:

1. **ScrapeWebsiteTool blast radius:** Dedup key must be (tool_name, crew_name), not crew_name alone
2. **CR01/BR01 evidence scoping:** Filter evidence to crew's directory prefix
3. **control_coverage_pct:** Count filtered_by edges in the denominator
4. **CR05 file paths in evidence:** Add crew source_file and agent source_files
5. **CR06 code remediation:** Add framework-specific code fix (Agent() with tools modification)
6. **Duplicate blast radius dedup:** Same as fix 1
7. **Per-crew risk scores:** Attribute findings by directory path, not crew name string matching
8. **risk_score_breakdown:** Populate the dict showing score composition

These are Sprint 1 work — they fix the existing CrewAI parser before adding new parsers.

---

## VALIDATION TARGETS

### Sprint 1 (framework breadth):

```python
# LangGraph: test on langgraph/examples or a real LangGraph repo
assert len(result["crew_definitions"]) > 0, "No graphs detected"
assert any(c["framework"] == "LangGraph" for c in result["crew_definitions"])
assert result["framework_parse_quality"] == "full"
assert len(result["top_paths"]) >= 8, "Less than 8 findings on LangGraph project"
assert any(br["agent_count"] >= 2 for br in result["blast_radii"]), "No blast radii"

# LangChain: test on a repo with AgentExecutor
assert len(result["crew_definitions"]) > 0, "No agents detected"
assert any(c["framework"] == "LangChain" for c in result["crew_definitions"])
assert result["framework_parse_quality"] in ("full", "partial")

# Connectable surfaces
assert len(result["llm_models"]) > 0, "No LLM models detected"
assert len(result["env_var_names"]) > 0, "No env vars detected"

# Scanner fixes
assert max(br["agent_count"] for br in result["blast_radii"]) == 4  # ScrapeWebsiteTool
assert result["graph"]["risk_surface"]["control_coverage_pct"] > 0
```

### Sprint 2 (terminal + telemetry):

```
1. pip install stratum-cli && stratum scan . works
2. Terminal shows risk bar + action groups + flow maps
3. --quiet output is under 10 lines
4. --verbose shows full finding details
5. --badge generates valid SVG
6. Usage ping sends on first scan (after opt-in)
7. Usage ping includes project_hash, parse_quality, scan_source
```

### Sprint 3 (Action + upload):

```
1. GitHub Action runs on a test repo
2. PR comment appears with score and summary
3. Profile uploads to Supabase with org_id from GitHub context
4. Second repo in same org → 2 profiles under same org_id
5. Static report generated showing both repos
```

---

## BUILD ORDER FOR CLAUDE CODE

```
Session 1: "Refactor scanner.py to use a framework dispatcher.
   Extract CrewAI parsing into parsers/crewai_parser.py.
   Verify existing tests still pass with the refactored structure."

Session 2: "Implement parsers/langgraph_parser.py.
   Detect StateGraph, add_node, add_edge, compile.
   Convert to CrewDefinition + AgentDefinition + AgentRelationship.
   Test on a LangGraph project — verify crews, agents, relationships,
   blast_radii, and at least 8 findings fire."

Session 3: "Implement parsers/langchain_parser.py.
   Detect AgentExecutor, create_react_agent, create_openai_functions_agent.
   Convert to synthetic crews with tool-based relationships.
   Test on a LangChain ReAct project — verify agents and tools detected."

Session 4: "Add connectable surface detection: LLM models, env var names
   (with specificity classification), vector stores.
   Add project identity fields (git context detection).
   Add framework_parse_quality and project_hash to profile.
   Apply all scanner bug fixes (blast radius dedup, evidence scoping,
   control_coverage, CR06 code remediation)."

Session 5: "Terminal redesign. Create action_groups.py, risk_bar.py,
   flow_map.py, code_block.py. Rewrite terminal.py. Add verbose.py,
   quiet.py. Add --verbose, --quiet, --badge flags.
   Visual test on crewAI-examples AND a LangGraph project."

Session 6: "Package for PyPI. pyproject.toml, entry point, README.
   Add usage telemetry with opt-in consent.
   Test: pip install -e . && stratum scan . works end-to-end."

Session 7: "Build GitHub Action. YAML, scan + comment + upload.
   Set up Supabase table for profile storage.
   Test: Action runs on a test repo, profile appears in Supabase."
```
