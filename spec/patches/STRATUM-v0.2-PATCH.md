# STRATUM CLI v0.2 — Comprehensive Patch

## WHAT THIS PATCH DOES

Takes the scanner from "compounding findings exist but have credibility issues" to "every finding is defensible, the output is shareable, and the telemetry funds the enterprise product."

## WHY THIS PATCH EXISTS

The v0.1 graph patch introduced crews, agent chains, blast radii, and compounding findings. Good. But testing against crewAI-examples revealed:

1. **Blast radius is computed globally, not per-crew.** CR05 claims SerperDevTool feeds 9 agents — but those 9 agents span 5 independent crews that never co-execute. Real blast radius within any single crew is 2-4 agents. A developer who knows their codebase will immediately discount the tool.

2. **shares_tool edges are 77% cross-crew noise.** 60 of 78 shares_tool edges connect agents in different crews. Lead Market Analyst (MarketingPostsCrew) "shares" with Email Filter Agent (EmailFilterCrew). They happen to both use SerperDevTool. That's like saying two microservices are coupled because they both use PostgreSQL.

3. **Incident match_reason cites wrong paths.** EchoLeak's reason says "reads data via FileReadTool and sends it externally via SerperDevTool." EchoLeak is about Gmail read → email exfiltration. The match should cite the Gmail inbox → GmailGetThread → GmailToolkit → Gmail outbound path.

4. **STRATUM-002 still uses LangGraph remediation for CrewAI code.** `graph.compile(interrupt_before=[...])` on a CrewAI project. Flagged in two evaluations, still not fixed.

5. **CR06 bypass finding mixes evidence from unrelated crews.** The MatchToProposalCrew bypass is real, but the evidence also cites EmailFilterCrew for no reason.

6. **Risk score 98/100 for an example monorepo is not calibrated.** The base severity math exceeds 140 before capping. The score doesn't account for crew independence or monorepo structure.

7. **No flow map.** The graph has 148 edges and 89 nodes and the developer never sees them. No ASCII visualization. No screenshot moment.

8. **Telemetry is 13 fields.** The 20/10 enterprise dataset needs 30+.

9. **0 guardrail→capability edges in the graph** despite some guardrails having `covers_tools` populated.

10. **feeds_into has cross-project edges.** "Job Candidate Researcher → Book Outlining Agent" connects RecruitmentCrew to write_a_book_with_flows because agent name collision.

---

## HOW TO USE THIS PATCH

Add as `CLAUDE.md` alongside the existing codebase. Where this conflicts with existing code, this patch wins.

```
Message 1: "Patch Phase 1: Fix graph construction.
            - Scope shares_tool to same-crew only (remove cross-crew edges)
            - Scope blast_radii to per-crew (not global)  
            - Add guardrail→capability edges from covers_tools data
            - Fix feeds_into cross-project collisions (scope by source_file directory)
            - Recompute risk_surface with corrected graph
            Follow the spec exactly."

Message 2: "Patch Phase 2: Fix findings.
            - CR05: per-crew blast radius, one finding per crew with fan-out ≥ 3
            - CR06: evidence scoped to single crew per finding
            - CR01: scoped to same-crew shared tools only
            - STRATUM-002: framework-aware remediation (CrewAI → human_input=True)
            - All findings: graph_paths field populated with TracedPath objects
            Follow the spec exactly."

Message 3: "Patch Phase 3: Fix incident matching.
            - EchoLeak match_reason must cite Gmail path, not FileReadTool
            - Each incident gets distinct match_reason derived from the best-matching traced path
            - Confidence adjusted based on path specificity
            Follow the spec exactly."

Message 4: "Patch Phase 4: Flow map + terminal output.
            - Create flow_map.py renderer
            - Render per-crew flow diagrams in terminal
            - Add blast radius callouts
            - Add inline incident match_reason under findings
            Follow the spec exactly."

Message 5: "Patch Phase 5: Telemetry + score calibration + badge.
            - Full 20/10 telemetry schema
            - Risk score calibration (monorepo-aware, per-crew breakdown)
            - SVG badge generator
            Follow the spec exactly."

Message 6: "Patch Phase 6: Integration + validation.
            - Wire everything in scanner.py
            - Run against test_project/ and crewAI-examples
            - Verify all validation targets
            Follow the spec exactly."
```

---

## PHASE 1: FIX GRAPH CONSTRUCTION

### 1A. Scope shares_tool to same-crew only

**Current behavior:** Every pair of agents that use the same tool gets a shares_tool edge, regardless of crew membership. Result: 78 edges, 60 cross-crew.

**New behavior:** shares_tool edges ONLY between agents in the SAME crew who share a tool.

```python
# In graph/builder.py — replace the shares_tool edge construction

def _build_shares_tool_edges(agents, crews, nodes) -> list[GraphEdge]:
    """
    For each crew, find agents that share a tool.
    Only emit edges within the same crew.
    """
    edges = []
    for crew in crews:
        crew_agent_names = set(crew.agent_names)
        # Collect tools per agent within this crew
        crew_agent_tools = {}
        for agent_def in agents:
            if agent_def.name in crew_agent_names and agent_def.tool_names:
                crew_agent_tools[agent_def.name] = set(agent_def.tool_names)
        
        # Find shared tools within this crew
        agent_names = list(crew_agent_tools.keys())
        for i in range(len(agent_names)):
            for j in range(i + 1, len(agent_names)):
                shared = crew_agent_tools[agent_names[i]] & crew_agent_tools[agent_names[j]]
                for tool in shared:
                    edges.append(GraphEdge(
                        source=f"agent_{agent_names[i]}",
                        target=f"agent_{agent_names[j]}",
                        edge_type="shares_tool",
                        has_control=False,
                        data_sensitivity=_infer_tool_sensitivity(tool),
                        metadata={"shared_tool": tool, "crew": crew.name}
                    ))
    return edges
```

**Expected result on crewAI-examples:** ~18 same-crew edges (down from 78). Each edge has a `crew` field so findings can cite it.

### 1B. Scope blast_radii to per-crew

**Current behavior:** Finds all agents globally that use a tool, reports one blast radius per tool.

**New behavior:** Computes blast radius per (tool, crew) pair. SerperDevTool in RecruitmentCrew (3 agents) is a separate blast radius from SerperDevTool in SurpriseTravelCrew (3 agents).

```python
# In graph/pathfinder.py — replace find_blast_radii

def find_blast_radii(graph, agents, crews) -> list[BlastRadius]:
    """
    For each (tool, crew) pair where the tool is shared by 2+ agents,
    compute the blast radius within that crew.
    """
    results = []
    for crew in crews:
        crew_agent_names = set(crew.agent_names)
        crew_agent_tools = {}
        for agent_def in agents:
            if agent_def.name in crew_agent_names and agent_def.tool_names:
                crew_agent_tools[agent_def.name] = agent_def.tool_names
        
        # Find tools shared by 2+ agents in this crew
        tool_agents = {}  # tool_name -> [agent_names]
        for agent_name, tools in crew_agent_tools.items():
            for tool in tools:
                if tool not in tool_agents:
                    tool_agents[tool] = []
                tool_agents[tool].append(agent_name)
        
        for tool, sharing_agents in tool_agents.items():
            if len(sharing_agents) < 2:
                continue
            
            # Find downstream externals reachable from these agents
            downstream_externals = _find_downstream_externals(
                graph, sharing_agents
            )
            
            agent_labels = [_get_agent_label(graph, a) for a in sharing_agents]
            external_labels = [_get_node_label(graph, e) for e in downstream_externals]
            
            results.append(BlastRadius(
                source_node_id=f"cap_{tool}",
                source_label=tool,
                affected_agent_ids=sharing_agents,
                affected_agent_labels=agent_labels,
                downstream_external_ids=downstream_externals,
                downstream_external_labels=external_labels,
                agent_count=len(sharing_agents),
                external_count=len(downstream_externals),
                crew_name=crew.name,       # NEW FIELD
                crew_id=crew.name,         # NEW FIELD
            ))
    
    return results
```

**Add to BlastRadius dataclass:**
```python
@dataclass
class BlastRadius:
    # ... existing fields ...
    crew_name: str = ""     # Which crew this blast radius is within
    crew_id: str = ""
```

**Expected result on crewAI-examples:**

| Tool | Crew | Agents | Correct? |
|---|---|---|---|
| ScrapeWebsiteTool | StockAnalysisCrew | 4 (financial, research, financial_analyst, investment_advisor) | ✓ Demo moment |
| WebsiteSearchTool | StockAnalysisCrew | 3 | ✓ |
| SEC10QTool | StockAnalysisCrew | 3 | ✓ |
| SerperDevTool | RecruitmentCrew | 3 | ✓ |
| SerperDevTool | SurpriseTravelCrew | 3 | ✓ |
| SerperDevTool | MarketingPostsCrew | 2 | ✓ |
| GmailGetThread | EmailFilterCrew | 2 | ✓ |

No more "SerperDevTool → 9 agents" across 5 crews.

### 1C. Add guardrail→capability edges

**Current state:** Some guardrails have `covers_tools` populated (landing_page_generator covers FileManagementToolkit, nvidia marketing covers SerperDevTool+ScrapeWebsiteTool). But 0 gated_by/filtered_by edges exist in the graph.

**Fix:** After building capability and guardrail nodes, iterate guardrails with non-empty `covers_tools` and create edges.

```python
def _build_guardrail_edges(guardrails, capabilities, graph_nodes) -> list[GraphEdge]:
    edges = []
    for guard in guardrails:
        if not guard.covers_tools:
            continue
        
        guard_node_id = f"guard_{guard.kind}_{guard.line_number}"
        
        # Deduplicate covers_tools
        covered = set(guard.covers_tools)
        
        for tool_name in covered:
            # Find the capability node(s) for this tool
            for cap in capabilities:
                if cap.function_name.strip("[]") == tool_name or cap.function_name == tool_name:
                    # Determine edge type based on guardrail kind
                    if guard.kind == "hitl":
                        edge_type = "gated_by"
                    else:
                        edge_type = "filtered_by"
                    
                    cap_node_id = f"cap_{tool_name}_{cap.kind}"
                    edges.append(GraphEdge(
                        source=cap_node_id,
                        target=guard_node_id,
                        edge_type=edge_type,
                        has_control=True,
                        data_sensitivity=cap.trust_level
                    ))
    
    return edges
```

**Also:** For any edge that flows FROM a capability that has a guardrail covering it, set `has_control=True` on that downstream edge. This will make `control_coverage_pct` non-zero where guardrails actually exist.

### 1D. Fix feeds_into cross-project collisions

**Problem:** "Job Candidate Researcher → Book Outlining Agent" — agents from different projects matched by name.

**Fix:** Scope feeds_into edges by directory prefix. Two agents can only have a feeds_into edge if they belong to the same crew AND the crew's `source_file` shares a directory root with both agents.

```python
def _build_feeds_into_edges(crews, agent_defs) -> list[GraphEdge]:
    edges = []
    for crew in crews:
        crew_dir = _get_directory_prefix(crew.source_file)
        
        # Only include agents whose source_file shares the crew's directory
        valid_agents = []
        for agent_name in crew.agent_names:
            agent_def = _find_agent_def(agent_defs, agent_name)
            if agent_def is None:
                continue
            agent_dir = _get_directory_prefix(agent_def.source_file)
            # Agent must be in the same project directory as the crew
            if _shares_project_root(crew_dir, agent_dir):
                valid_agents.append(agent_name)
        
        # Build sequential chain from valid agents only
        if crew.process_type == "sequential":
            for i in range(len(valid_agents) - 1):
                edges.append(GraphEdge(
                    source=f"agent_{valid_agents[i]}",
                    target=f"agent_{valid_agents[i+1]}",
                    edge_type="feeds_into",
                    has_control=False,
                    metadata={"crew": crew.name}
                ))
    
    return edges

def _shares_project_root(dir_a: str, dir_b: str) -> bool:
    """
    Two paths share a project root if their first two directory components match.
    crews/stock_analysis/... and crews/stock_analysis/... → True
    crews/recruitment/... and flows/write_a_book_with_flows/... → False
    """
    parts_a = Path(dir_a).parts[:2]
    parts_b = Path(dir_b).parts[:2]
    return parts_a == parts_b
```

**Expected result:** "Job Candidate Researcher → Book Outlining Agent" and "Job Candidate Researcher → Chapter Writer" disappear. All feeds_into edges are within-project.

### 1E. Recompute risk_surface with corrected graph

After applying 1A-1D, recompute:

```python
risk_surface = {
    "total_nodes": len(graph.nodes),
    "total_edges": len(graph.edges),         # Will be ~80 (down from 148)
    "uncontrolled_path_count": len(uncontrolled_paths),
    "max_path_hops": max(len(p.node_ids) for p in uncontrolled_paths) if uncontrolled_paths else 0,
    "sensitive_data_types": list(set(...)),
    "external_sink_count": ...,
    "control_coverage_pct": controlled_edges / controllable_edges,  # Now >0 where guardrails exist
    "trust_boundary_crossings": ...,
    "downward_crossings": ...,
    "max_fan_out_per_crew": max(br.agent_count for br in blast_radii) if blast_radii else 0,  # NEW
    "max_chain_depth": max_chain_depth,                                                         # NEW
    "edge_density": len(graph.edges) / (n * (n-1)) if n > 1 else 0,                           # NEW
    "crew_count": len(crews),                                                                   # NEW
}
```

---

## PHASE 2: FIX FINDINGS

### 2A. STRATUM-CR05 — Per-crew blast radius findings

**Current:** One finding with "SerperDevTool → 9 agents" across 5 crews.

**New:** One finding PER (tool, crew) pair where agent_count ≥ 3. Each finding is precise about which crew, which agents, and which downstream externals.

```python
def generate_blast_radius_findings(blast_radii, detected_frameworks) -> list[Finding]:
    findings = []
    
    # Only generate findings for blast radii with 3+ agents
    significant = [br for br in blast_radii if br.agent_count >= 3]
    
    # Sort by agent_count descending — most impactful first
    significant.sort(key=lambda br: -br.agent_count)
    
    for i, br in enumerate(significant):
        severity = "CRITICAL" if br.agent_count >= 4 else "HIGH"
        
        # Build the fan-out path display
        path_lines = [f"{br.source_label} (shared tool in {br.crew_name})"]
        for agent_label in br.affected_agent_labels:
            externals = _get_agent_externals(br, agent_label)
            ext_str = f" → [{', '.join(externals)}]" if externals else ""
            path_lines.append(f"  ├──▶ {agent_label}{ext_str}")
        # Fix last line to use └
        if path_lines:
            path_lines[-1] = path_lines[-1].replace("├", "└", 1)
        
        finding = Finding(
            id=f"STRATUM-CR05{'.' + str(i+1) if i > 0 else ''}",
            severity=severity,
            confidence="confirmed",
            category="compounding",
            title=f"Shared tool blast radius: {br.source_label} → {br.agent_count} agents in {br.crew_name}",
            path="\n".join(path_lines),
            description=(
                f"{br.source_label} feeds {br.agent_count} agents in crew '{br.crew_name}' — "
                f"blast radius: {br.external_count} external services. "
                f"If {br.source_label} returns poisoned data (prompt injection in scraped content), "
                f"{br.agent_count} agents are compromised simultaneously within the same execution context. "
                f"Each has independent downstream actions, so a single point of compromise fans out to "
                f"{br.external_count} external services."
            ),
            evidence=[
                f"Crew: {br.crew_name}",
                f"Shared by: {', '.join(br.affected_agent_labels)}",
                f"Downstream: {', '.join(br.downstream_external_labels)}"
            ],
            scenario=(
                f"A single poisoned input to {br.source_label} would compromise your "
                f"{br.crew_name} pipeline: {', '.join(br.affected_agent_labels[:3])}"
                f"{'...' if len(br.affected_agent_labels) > 3 else ''}."
            ),
            business_context=(
                "This finding exists because the graph traced fan-out from one shared tool "
                "within a single execution context. No checklist produces it."
            ),
            remediation=_get_blast_radius_remediation(br, detected_frameworks),
            owasp_id="ASI01",
            owasp_name="Agent Goal Hijacking",
            finding_class="compounding"
        )
        findings.append(finding)
    
    return findings
```

**Expected findings on crewAI-examples:**

```
STRATUM-CR05   | CRITICAL | Shared tool blast radius: ScrapeWebsiteTool → 4 agents in StockAnalysisCrew
STRATUM-CR05.1 | HIGH     | Shared tool blast radius: SerperDevTool → 3 agents in RecruitmentCrew
STRATUM-CR05.2 | HIGH     | Shared tool blast radius: SerperDevTool → 3 agents in SurpriseTravelCrew
```

**The StockAnalysisCrew finding is the demo moment:**

```
🔴 STRATUM-CR05 | CRITICAL | Shared tool blast radius

ScrapeWebsiteTool → 4 agents in StockAnalysisCrew

  ScrapeWebsiteTool (shared tool in StockAnalysisCrew)
  ├──▶ Financial Agent → [Web search, HTTP endpoint]
  ├──▶ Research Analyst Agent → [Web scraper, SEC filing]
  ├──▶ Financial Analyst Agent → [Web search, HTTP endpoint]
  └──▶ Investment Advisor Agent → [Web search]

If ScrapeWebsiteTool returns poisoned data, 4 agents in the same execution
context are compromised simultaneously. A single poisoned webpage would
compromise your entire stock analysis pipeline.

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

Every claim in that finding is verifiable by looking at the code. That's credibility.

### 2B. STRATUM-CR06 — Single-crew evidence

**Current:** Evidence cites both MatchToProposalCrew and EmailFilterCrew in the same finding.

**Fix:** Generate one bypass finding per crew where a bypass is detected. Each finding cites only its own crew.

```python
def generate_bypass_findings(graph, crews, agents) -> list[Finding]:
    findings = []
    
    for crew in crews:
        if crew.process_type != "sequential" or len(crew.agent_names) < 2:
            continue
        
        bypasses = _detect_bypasses_in_crew(graph, crew, agents)
        
        for bypass in bypasses:
            findings.append(Finding(
                id="STRATUM-CR06",
                severity="HIGH",
                confidence="probable",
                category="compounding",
                title=f"'{bypass.downstream_agent}' bypasses '{bypass.upstream_agent}' — reads {bypass.shared_source} directly",
                evidence=[
                    f"Crew: {crew.name}",
                    f"Shared source: {bypass.shared_source}",
                    f"Upstream (intended filter): {bypass.upstream_agent}",
                    f"Downstream (direct access): {bypass.downstream_agent}"
                ],
                # ... rest of finding
            ))
    
    return findings
```

### 2C. STRATUM-CR01 — Same-crew scoping

**Current:** "Matcher → [SerperDevTool] → Lead Market Analyst" — these are in different crews.

**Fix:** Only emit CR01 when the two agents sharing a tool are in the same crew AND one processes untrusted input while the other performs external actions.

```python
def generate_shared_tool_bridge_findings(graph, crews, agents, blast_radii) -> list[Finding]:
    """
    CR01: Shared tool bridges untrusted input to external action.
    Only fires when both agents are in the same crew.
    """
    findings = []
    
    for br in blast_radii:
        # Already scoped to per-crew by Phase 1B
        crew_name = br.crew_name
        
        # Check if any agent in the blast radius processes untrusted input
        # AND another agent in the blast radius performs external actions
        untrusted_agents = [a for a in br.affected_agent_ids 
                          if _has_untrusted_input(graph, a)]
        external_agents = [a for a in br.affected_agent_ids 
                         if _has_external_action(graph, a)]
        
        if untrusted_agents and external_agents and set(untrusted_agents) != set(external_agents):
            # There's a bridge: one agent ingests untrusted data, shares tool with
            # another agent that has external action capability
            findings.append(Finding(
                id="STRATUM-CR01",
                category="compounding",
                evidence=[f"Crew: {crew_name}", ...],
                # ...
            ))
    
    return findings
```

### 2D. STRATUM-002 — Framework-aware remediation

**Current:** Always emits `graph.compile(interrupt_before=[...])` regardless of framework.

**Fix:**

```python
def _get_remediation(finding_id: str, detected_frameworks: list[str], 
                     source_file: str = "") -> str:
    """
    Return framework-appropriate remediation.
    If source_file is in a CrewAI crew → CrewAI syntax.
    If source_file is in a LangGraph graph → LangGraph syntax.
    If ambiguous → show both.
    """
    # Determine framework from source file context
    framework = _detect_framework_for_file(source_file, detected_frameworks)
    
    remediations = {
        "STRATUM-002": {
            "CrewAI": (
                "Fix (CrewAI):\n"
                "  task = Task(\n"
                "      description=\"...\",\n"
                "+     human_input=True   # approve before destructive action\n"
                "  )"
            ),
            "LangGraph": (
                "Fix (LangGraph):\n"
                "  graph = workflow.compile(\n"
                "+     interrupt_before=[\"file_management\"]\n"
                "  )"
            ),
        },
        # ... other findings
    }
    
    if framework in remediations.get(finding_id, {}):
        return remediations[finding_id][framework]
    
    # If both frameworks detected, show both
    both = remediations.get(finding_id, {})
    if len(both) > 1:
        return "\n\n".join(f"{fw}:\n{code}" for fw, code in both.items())
    
    return list(both.values())[0] if both else ""
```

**STRATUM-002's source_file is `crews\\landing_page_generator\\...\\crew.py`** which is CrewAI. Result: `human_input=True`.

### 2E. graph_paths field on all findings

Every finding should have a `graph_paths` field populated with the actual traced paths that generated it. Currently they're all empty arrays.

```python
# In the finding generation, always populate graph_paths
finding.graph_paths = [
    {
        "node_ids": path.node_ids,
        "node_labels": path.node_labels,
        "edge_types": path.edge_types,
        "data_sensitivity": path.data_sensitivity,
        "has_any_control": path.has_any_control
    }
    for path in relevant_paths
]
```

This is critical for:
1. **Terminal output** — render the path inline under the finding
2. **JSON output** — consumers can trace exactly which graph walk produced the finding
3. **Telemetry** — anonymized path shapes feed the risk map

---

## PHASE 3: FIX INCIDENT MATCHING

### 3A. Path-specific match_reason

**Current:** EchoLeak and Slack AI Exfil both say "reads data via FileReadTool and sends it externally via SerperDevTool." Generic, wrong, and identical for two different incidents.

**New:** Each incident has a `pattern_signature` that describes what graph paths it matches. The match_reason is generated by finding the best-matching traced path.

```python
INCIDENT_MATCH_PATTERNS = {
    "ECHOLEAK-2025": {
        "required_sources": ["gmail", "email", "inbox"],
        "required_sinks": ["gmail", "email", "slack", "outbound"],
        "pattern": "sensitive_inbox_read → outbound_send",
        "reason_template": (
            "Your {crew_name} reads email content via {source_tool} and routes it "
            "to {sink_count} outbound services ({sink_names}) with no filter — "
            "the same data→external pattern that enabled EchoLeak. In that incident, "
            "zero-click prompt injection via email extracted data from "
            "OneDrive/SharePoint/Teams and exfiltrated it through trusted Microsoft domains."
        )
    },
    "SLACK-AI-EXFIL-2024": {
        "required_sources": ["slack", "messaging", "chat"],
        "required_sinks": ["url", "http", "link", "outbound"],
        "pattern": "messaging_read → url_exfil",
        "reason_template": (
            "Your agents process messaging content and have outbound HTTP capabilities "
            "via {sink_names}. Hidden instructions in messages could cause data exfiltration "
            "via crafted links — the same pattern behind the Slack AI data exfiltration, "
            "where private channel data was leaked through malicious link insertion."
        )
    },
    "DOCKER-GORDON-2025": {
        "required_sources": ["scrape", "web", "http", "url", "fetch"],
        "required_sinks": ["http", "requests", "outbound"],
        "pattern": "external_content_fetch → tool_execution",
        "reason_template": (
            "Your {crew_name} processes external web content via {source_tool} and "
            "distributes it to {agent_count} agents with no content validation — "
            "the same untrusted-input→tool-execution pattern that enabled the Docker "
            "Ask Gordon exploit, where poisoned repository metadata triggered tools "
            "to fetch payloads from attacker-controlled servers."
        )
    },
    "SERVICENOW-NOWASSIST-2025": {
        "required_sources": [],  # Any multi-agent delegation
        "required_sinks": ["outbound", "external"],
        "pattern": "cross_agent_delegation → privilege_escalation",
        "reason_template": (
            "Your {crew_name} has {chain_length}-agent delegation chains where "
            "agent outputs feed directly into subsequent agents. In the ServiceNow "
            "Now Assist incident, a low-privilege agent manipulated a high-privilege "
            "agent into exporting case files to an external URL via second-order "
            "prompt injection."
        )
    }
}

def generate_match_reason(incident_id: str, traced_paths: list, crews: list, 
                          blast_radii: list, agents: list) -> tuple[str, float]:
    """
    Find the best matching traced path for this incident and generate a specific reason.
    Returns (match_reason, adjusted_confidence).
    """
    pattern = INCIDENT_MATCH_PATTERNS.get(incident_id)
    if not pattern:
        return ("", 0.0)
    
    best_path = None
    best_score = 0
    
    for path in traced_paths:
        score = _score_path_against_pattern(path, pattern)
        if score > best_score:
            best_score = score
            best_path = path
    
    if best_path is None or best_score == 0:
        # No matching path — check blast radii and agent chains for non-path patterns
        if incident_id == "SERVICENOW-NOWASSIST-2025":
            # Match on agent chain length
            longest_chain = max(
                (len(c.agent_names) for c in crews), default=0
            )
            if longest_chain >= 3:
                crew = max(crews, key=lambda c: len(c.agent_names))
                return (
                    pattern["reason_template"].format(
                        crew_name=crew.name,
                        chain_length=len(crew.agent_names)
                    ),
                    0.5
                )
        return ("", 0.0)
    
    # Populate template with specifics from the path
    source_tool = best_path.node_labels[0] if best_path.node_labels else "unknown"
    sink_labels = [l for l in best_path.node_labels if _is_external(l)]
    
    # Find which crew this path belongs to
    crew_name = _find_crew_for_path(best_path, crews, agents)
    
    reason = pattern["reason_template"].format(
        crew_name=crew_name or "your agent system",
        source_tool=source_tool,
        sink_count=len(sink_labels),
        sink_names=", ".join(sink_labels),
        agent_count=len(blast_radii[0].affected_agent_labels) if blast_radii else "multiple",
        chain_length=len(best_path.node_ids)
    )
    
    # Adjust confidence based on match quality
    confidence = min(1.0, best_score / 3.0)  # Normalize 0-3 score to 0-1
    
    return (reason, confidence)


def _score_path_against_pattern(path, pattern) -> int:
    """Score how well a traced path matches an incident pattern."""
    score = 0
    path_text = " ".join(path.node_labels).lower()
    
    # Check required sources
    for source_keyword in pattern["required_sources"]:
        if source_keyword in path_text:
            score += 1
            break
    
    # Check required sinks
    for sink_keyword in pattern["required_sinks"]:
        if sink_keyword in path_text:
            score += 1
            break
    
    # Bonus for matching data sensitivity
    if path.data_sensitivity == "personal":
        score += 1
    
    return score
```

**Expected results on crewAI-examples:**

| Incident | Match_Reason Should Cite | Confidence |
|---|---|---|
| ECHOLEAK-2025 | Gmail inbox → GmailGetThread → GmailToolkit → Gmail outbound in EmailFilterCrew | 1.0 |
| SLACK-AI-EXFIL-2024 | Slack SDK outbound in meeting_assistant_flow (if no messaging source found, downgrade confidence) | 0.5 |
| DOCKER-GORDON-2025 | ScrapeWebsiteTool → 4 agents in StockAnalysisCrew | 0.75 |
| SERVICENOW-NOWASSIST-2025 | 4-agent chain in StockAnalysisCrew | 0.5 |

**Key principle:** If the best-matching path doesn't contain the incident's required source/sink keywords, the confidence drops. No more 1.0 confidence on Slack AI Exfil when the codebase has no Slack data sources (only a Slack outbound sender in meeting_assistant_flow).

---

## PHASE 4: FLOW MAP + TERMINAL OUTPUT

### 4A. `output/flow_map.py` — Per-Crew ASCII Topology

**The core viral artifact.** One flow diagram per crew that has findings, rendered in the terminal using Rich.

```python
def render_crew_flow_maps(
    crews: list,
    graph,
    findings: list,
    blast_radii: list,
    max_width: int = 90
) -> list[str]:
    """
    Render one flow map per crew that has at least one finding.
    Returns list of Rich-formatted strings.
    """
    maps = []
    
    # Only render maps for crews that have findings
    finding_crews = _get_crews_with_findings(crews, findings, blast_radii)
    
    for crew in finding_crews:
        map_str = _render_single_crew_map(crew, graph, findings, blast_radii, max_width)
        if map_str:
            maps.append(map_str)
    
    return maps


def _render_single_crew_map(crew, graph, findings, blast_radii, max_width) -> str:
    """
    Render a single crew's data flow map.
    
    Layout:
    ╭──── CrewName ─────────────────────────────────────────────╮
    │                                                           │
    │  [data source] ──▶ Agent 1 ──▶ Agent 2 ──▶ Agent 3       │
    │                     │           │           │             │
    │                     ▼           ▼           ▼             │
    │               [ext service] [ext service] [ext service]   │
    │                ⚠ no gate     ⚠ no gate                   │
    │                                                           │
    │  ⚠ 2 uncontrolled paths · 0% coverage · 3-agent chain   │
    ╰───────────────────────────────────────────────────────────╯
    """
    lines = []
    
    # Header
    header = f" {crew.name} "
    border_len = max(max_width - 2, len(header) + 4)
    lines.append(f"╭{'─' * ((border_len - len(header)) // 2)}{header}{'─' * ((border_len - len(header) + 1) // 2)}╮")
    lines.append(f"│{' ' * border_len}│")
    
    # Get crew's agents in order
    crew_agents = crew.agent_names
    
    # Find data sources that feed into this crew's agents
    data_sources = _get_crew_data_sources(crew, graph)
    
    # Find external sinks reachable from this crew's agents
    external_sinks = _get_crew_external_sinks(crew, graph)
    
    # Render agent chain
    agent_labels = [_get_agent_label(graph, a) for a in crew_agents]
    chain_str = " ──▶ ".join(agent_labels)
    
    # Add data sources
    for ds in data_sources:
        sensitivity = ds.get("sensitivity", "")
        sens_str = f" ({sensitivity})" if sensitivity and sensitivity != "unknown" else ""
        lines.append(f"│  {ds['label']}{sens_str}")
        lines.append(f"│    └──▶ {chain_str}")
    
    if not data_sources:
        lines.append(f"│  {chain_str}")
    
    # Add external sinks with control markers
    for sink in external_sinks:
        control_marker = "✓ gated" if sink.get("has_control") else "⚠ no gate"
        agent_source = sink.get("via_agent", "")
        lines.append(f"│    {'    ' * _agent_index(crew_agents, agent_source)}└──▶ {sink['label']}  {control_marker}")
    
    # Blast radius callout
    crew_brs = [br for br in blast_radii if br.crew_name == crew.name and br.agent_count >= 3]
    for br in crew_brs:
        lines.append(f"│  🔴 BLAST RADIUS: {br.source_label} → {br.agent_count} agents → {br.external_count} external services")
    
    # Summary line
    crew_findings = [f for f in findings if crew.name in str(f.evidence)]
    uncontrolled = sum(1 for f in crew_findings if f.category == "security")
    coverage = _get_crew_control_coverage(crew, graph)
    lines.append(f"│{' ' * border_len}│")
    lines.append(f"│  ⚠ {len(crew_findings)} findings · {coverage:.0%} control coverage · {len(crew_agents)}-agent {crew.process_type} chain")
    
    # Footer
    lines.append(f"│{' ' * border_len}│")
    lines.append(f"╰{'─' * border_len}╯")
    
    return "\n".join(lines)
```

**Target output for StockAnalysisCrew:**

```
╭────────────── StockAnalysisCrew ──────────────────────────────────────╮
│                                                                       │
│  Web (external input)                                                 │
│    └──▶ Financial Agent ──▶ Research Analyst ──▶ Financial Analyst ──▶ Investment Advisor
│           ├──▶ HTTP endpoint  ⚠ no gate                              │
│           └──▶ Web search  ⚠ no gate                                 │
│                                                                       │
│  🔴 BLAST RADIUS: ScrapeWebsiteTool → 4 agents → 2 external services │
│                                                                       │
│  ⚠ 3 findings · 0% control coverage · 4-agent sequential chain       │
╰───────────────────────────────────────────────────────────────────────╯
```

**Target output for EmailFilterCrew:**

```
╭────────────── EmailFilterCrew ────────────────────────────────────────╮
│                                                                       │
│  Gmail inbox (personal)                                               │
│    └──▶ Email Filter Agent ──▶ Email Action Agent ──▶ Email Response Writer
│                                  ├──▶ Gmail outbound  ⚠ no gate      │
│                                  └──▶ Tavily API  ⚠ no gate          │
│    └──▶ [BYPASS] Email Response Writer reads inbox directly           │
│                                                                       │
│  ⚠ 4 findings · 0% control coverage · 3-agent sequential chain       │
╰───────────────────────────────────────────────────────────────────────╯
```

### 4B. Terminal output section order

Update `output/terminal.py`:

```
1. HEADER — scan info, frameworks, file counts
2. FLOW MAPS — one per crew with findings (NEW)
3. CRITICAL FINDINGS — STRATUM-001, CR05
4. HIGH FINDINGS — STRATUM-002, BR01, CR01, CR06
5. MEDIUM FINDINGS — STRATUM-008, 009, 010, CR02
6. SIGNALS — CONTEXT-001, TELEMETRY-003, BR03, BR04, OP02
7. INCIDENT MATCHES — with inline match_reason (ENHANCED)
8. RISK SCORE — with per-crew breakdown (NEW)
9. QUICK FIXES — existing
```

### 4C. Inline incident match_reason under findings

When displaying a finding, if it matches an incident, show the match_reason inline:

```
STRATUM-001 | CRITICAL | Unguarded data-to-external path (2 paths)

  Gmail inbox → GmailGetThread → GmailToolkit → Gmail outbound  ⚠ no filter
  Gmail inbox → GmailGetThread → TavilySearchResults → Tavily API  ⚠ no filter

  Someone sends your agent a crafted email. The agent reads your Gmail inbox
  and forwards sensitive content via Gmail outbound — to an attacker-controlled
  address embedded in the injected instructions.

  📎 Matches: Microsoft Copilot EchoLeak (2025-Q1, $200M+ impact)
     Your EmailFilterCrew reads email content via GmailGetThread and routes it
     to 2 outbound services (Gmail outbound, Tavily API) with no filter — the
     same data→external pattern that enabled EchoLeak.

  Fix (CrewAI):
    task = Task(
        description="...",
  +     human_input=True   # review before external calls
    )
```

---

## PHASE 5: TELEMETRY + SCORE CALIBRATION + BADGE

### 5A. Full 20/10 Telemetry Schema

Replace the current 13-field profile:

```python
@dataclass
class TelemetryProfile:
    """v0.2 schema. All fields anonymized — no paths, no names, no code."""
    
    # Identity
    topology_signature: str = ""
    schema_version: str = "0.2"
    
    # Architecture
    archetype: str = ""
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
    max_fan_out: int = 0
    max_chain_depth: int = 0
    agent_to_agent_edges: int = 0
    external_sink_count: int = 0
    
    # Risk profile
    risk_score: int = 0
    risk_score_per_crew: dict = field(default_factory=dict)  # {"crew_hash_1": 45, "crew_hash_2": 72}
    findings_by_severity: dict = field(default_factory=dict)  # {"critical": 2, "high": 4, ...}
    findings_by_category: dict = field(default_factory=dict)  # {"security": 1, "compounding": 4, ...}
    finding_ids: list = field(default_factory=list)           # ["STRATUM-001", "STRATUM-CR05", ...]
    incident_match_count: int = 0
    incident_ids: list = field(default_factory=list)
    
    # Blast radius metrics
    blast_radius_count: int = 0
    max_blast_radius: int = 0
    blast_radius_distribution: dict = field(default_factory=dict)  # {"2": 3, "3": 2, "4": 1}
    control_bypass_count: int = 0
    
    # Control maturity
    guardrail_count: int = 0
    guardrail_kinds: dict = field(default_factory=dict)     # {"validation": 13, "hitl": 0, ...}
    guardrail_linked_count: int = 0                          # guardrails with non-empty covers_tools
    control_coverage_pct: float = 0.0
    has_checkpointing: bool = False
    checkpoint_type: str = "none"
    has_observability: bool = False
    has_hitl_anywhere: bool = False
    error_handling_ratio: float = 0.0                       # handled_calls / total_calls
    
    # Data sensitivity
    has_pii: bool = False
    has_financial: bool = False
    has_credentials: bool = False
    sensitive_data_types: list = field(default_factory=list)
    trust_boundary_crossings: int = 0
    downward_crossings: int = 0
    regulatory_surface: list = field(default_factory=list)  # ["GDPR", "EU_AI_ACT", "NIST_AI_RMF"]
```

**Population:**

```python
def build_telemetry_profile(scan_result, graph, crews, blast_radii, findings) -> TelemetryProfile:
    p = TelemetryProfile()
    
    # Architecture
    p.agent_count = len(scan_result.agent_definitions)
    p.crew_count = len(crews)
    p.unique_tool_count = len(set(
        t for a in scan_result.agent_definitions for t in a.get("tool_names", [])
    ))
    p.capability_fingerprint = {
        "outbound": scan_result.outbound_count,
        "data_access": scan_result.data_access_count,
        "code_exec": scan_result.code_exec_count,
        "destructive": scan_result.destructive_count,
        "financial": scan_result.financial_count
    }
    p.files_scanned = scan_result.files_scanned
    
    # Graph topology
    p.node_count = len(graph.nodes)
    p.edge_count = len(graph.edges)
    n = p.node_count
    p.edge_density = round(p.edge_count / (n * (n - 1)), 4) if n > 1 else 0
    
    feeds_into = [e for e in graph.edges if e["type"] == "feeds_into"]
    p.agent_to_agent_edges = len(feeds_into)
    p.max_chain_depth = _compute_max_chain_depth(feeds_into, graph.nodes)
    p.max_fan_out = max((br.agent_count for br in blast_radii), default=0)
    p.external_sink_count = sum(1 for n in graph.nodes if n["type"] == "external")
    
    # Risk profile
    p.risk_score = scan_result.risk_score
    p.risk_score_per_crew = _compute_per_crew_scores(crews, findings)  # Hashed crew names
    p.findings_by_severity = _count_by_field(findings, "severity")
    p.findings_by_category = _count_by_field(findings, "category")
    p.finding_ids = [f.id for f in findings]
    p.incident_match_count = len(scan_result.incident_matches)
    p.incident_ids = [m.incident_id for m in scan_result.incident_matches]
    
    # Blast radius
    p.blast_radius_count = len(blast_radii)
    p.max_blast_radius = max((br.agent_count for br in blast_radii), default=0)
    p.blast_radius_distribution = _distribution([br.agent_count for br in blast_radii])
    p.control_bypass_count = sum(1 for f in findings if f.id == "STRATUM-CR06")
    
    # Control maturity
    p.guardrail_count = scan_result.guardrail_count
    p.guardrail_kinds = _count_guardrails_by_kind(scan_result.guardrails)
    p.guardrail_linked_count = sum(1 for g in scan_result.guardrails if g.covers_tools)
    p.control_coverage_pct = graph.risk_surface.get("control_coverage_pct", 0.0)
    p.has_checkpointing = scan_result.checkpoint_type != "none"
    p.checkpoint_type = scan_result.checkpoint_type
    p.has_observability = not any(s.id == "TELEMETRY-003" for s in scan_result.signals)
    p.has_hitl_anywhere = any(g.kind == "hitl" for g in scan_result.guardrails)
    handled = sum(1 for c in scan_result.capabilities if c.has_error_handling)
    total = len(scan_result.capabilities)
    p.error_handling_ratio = round(handled / total, 2) if total > 0 else 0
    
    # Data sensitivity
    surface = graph.risk_surface
    p.has_pii = "personal" in surface.get("sensitive_data_types", [])
    p.has_financial = "financial" in surface.get("sensitive_data_types", [])
    p.has_credentials = "credentials" in surface.get("sensitive_data_types", [])
    p.sensitive_data_types = surface.get("sensitive_data_types", [])
    p.trust_boundary_crossings = surface.get("trust_boundary_crossings", 0)
    p.downward_crossings = surface.get("downward_crossings", 0)
    p.regulatory_surface = _simplify_regulatory(surface.get("regulatory_frameworks", []))
    
    return p


def _compute_per_crew_scores(crews, findings) -> dict:
    """
    Compute risk score per crew. Use hashed crew name for anonymity.
    """
    scores = {}
    for crew in crews:
        crew_findings = [f for f in findings if crew.name in str(f.evidence)]
        if not crew_findings:
            continue
        score = sum(
            25 if f.severity == "CRITICAL" else
            15 if f.severity == "HIGH" else
            8 if f.severity == "MEDIUM" else 3
            for f in crew_findings
        )
        crew_hash = hashlib.sha256(crew.name.encode()).hexdigest()[:8]
        scores[crew_hash] = min(score, 100)
    return scores
```

**What the enterprise product gets from this at N=1,000:**

- "Projects with edge_density > 0.03 have 3.2× more compounding findings"
- "The median max_blast_radius across all projects is 3. Your project's 4 puts you in the 82nd percentile"
- "89% of projects with has_hitl_anywhere=False and outbound > 10 have at least one CRITICAL finding"
- "Projects that add a single guardrail_linked reduce their risk_score by an average of 18 points"
- Risk score benchmarking by archetype and framework combination
- Blast radius distribution across the ecosystem: "Most common: 2-agent fan-out (43%), 3-agent (28%), 4+ agent (12%)"

### 5B. Risk Score Calibration

**Current:** Base severity math gives 142 (2×25 + 4×15 + 4×8), capped at 100. With bonuses, hits 98.

**Problem:** This monorepo has 29 crews. Most findings are concentrated in a few crews (EmailFilterCrew, StockAnalysisCrew). The score treats the repo as one project when it's actually 15+ independent projects.

**Fix 1: Add per-crew scores to the output.**

```
Risk Score: 73 (overall)

  EmailFilterCrew:      85/100  (3 findings: 1 CRITICAL, 1 HIGH, 1 MEDIUM)
  StockAnalysisCrew:    68/100  (2 findings: 1 CRITICAL, 1 MEDIUM)
  MatchToProposalCrew:  38/100  (1 finding: 1 HIGH)
  GameBuilderCrew:       8/100  (1 finding: 1 MEDIUM)
```

Per-crew scores are scoped: only findings that cite the crew's evidence contribute. This gives developers actionable prioritization.

**Fix 2: Attenuate the global score for monorepos.**

```python
def calculate_risk_score(findings, signals, capabilities, guardrails, crews) -> int:
    # Base: sum severity scores
    base = sum(
        25 if f.severity == "CRITICAL" else
        15 if f.severity == "HIGH" else
        8 if f.severity == "MEDIUM" else 3
        for f in findings
    )
    
    # Bonuses (existing)
    bonus = 0
    if not any(g.kind != "validation" for g in guardrails):
        bonus += 15  # zero real guardrails
    # ... other existing bonuses
    
    raw = base + bonus
    
    # Monorepo attenuation: if many independent crews, the risk is spread
    # across separate deployments, not concentrated in one
    if len(crews) > 5:
        # Diminishing returns: each additional crew reduces the compounding factor
        # but doesn't reduce below the max single-crew score
        per_crew_max = max(
            _crew_score(crew, findings) for crew in crews
        ) if crews else raw
        
        # Global score is the max crew score + a logarithmic bonus for additional risk surface
        additional_crews_with_findings = sum(
            1 for c in crews if _crew_score(c, findings) > 0
        ) - 1  # Subtract 1 for the max crew
        
        global_score = per_crew_max + int(5 * math.log1p(additional_crews_with_findings))
        raw = min(raw, global_score)
    
    return min(raw, 100)
```

**Expected result on crewAI-examples:** Score drops from 98 to ~73-80. Still alarming (EmailFilterCrew at 85 is bad) but not "everything is on fire" for what's actually a collection of toy examples.

### 5C. Badge Generator

```python
# badge/generator.py

def generate_badge_svg(risk_score: int, finding_count: int, 
                       critical_count: int = 0) -> str:
    """
    Generate shields.io-style SVG badge.
    
    Colors:
    - 0-30:   #4c1 (green)   — "low risk"
    - 31-60:  #dfb317 (yellow) — "moderate risk"  
    - 61-80:  #fe7d37 (orange) — "high risk"
    - 81-100: #e05d44 (red)   — "critical risk"
    """
    if risk_score <= 30:
        color = "#4c1"
        label = "low"
    elif risk_score <= 60:
        color = "#dfb317"
        label = "moderate"
    elif risk_score <= 80:
        color = "#fe7d37"
        label = "high"
    else:
        color = "#e05d44"
        label = "critical"
    
    right_text = f"risk: {risk_score}"
    if critical_count > 0:
        right_text += f" · {critical_count} critical"
    
    # Standard shields.io SVG template
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="180" height="20">
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="a"><rect width="180" height="20" rx="3"/></clipPath>
  <g clip-path="url(#a)">
    <path fill="#555" d="M0 0h65v20H0z"/>
    <path fill="{color}" d="M65 0h115v20H65z"/>
    <path fill="url(#b)" d="M0 0h180v20H0z"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="32" y="15" fill="#010101" fill-opacity=".3">stratum</text>
    <text x="32" y="14">stratum</text>
    <text x="122" y="15" fill="#010101" fill-opacity=".3">{right_text}</text>
    <text x="122" y="14">{right_text}</text>
  </g>
</svg>'''
    
    return svg
```

**CLI flag:**
```
stratum scan . --badge         # writes stratum-badge.svg to current directory
stratum scan . --badge=./docs  # writes to specified directory
```

**README usage:**
```markdown
![Stratum Risk Score](./stratum-badge.svg)
```

---

## PHASE 6: INTEGRATION + VALIDATION

### scanner.py Pipeline

```python
def scan(directory, options) -> ScanResult:
    # Phase 1: Detection (existing)
    capabilities = ...
    guardrails = ...
    agents = ...
    
    # Phase 2: Crew extraction (existing, from v0.1 patch)
    python_files = _collect_python_files(directory)
    yaml_files = _collect_yaml_files(directory)
    crews = extract_crews(python_files, yaml_files, agents)
    
    # Phase 3: Graph construction (FIXED)
    graph = build_graph(capabilities, agents, guardrails, mcp_servers, crews)
    #  - shares_tool scoped to same-crew (1A)
    #  - guardrail→capability edges from covers_tools (1C)
    #  - feeds_into scoped by directory (1D)
    
    # Phase 4: Path discovery (FIXED)
    uncontrolled_paths = find_uncontrolled_paths(graph)
    blast_radii = find_blast_radii(graph, agents, crews)  # Per-crew (1B)
    control_bypasses = find_control_bypasses(graph, crews, agents)
    
    # Phase 5: Findings (FIXED)
    graph_findings = generate_all_graph_findings(
        graph, crews, blast_radii, control_bypasses, 
        uncontrolled_paths, detected_frameworks
    )
    rule_findings = evaluate_existing_rules(...)
    all_findings = merge_and_dedup(graph_findings, rule_findings)
    
    # Phase 6: Incident matching (FIXED)
    incident_matches = match_incidents(capabilities, graph)
    for match in incident_matches:
        reason, confidence = generate_match_reason(
            match.incident_id, uncontrolled_paths, crews, blast_radii, agents
        )
        match.match_reason = reason
        match.confidence = confidence
    
    # Phase 7: Score (CALIBRATED)
    risk_score = calculate_risk_score(all_findings, signals, capabilities, guardrails, crews)
    per_crew_scores = {c.name: _crew_score(c, all_findings) for c in crews}
    
    # Phase 8: Telemetry (ENRICHED)
    telemetry = build_telemetry_profile(scan_result, graph, crews, blast_radii, all_findings)
    
    # Phase 9: Badge (NEW)
    if options.badge:
        badge_svg = generate_badge_svg(risk_score, len(all_findings), critical_count)
        write_badge(options.badge_path, badge_svg)
    
    # Phase 10: Flow maps (NEW)
    flow_maps = render_crew_flow_maps(crews, graph, all_findings, blast_radii)
    
    return ScanResult(
        ...,
        graph=graph,
        crews=crews,
        blast_radii=blast_radii,
        per_crew_scores=per_crew_scores,
        telemetry_profile=telemetry,
        flow_maps=flow_maps,  # For terminal rendering
    )
```

---

## VALIDATION TARGETS

### On crewAI-examples — must all pass:

**Graph correctness:**
1. `shares_tool` edges < 25 (all same-crew, down from 78)
2. `feeds_into` edges: no cross-project collisions (no "Researcher → Book Outlining Agent")
3. `filtered_by` or `gated_by` edges > 0 (from nvidia marketing guardrails with covers_tools)
4. `control_coverage_pct > 0` (some guardrails have linked tools)

**Finding accuracy:**
5. STRATUM-CR05 fires once per qualifying crew, not globally. StockAnalysisCrew gets "ScrapeWebsiteTool → 4 agents" (CRITICAL). RecruitmentCrew gets "SerperDevTool → 3 agents" (HIGH). No finding claims 9 agents.
6. STRATUM-CR06 evidence cites ONE crew per finding instance, not multiple
7. STRATUM-CR01 only fires for same-crew shared tools bridging trust boundaries
8. STRATUM-002 remediation is `human_input=True` (CrewAI), not `graph.compile(...)`
9. STRATUM-001 evidence only includes email_auto_responder_flow files

**Incident matching:**
10. EchoLeak match_reason cites Gmail/GmailGetThread/GmailToolkit path in EmailFilterCrew
11. EchoLeak match_reason does NOT mention FileReadTool or SerperDevTool
12. Slack AI Exfil has different match_reason from EchoLeak (not identical text)
13. Slack AI Exfil confidence ≤ 0.75 (no Slack data source in codebase, only Slack outbound sender)
14. Docker Gordon match_reason cites ScrapeWebsiteTool or web scraping

**Virality features:**
15. Flow map renders for EmailFilterCrew showing Gmail inbox → 3-agent chain → Gmail outbound ⚠ no gate
16. Flow map renders for StockAnalysisCrew showing 🔴 BLAST RADIUS callout
17. `--badge` flag generates valid SVG file

**Telemetry:**
18. Profile has ≥ 30 populated fields
19. `risk_score_per_crew` is a non-empty dict with hashed keys
20. `findings_by_severity` and `findings_by_category` match actual finding counts
21. `error_handling_ratio` is non-zero (some caps have error handling)
22. `guardrail_linked_count` > 0 (nvidia marketing guardrails have covers_tools)
23. `blast_radius_distribution` is correct (e.g., {"2": 4, "3": 3, "4": 1})

**Score calibration:**
24. Global risk score ≤ 85 (down from 98 — monorepo attenuation)
25. Per-crew scores available: EmailFilterCrew highest, GameBuilderCrew lowest
26. Per-crew scores shown in terminal output

---

## WHAT DOES NOT CHANGE

- Capability detection (AST parsing, framework tools) — unchanged
- MCP scanning — unchanged  
- Env scanning — unchanged
- Existing rules STRATUM-003 through STRATUM-007 — unchanged
- History/diff system — unchanged
- `--no-telemetry` flag — unchanged
- Quick fix annotations — unchanged
- Dedup contract (finding.id + sorted evidence) — unchanged
- Confidence gating (CRITICAL requires CONFIRMED) — unchanged
- Crew extraction logic — unchanged (only graph construction of edges changes)
- Agent parser — unchanged (only how results are used in graph changes)

---

## VIRALITY IMPACT SUMMARY

| Feature | Before | After | Virality Effect |
|---|---|---|---|
| Flow map | None | Per-crew ASCII topology | **The screenshot.** Terminal output that shows data flow with ⚠ markers |
| Blast radius | "9 agents" (wrong) | "4 agents in StockAnalysisCrew" (right) | **Credible** — developer verifies and trusts it |
| Incident match | "FileReadTool → SerperDevTool" | "GmailGetThread → Gmail outbound in EmailFilterCrew" | **"Holy shit, that's exactly EchoLeak"** |
| Per-crew scores | None | EmailFilterCrew: 85, StockAnalysisCrew: 68 | **Actionable** — "fix EmailFilterCrew first" |
| Badge | None | SVG in README | **Passive virality** — every repo visitor sees the score |
| Risk score | 98 (alarmist) | ~75 (calibrated) | **Trustworthy** — not crying wolf |

## TELEMETRY IMPACT SUMMARY

| Metric | Before | After | Enterprise Value |
|---|---|---|---|
| Fields | 13 | 35+ | Full architectural fingerprint for benchmarking |
| Graph topology | None | edge_density, max_fan_out, chain_depth | "Projects with your topology have these risks" |
| Per-crew scores | None | Hashed crew→score mapping | Vertical/team-level risk benchmarking |
| Blast radius dist | max only | Full distribution | "82nd percentile for blast radius in your archetype" |
| Control maturity | coverage_pct only | 8 maturity signals | "Adding one HITL gate reduces score by avg 18 points" |
| Guardrail linking | None | guardrail_linked_count | "Only 12% of guardrails are actually connected to capabilities" |
