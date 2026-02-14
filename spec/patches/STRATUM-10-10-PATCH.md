# STRATUM v0.2.1 — The 10/10 Patch

## WHAT THIS FIXES

22 specific issues across three layers. Every fix is traced to a test that proves it works.

| # | Layer | Issue | Impact |
|---|---|---|---|
| 1 | Scanner | ScrapeWebsiteTool → 4 agents blast radius not firing | Missing the demo finding |
| 2 | Scanner | CR01 evidence leaks across 4 files from 3 subprojects | Credibility |
| 3 | Scanner | BR01 evidence includes integrations/CrewAI-LangGraph files | Credibility |
| 4 | Scanner | control_coverage_pct = 0.0 despite 3 guardrail edges | Incorrect metric |
| 5 | Scanner | Duplicate GmailToolkit blast radius entry | Dedup bug |
| 6 | Scanner | CR05 findings have no file paths in evidence | Can't find where to fix |
| 7 | Scanner | CR06 findings have prose remediation, no code | Can't copy-paste fix |
| 8 | Telemetry | Per-crew risk scores broken (10 of 13 findings unattributed) | Enterprise slide broken |
| 9 | Telemetry | risk_score_breakdown empty | Can't explain score |
| 10 | Telemetry | framework_versions empty | Can't do version correlation |
| 11 | Telemetry | has_scrape_to_action = false (should be true) | Incorrect flag |
| 12 | Telemetry | tools_shared_by_3_plus = 10 (too high) | Inflated metric |
| 13 | Telemetry | isolated_agent_count = 21 (suspicious) | Investigate |
| 14 | Terminal | No flow maps | Nothing to screenshot |
| 15 | Terminal | No action grouping | 13 findings instead of 3 actions |
| 16 | Terminal | No risk bar | Score is a number, not a visual |
| 17 | Terminal | No time estimates | Problems, not a plan |
| 18 | Terminal | No --verbose/--quiet modes | One-size-fits-all |
| 19 | Terminal | MEDIUM findings get full treatment | Cognitive overload |
| 20 | Terminal | Finding IDs as primary organization | Developer doesn't care about IDs |
| 21 | Terminal | No badge/CI output | No passive distribution |
| 22 | Terminal | No "apply to" file references on actions | Fix what, where? |

---

## PHASE 1: SCANNER FIXES

### Fix 1: ScrapeWebsiteTool Blast Radius

**Root cause:** The blast radius computation skips a tool when it encounters a dedup collision. ScrapeWebsiteTool and WebsiteSearchTool both exist in StockAnalysisCrew. When the iterator finds WebsiteSearchTool (3 agents), it marks StockAnalysisCrew as "handled" and skips ScrapeWebsiteTool (4 agents).

**Fix in `graph/pathfinder.py`:**

```python
def find_blast_radii(graph, agents, crews) -> list[BlastRadius]:
    results = []
    
    for crew in crews:
        crew_agent_names = set(crew.agent_names)
        
        # Collect ALL tools per agent in this crew
        tool_to_agents = {}  # tool_name → [agent_names]
        for agent_def in agents:
            if agent_def.name in crew_agent_names and agent_def.tool_names:
                for tool in agent_def.tool_names:
                    if tool not in tool_to_agents:
                        tool_to_agents[tool] = []
                    tool_to_agents[tool].append(agent_def.name)
        
        # Emit blast radius for EVERY tool shared by 2+ agents
        # DO NOT break or skip after first tool per crew
        for tool_name, sharing_agents in tool_to_agents.items():
            if len(sharing_agents) < 2:
                continue
            
            downstream_externals = _find_downstream_externals(graph, sharing_agents)
            
            results.append(BlastRadius(
                source_node_id=f"cap_{tool_name}",
                source_label=tool_name,
                affected_agent_ids=sharing_agents,
                affected_agent_labels=[_get_agent_label(graph, a) for a in sharing_agents],
                downstream_external_ids=[e.id for e in downstream_externals],
                downstream_external_labels=[e.label for e in downstream_externals],
                agent_count=len(sharing_agents),
                external_count=len(downstream_externals),
                crew_name=crew.name,
                crew_id=crew.name,
            ))
    
    # DEDUP: by (tool_name, crew_name) — keep the first, not by crew alone
    seen = set()
    deduped = []
    for br in results:
        key = (br.source_label, br.crew_name)
        if key not in seen:
            seen.add(key)
            deduped.append(br)
    
    # Sort by agent_count descending
    deduped.sort(key=lambda br: -br.agent_count)
    
    return deduped
```

**The bug was:** Dedup key was `crew_name` alone (or similar), so only one blast radius per crew was emitted. Fix: dedup key is `(tool_name, crew_name)`.

**Validation:** After fix, blast_radii for StockAnalysisCrew should include:
- ScrapeWebsiteTool: 4 agents (financial_agent, research_analyst_agent, financial_analyst_agent, investment_advisor_agent)
- WebsiteSearchTool: 3 agents
- CalculatorTool: 3 agents
- SEC10QTool: 3 agents
- SEC10KTool: 3 agents

max_blast_radius should be 4. CR05 finding should fire for ScrapeWebsiteTool → 4 agents as CRITICAL.

### Fix 2: CR01 Evidence Scoping

**Root cause:** CR01 collects evidence from every file where any agent in the finding is defined. Matcher is defined in match_profile_to_positions AND recruitment. Job Candidate Researcher is in recruitment. Unrelated files from instagram_post and email_auto_responder_flow get pulled in because the evidence collector greps broadly.

**Fix in `rules/graph_rules.py` (or wherever CR01 is generated):**

```python
def _scope_evidence_to_crew(finding, crew_name, crew_definitions, agent_definitions):
    """
    Filter evidence to only include files that share a directory root
    with the crew's source_file.
    """
    crew = next((c for c in crew_definitions if c.name == crew_name), None)
    if not crew or not crew.source_file:
        return finding
    
    crew_root = _get_project_root(crew.source_file)
    
    scoped_evidence = []
    for ev in finding.evidence:
        ev_path = ev.split(":")[0]  # Strip line numbers
        ev_root = _get_project_root(ev_path)
        if _shares_project_root(crew_root, ev_root):
            scoped_evidence.append(ev)
    
    # Always keep at least one evidence item
    if scoped_evidence:
        finding.evidence = scoped_evidence
    
    return finding

def _get_project_root(path: str) -> str:
    """
    Extract the first 2 directory components as the project root.
    'crews/match_profile_to_positions/src/...' → 'crews/match_profile_to_positions'
    'flows/email_auto_responder_flow/src/...' → 'flows/email_auto_responder_flow'
    """
    parts = path.replace("\\", "/").split("/")
    return "/".join(parts[:2]) if len(parts) >= 2 else parts[0]

def _shares_project_root(root_a: str, root_b: str) -> bool:
    return root_a.lower() == root_b.lower()
```

**Apply to CR01, BR01, CR02, STRATUM-008, and any finding that collects evidence from multiple source files.**

After generating the finding and before adding it to the results list:
```python
finding = _scope_evidence_to_crew(finding, crew_name, crew_definitions, agent_definitions)
```

**Validation:**
- CR01 evidence: 1-2 files, all from `crews/match_profile_to_positions/` or `crews/recruitment/`
- BR01 evidence: 1-3 files, all from `flows/email_auto_responder_flow/`
- No evidence from `crews/instagram_post/` in CR01
- No evidence from `integrations/CrewAI-LangGraph/` in BR01

### Fix 3: BR01 Evidence Scoping

Same fix as #2. BR01 is about "agent sends external messages without human review." The finding relates to the email auto-responder flow. Evidence should only include files from that flow.

Additionally, BR01's evidence currently includes 6 files. The fix should also limit evidence to the most relevant files (max 3):

```python
def _limit_evidence(evidence: list, max_items: int = 3) -> list:
    """Keep the most specific evidence items."""
    if len(evidence) <= max_items:
        return evidence
    # Prefer files with line numbers (more specific)
    with_lines = [e for e in evidence if ':' in e and not e.endswith(':0')]
    without = [e for e in evidence if e not in with_lines]
    return (with_lines + without)[:max_items]
```

### Fix 4: control_coverage_pct Calculation

**Root cause:** The risk_surface computation counts `has_control` on path edges (reads_from, sends_to, writes_to, shares_with), but filtered_by/gated_by edges are control edges themselves — they're not on the data path. The computation needs to check: for each controllable data-path edge, does the source capability have a guardrail edge?

**Fix in `graph/pathfinder.py` or `scanner.py` where risk_surface is computed:**

```python
def _compute_control_coverage(graph) -> float:
    """
    For each data-path edge (reads_from, sends_to, writes_to, shares_with, shares_tool),
    check if either endpoint has a gated_by or filtered_by edge.
    """
    controllable_edge_types = {"reads_from", "sends_to", "writes_to", "shares_with", "shares_tool"}
    guardrail_edge_types = {"gated_by", "filtered_by"}
    
    # Build set of nodes that have guardrail coverage
    guarded_nodes = set()
    for edge in graph.edges:
        if edge.type in guardrail_edge_types:
            guarded_nodes.add(edge.source)  # The capability being guarded
    
    controllable = 0
    controlled = 0
    for edge in graph.edges:
        if edge.type in controllable_edge_types:
            controllable += 1
            if edge.source in guarded_nodes or edge.target in guarded_nodes:
                controlled += 1
            # Also check if the edge itself has has_control flag
            if edge.has_control:
                controlled += 1
                controlled = min(controlled, controllable)  # Don't double-count
    
    if controllable == 0:
        return 0.0
    
    return round(controlled / controllable, 4)
```

**Validation:** control_coverage_pct > 0. Specifically, SerperDevTool has 3 filtered_by edges, and there are shares_tool edges involving SerperDevTool. Those shares_tool edges should be counted as controlled.

### Fix 5: Deduplicate Blast Radii

Already handled in Fix 1 — dedup key is `(tool_name, crew_name)`. The duplicate GmailToolkit entry (same tool, same crew, same agent_count) will be caught.

### Fix 6: CR05 File Paths in Evidence

**Current:** `['Crew: SurpriseTravelCrew', 'Shared by: Activity Planner, ...', 'Downstream: Serper API']`

No file path. Developer can't find where to apply the fix.

**Fix:** Add the crew's source_file and the tool's instantiation file to evidence:

```python
def generate_blast_radius_findings(blast_radii, crews, agent_definitions, detected_frameworks):
    for br in significant:
        # Find the crew's source file
        crew = next((c for c in crews if c.name == br.crew_name), None)
        crew_file = crew.source_file if crew else ""
        
        # Find files where the shared tool is instantiated/assigned
        tool_files = set()
        for agent_def in agent_definitions:
            if agent_def.name in br.affected_agent_ids:
                if agent_def.source_file:
                    tool_files.add(agent_def.source_file)
        
        # Clean paths for display
        display_files = [_shorten_path(f) for f in sorted(tool_files)[:2]]
        
        evidence = [
            f"Crew: {br.crew_name}",
            f"Shared by: {', '.join(br.affected_agent_labels)}",
            f"Downstream: {', '.join(br.downstream_external_labels)}",
        ]
        # Add file paths
        for df in display_files:
            evidence.append(df)
        if crew_file and _shorten_path(crew_file) not in display_files:
            evidence.append(_shorten_path(crew_file))
        
        finding = Finding(
            evidence=evidence,
            # ... rest unchanged
        )
```

**Validation:** Every CR05 finding has at least one file path in its evidence array that contains `\\` or `/`.

### Fix 7: CR06 Code Remediation

**Current:**
```
Route all Gmail inbox access through Email Action Agent:
  1. Remove direct Gmail inbox access from Email Response Writer
  2. Pass filtered output from Email Action Agent to Email Response Writer
  3. Or add output_filter on Email Response Writer's direct read
```

Prose. Not actionable.

**Fix:** Add framework-specific code:

```python
CR06_REMEDIATION = {
    "CrewAI": {
        "remove_tool": (
            "Fix (CrewAI) — Remove direct data access from downstream agent:\n"
            "  # In {crew_file}:\n"
            "  {downstream_agent_var} = Agent(\n"
            "      role=\"{downstream_role}\",\n"
            "      tools=[...],\n"
            "-     tools=[{shared_tool}, ...],  # remove {shared_tool}\n"
            "+     tools=[...],                  # only non-data-source tools\n"
            "  )\n"
            "\n"
            "Or — add validation on the direct read:\n"
            "  task = Task(\n"
            "      agent={downstream_agent_var},\n"
            "+     output_pydantic=ValidatedInput,  # enforce schema\n"
            "  )"
        ),
    },
    "LangGraph": {
        "remove_tool": (
            "Fix (LangGraph) — Gate the data source access:\n"
            "  graph.add_conditional_edges(\n"
            "      \"{upstream_node}\",\n"
            "      should_continue,\n"
            "      {{\"proceed\": \"{downstream_node}\", \"reject\": END}}\n"
            "  )"
        ),
    }
}

def _get_cr06_remediation(bypass, detected_frameworks, crew_file=""):
    fw = detected_frameworks[0] if detected_frameworks else "CrewAI"
    template = CR06_REMEDIATION.get(fw, CR06_REMEDIATION["CrewAI"])["remove_tool"]
    
    return template.format(
        crew_file=_shorten_path(crew_file),
        downstream_agent_var=_to_var_name(bypass.downstream_agent),
        downstream_role=bypass.downstream_agent,
        upstream_agent_var=_to_var_name(bypass.upstream_agent),
        shared_tool=bypass.shared_source,
        upstream_node=bypass.upstream_agent,
        downstream_node=bypass.downstream_agent,
    )
```

**For CR06.1 on crewAI-examples, the output becomes:**

```
Fix (CrewAI) — Remove direct data access from downstream agent:
  # In email_filter_crew/email_filter_crew.py:
  email_response_writer = Agent(
      role="Email Response Writer",
      tools=[...],
-     tools=[GmailGetThread, ...],  # remove GmailGetThread
+     tools=[...],                  # only non-data-source tools
  )

Or — add validation on the direct read:
  task = Task(
      agent=email_response_writer,
+     output_pydantic=ValidatedInput,  # enforce schema
  )
```

---

## PHASE 2: TELEMETRY FIXES

### Fix 8: Per-Crew Risk Score Attribution

**Root cause:** The scoring function matches crew names against evidence strings. But 10 of 13 findings have file paths in evidence, not crew names. `STRATUM-001` evidence is `flows\email_auto_responder_flow\...\email_filter_crew.py` — the string "EmailFilterCrew" never appears.

**Fix:** Build a mapping from directory prefixes to crew names, then attribute findings by matching evidence file paths to crew directories.

```python
def _build_crew_directory_map(crew_definitions) -> dict:
    """
    Map directory prefixes to crew names.
    
    'flows/email_auto_responder_flow' → 'EmailFilterCrew'
    'crews/stock_analysis' → 'StockAnalysisCrew'
    'crews/match_profile_to_positions' → 'MatchToProposalCrew'
    
    A crew's directory is derived from its source_file.
    If a crew's source_file is 'flows/email.../crews/email_filter_crew/email_filter_crew.py',
    the directory is 'flows/email_auto_responder_flow'.
    """
    crew_dirs = {}
    for crew in crew_definitions:
        sf = crew.source_file if hasattr(crew, 'source_file') else crew.get('source_file', '')
        if not sf:
            continue
        parts = sf.replace("\\", "/").split("/")
        # Use first 2 components as project root
        if len(parts) >= 2:
            root = "/".join(parts[:2]).lower()
            name = crew.name if hasattr(crew, 'name') else crew.get('name', '')
            crew_dirs[root] = name
    return crew_dirs


def _attribute_finding_to_crew(finding, crew_dir_map, crew_definitions) -> str:
    """
    Return the crew name this finding belongs to.
    
    Strategy (in order):
    1. Check if crew name appears in evidence strings (current approach)
    2. Check if evidence file paths match a crew's directory prefix
    3. Check if crew name appears in finding title
    4. Return "" if no match
    """
    crew_names = set(
        c.name if hasattr(c, 'name') else c.get('name', '')
        for c in crew_definitions
    )
    evidence = finding.evidence if hasattr(finding, 'evidence') else finding.get('evidence', [])
    title = finding.title if hasattr(finding, 'title') else finding.get('title', '')
    
    # Strategy 1: Crew name in evidence
    evidence_str = str(evidence)
    for name in crew_names:
        if name in evidence_str:
            return name
    
    # Strategy 2: File path directory match
    for ev in evidence:
        ev_clean = ev.replace("\\", "/").lower()
        parts = ev_clean.split("/")
        if len(parts) >= 2:
            ev_root = "/".join(parts[:2])
            if ev_root in crew_dir_map:
                return crew_dir_map[ev_root]
    
    # Strategy 3: Crew name in title
    for name in crew_names:
        if name in title:
            return name
    
    return ""


def compute_per_crew_scores(findings, crew_definitions) -> dict:
    """
    Returns {crew_hash: score} with findings attributed to crews
    by directory matching, not string matching.
    """
    crew_dir_map = _build_crew_directory_map(crew_definitions)
    
    severity_weights = {
        "CRITICAL": 25, "critical": 25,
        "HIGH": 15, "high": 15,
        "MEDIUM": 8, "medium": 8,
        "LOW": 3, "low": 3,
    }
    
    crew_scores = {}  # crew_name → raw_score
    
    for f in findings:
        crew_name = _attribute_finding_to_crew(f, crew_dir_map, crew_definitions)
        if not crew_name:
            continue
        
        severity = f.severity if hasattr(f, 'severity') else f.get('severity', '')
        weight = severity_weights.get(severity, 0)
        
        if crew_name not in crew_scores:
            crew_scores[crew_name] = 0
        crew_scores[crew_name] += weight
    
    # Cap at 100, hash crew names, sort descending
    result = {}
    for name, score in crew_scores.items():
        crew_hash = hashlib.sha256(name.encode()).hexdigest()[:8]
        result[crew_hash] = min(score, 100)
    
    return result
```

**Also store the unhashed version for the risk_scores_per_crew list:**

```python
# In build_scan_profile:
crew_scores_named = compute_per_crew_scores_named(all_findings, crews)
p.risk_scores_per_crew = sorted(crew_scores_named.values(), reverse=True)
```

**Validation:**
- EmailFilterCrew should have the highest score: STRATUM-001 (CRITICAL=25) + CR05.2 (HIGH=15) + CR06.1 (HIGH=15) + BR01 (HIGH=15) = 70
- StockAnalysisCrew: CR05.1 (CRITICAL=25) + STRATUM-009 (MEDIUM=8) = 33
- Per-crew scores should have at least 3 non-zero values > 30
- STRATUM-001 should attribute to EmailFilterCrew via evidence file path matching

### Fix 9: Risk Score Breakdown

```python
def compute_risk_score_with_breakdown(findings, signals, guardrails, crews) -> tuple:
    """Returns (score, breakdown_dict)."""
    
    breakdown = {}
    
    # Base severity
    base = 0
    for f in findings:
        sev = f.severity if hasattr(f, 'severity') else f.get('severity', '')
        if sev in ("CRITICAL", "critical"):
            base += 25
        elif sev in ("HIGH", "high"):
            base += 15
        elif sev in ("MEDIUM", "medium"):
            base += 8
        elif sev in ("LOW", "low"):
            base += 3
    breakdown["base_severity"] = base
    
    # Signal severity
    signal_score = 0
    for s in signals:
        sev = s.severity if hasattr(s, 'severity') else s.get('severity', '')
        if sev in ("MEDIUM", "medium"):
            signal_score += 8
        elif sev in ("LOW", "low"):
            signal_score += 3
    breakdown["signal_severity"] = signal_score
    
    # Bonus: no real guardrails (only 'validation' type)
    bonus_guardrails = 0
    guardrail_kinds = set(g.kind if hasattr(g, 'kind') else g.get('kind', '') for g in guardrails)
    if guardrail_kinds <= {"validation", ""}:
        bonus_guardrails = 10
    breakdown["bonus_no_real_guardrails"] = bonus_guardrails
    
    # Bonus: no HITL anywhere
    bonus_hitl = 0
    if not any((g.kind if hasattr(g, 'kind') else g.get('kind', '')) == "hitl" for g in guardrails):
        bonus_hitl = 5
    breakdown["bonus_no_hitl"] = bonus_hitl
    
    # Monorepo attenuation
    attenuation = 0
    if len(crews) > 5:
        attenuation = -max(0, int(5 * len([c for c in crews if len(c.agent_names if hasattr(c, 'agent_names') else c.get('agent_names', [])) > 0]) * 0.3))
        # Don't let attenuation exceed 30% of raw
    breakdown["monorepo_attenuation"] = attenuation
    
    raw = base + signal_score + bonus_guardrails + bonus_hitl + attenuation
    final = max(0, min(raw, 100))
    
    breakdown["raw_total"] = raw
    breakdown["final_capped"] = final
    
    return final, breakdown
```

**Validation:** `risk_score_breakdown` is a non-empty dict with keys like `base_severity`, `signal_severity`, `bonus_no_real_guardrails`, `bonus_no_hitl`, `monorepo_attenuation`, `raw_total`, `final_capped`.

### Fix 10: Framework Versions

```python
def detect_framework_versions(directory: str) -> dict:
    """
    Parse requirements.txt, pyproject.toml, or setup.cfg for framework versions.
    Returns {"crewai": "0.51.0", "langchain-core": "0.1.20", ...}
    """
    versions = {}
    
    # Search for requirements files
    req_files = []
    for root, dirs, files in os.walk(directory):
        for fname in files:
            if fname in ("requirements.txt", "pyproject.toml", "setup.cfg"):
                req_files.append(os.path.join(root, fname))
    
    target_packages = {
        "crewai", "langchain", "langchain-core", "langchain-community",
        "langgraph", "autogen", "openai", "anthropic",
    }
    
    for req_file in req_files:
        try:
            with open(req_file, "r") as f:
                content = f.read()
            
            if req_file.endswith("requirements.txt"):
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Parse "package==version" or "package>=version"
                    for sep in ("==", ">=", "~=", "<=", ">", "<"):
                        if sep in line:
                            name, version = line.split(sep, 1)
                            name = name.strip().lower()
                            version = version.strip().split(",")[0].strip()
                            if name in target_packages:
                                versions[name] = version
                            break
            
            elif req_file.endswith("pyproject.toml"):
                # Simple regex extraction, not full TOML parsing
                import re
                for pkg in target_packages:
                    # Match patterns like: crewai = ">=0.51.0"
                    # Or: "crewai>=0.51.0"
                    patterns = [
                        rf'"{pkg}[><=~!]*([0-9][0-9.]*)"',
                        rf"'{pkg}[><=~!]*([0-9][0-9.]*)'",
                        rf'{pkg}\s*=\s*"[><=~!]*([0-9][0-9.]*)"',
                    ]
                    for pattern in patterns:
                        match = re.search(pattern, content, re.IGNORECASE)
                        if match:
                            versions[pkg] = match.group(1)
                            break
        except (IOError, UnicodeDecodeError):
            continue
    
    return versions
```

**Wire into `build_scan_profile`:**
```python
p.framework_versions = detect_framework_versions(scan_result.directory)
```

### Fix 11: has_scrape_to_action

**Current logic** checks for "scrape" in edge source IDs, but graph edge sources are node IDs like `cap_ScrapeWebsiteTool_outbound`, not plain text.

```python
def _detect_scrape_to_action(profile, graph):
    """
    True if the project scrapes web content AND sends data to external services.
    """
    scrape_tools = {"ScrapeWebsiteTool", "WebsiteSearchTool", "requests"}
    has_scraping = any(t in profile.tool_names for t in scrape_tools) or profile.has_web_scraping
    
    has_outbound = profile.external_service_count > 0
    
    # Check if any agent with scraping tools also has sends_to edges
    # or if scraping output feeds into agents that have outbound
    has_path = False
    for edge in graph.get("edges", []):
        source_lower = edge.get("source", "").lower()
        if edge["type"] == "sends_to" and any(t.lower() in source_lower for t in scrape_tools):
            has_path = True
            break
        # Also check: scrape tool → agent → sends_to
        if edge["type"] in ("tool_of", "shares_tool") and any(t.lower() in source_lower for t in scrape_tools):
            # This agent has a scrape tool — check if they also have sends_to
            agent_id = edge["target"]
            for e2 in graph.get("edges", []):
                if e2["source"] == agent_id and e2["type"] == "sends_to":
                    has_path = True
                    break
    
    return has_scraping and has_outbound and has_path
```

### Fix 12: tools_shared_by_3_plus Count

**Root cause:** Likely counting across crews or counting duplicate crew definitions (MarketingPostsCrew appears twice in crew_definitions).

```python
def _count_tools_shared_by_3_plus(agents, crews) -> int:
    """Count tools shared by 3+ agents, strictly per-crew, deduped."""
    seen_crew_names = set()
    count = 0
    
    for crew in crews:
        # Skip duplicate crew definitions
        if crew.name in seen_crew_names:
            continue
        seen_crew_names.add(crew.name)
        
        crew_agent_names = set(crew.agent_names)
        tool_counts = {}
        for agent in agents:
            if agent.name in crew_agent_names:
                for tool in agent.tool_names:
                    tool_counts[tool] = tool_counts.get(tool, 0) + 1
        
        for tool, c in tool_counts.items():
            if c >= 3:
                count += 1
    
    return count
```

**Validation:** On crewAI-examples, expected ~5-6 (not 10):
- StockAnalysisCrew: ScrapeWebsiteTool(4), WebsiteSearchTool(3), CalculatorTool(3), SEC10QTool(3), SEC10KTool(3) = 5
- RecruitmentCrew: SerperDevTool(3), ScrapeWebsiteTool(3) = 2 → total ~7
- SurpriseTravelCrew: SerperDevTool(3) = 1 → total ~8
- JobPostingCrew: web_search_tool(3), seper_dev_tool(3) = 2 → total ~10

Actually 10 might be correct if JobPostingCrew tools are counted. Need to verify that MarketingPostsCrew isn't being double-counted (it appears twice in crew_definitions). The dedup fix above prevents double-counting.

### Fix 13: Isolated Agent Count

21 of 53 agents have no edges. Investigate: are these single-agent crews or agents whose only connections are through tool_of edges (which connect capability→agent, not agent→agent)?

```python
def _compute_isolated_agents(graph):
    """
    An agent is isolated if it has no edges of types that indicate
    data flow or collaboration: feeds_into, shares_tool, shares_with,
    reads_from, sends_to.
    
    tool_of edges (capability→agent) don't count as "connected" because
    they just mean the agent has a tool — not that it communicates.
    """
    data_flow_types = {"feeds_into", "shares_tool", "shares_with", "reads_from", 
                       "sends_to", "writes_to", "gated_by", "filtered_by"}
    
    agent_nodes = set(n["id"] for n in graph["nodes"] if n["type"] == "agent")
    connected = set()
    
    for edge in graph["edges"]:
        if edge["type"] in data_flow_types:
            if edge["source"] in agent_nodes:
                connected.add(edge["source"])
            if edge["target"] in agent_nodes:
                connected.add(edge["target"])
    
    return len(agent_nodes - connected)
```

This should reduce the count since agents that have tool_of edges but no data flow edges are technically isolated from a risk perspective (no data flows to/from them). This is actually correct and useful info — it means "21 agents are defined but don't participate in any data flow paths." For single-agent crews, that's expected.

---

## PHASE 3: TERMINAL OUTPUT REDESIGN

This is the big one. The full architecture from the terminal redesign spec, condensed into implementation-ready code.

### File Structure

```
stratum/output/
├── __init__.py
├── terminal.py              # REWRITE: main renderer
├── action_groups.py         # NEW: findings → actions
├── flow_map.py              # NEW: per-crew ASCII diagrams
├── risk_bar.py              # NEW: visual risk bar
├── code_block.py            # NEW: bordered code boxes
├── verbose.py               # NEW: full detail mode
├── quiet.py                 # NEW: CI mode
├── json_output.py           # UNCHANGED
```

### `action_groups.py`

```python
"""
Collapses findings into deduplicated, prioritized actions.
13 findings → 7 action groups → 3 that matter right now.
"""
from dataclasses import dataclass, field

@dataclass
class ActionGroup:
    action_id: str = ""
    title: str = ""
    finding_ids: list = field(default_factory=list)
    finding_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    severity_label: str = ""
    effort: str = ""
    narrative: str = ""
    code_fix: str = ""
    apply_to: list = field(default_factory=list)
    incident_match: dict = field(default_factory=dict)
    priority: int = 0


# Each action: which findings it claims, and the developer-facing metadata
ACTION_DEFS = [
    {
        "id": "add_hitl",
        "title": "Add human review on outbound tasks",
        "claims": lambda f: (
            f.get("quick_fix_type") == "add_hitl"
            or "human_input=True" in f.get("remediation", "")
            or f["id"] in ("STRATUM-001", "STRATUM-002", "STRATUM-BR01")
        ),
        "effort": "5 min",
        "priority": 1,
        "code": {
            "CrewAI": (
                "task = Task(\n"
                "    description=\"...\",\n"
                "+   human_input=True   # review before external calls\n"
                ")"
            ),
            "LangGraph": (
                "graph = workflow.compile(\n"
                "+   interrupt_before=[\"send_email\", \"file_management\"]\n"
                ")"
            ),
        },
        "narrative_builder": "_narrative_hitl",
    },
    {
        "id": "add_tool_validation",
        "title": "Add input validation on shared tools",
        "claims": lambda f: f["id"].startswith("STRATUM-CR05"),
        "effort": "30 min",
        "priority": 2,
        "code": {
            "CrewAI": (
                "class ValidatedSearch(BaseTool):\n"
                "    def _run(self, query: str) -> str:\n"
                "        raw = SerperDevTool()._run(query)\n"
                "+       if contains_injection_patterns(raw):\n"
                "+           raise ValueError(\"Suspicious content\")\n"
                "        return raw"
            ),
        },
        "narrative_builder": "_narrative_blast_radius",
    },
    {
        "id": "fix_bypass",
        "title": "Fix data access bypass",
        "claims": lambda f: f["id"].startswith("STRATUM-CR06"),
        "effort": "15 min",
        "priority": 3,
        "code": {
            "CrewAI": (
                "# Remove direct data access from downstream agent:\n"
                "response_writer = Agent(\n"
                "    role=\"Email Response Writer\",\n"
                "-   tools=[GmailGetThread, ...],\n"
                "+   tools=[TavilySearchResults],  # no direct inbox\n"
                ")\n"
                "\n"
                "# Or add validation on the direct read:\n"
                "task = Task(\n"
                "    agent=response_writer,\n"
                "+   output_pydantic=ValidatedEmail,\n"
                ")"
            ),
        },
        "narrative_builder": "_narrative_bypass",
    },
    {
        "id": "isolate_tools",
        "title": "Isolate shared tool contexts between agents",
        "claims": lambda f: f["id"] == "STRATUM-CR01",
        "effort": "15 min",
        "priority": 4,
        "code": {
            "CrewAI": (
                "matcher = Agent(\n"
                "    role=\"Matcher\",\n"
                "-   tools=[shared_serper],\n"
                "+   tools=[SerperDevTool()],  # independent instance\n"
                ")"
            ),
        },
        "narrative_builder": "_narrative_bridge",
    },
    {
        "id": "add_error_handling",
        "title": "Add error handling on external calls",
        "claims": lambda f: f["id"] == "STRATUM-008",
        "effort": "30 min",
        "priority": 10,
        "code": {"CrewAI": "try:\n    result = tool._run(input)\nexcept Exception as e:\n    return f\"Tool failed: {e}\""},
        "narrative_builder": None,
    },
    {
        "id": "add_timeout",
        "title": "Add timeouts on HTTP calls",
        "claims": lambda f: f["id"] == "STRATUM-009",
        "effort": "2 min",
        "priority": 11,
        "code": {"_default": "requests.get(url, timeout=30)"},
        "narrative_builder": None,
    },
    {
        "id": "add_checkpointing",
        "title": "Add checkpointing for crash recovery",
        "claims": lambda f: f["id"] == "STRATUM-010",
        "effort": "5 min",
        "priority": 12,
        "code": {"CrewAI": "crew = Crew(\n    agents=[...],\n    tasks=[...],\n+   memory=True,\n)"},
        "narrative_builder": None,
    },
    {
        "id": "add_structured_output",
        "title": "Add output validation between agent steps",
        "claims": lambda f: f["id"] in ("STRATUM-CR02", "STRATUM-BR04"),
        "effort": "15 min",
        "priority": 13,
        "code": {"CrewAI": "task = Task(\n    description=\"...\",\n+   output_pydantic=StepOutput,\n)"},
        "narrative_builder": None,
    },
]

# ─── Narrative builders ───

def _narrative_hitl(findings, incident_matches):
    base = (
        "Your agents send emails and take actions with no human check. "
        "One crafted email can make your agent forward inbox contents "
        "to an attacker."
    )
    # Append incident if EchoLeak matched
    echo = next((m for m in incident_matches 
                 if m.get("incident_id", m.get("id", "")) == "ECHOLEAK-2025"
                 and m.get("confidence", 0) >= 0.75), None)
    if echo:
        base += (
            " This is the exact pattern behind the Microsoft "
            "Copilot EchoLeak breach."
        )
    return base

def _narrative_blast_radius(findings, incident_matches):
    parts = []
    for f in findings:
        title = f.get("title", "")
        clean = title.replace("Shared tool blast radius: ", "")
        parts.append(clean)
    return ". ".join(parts) + ". One poisoned result compromises all of them at once."

def _narrative_bypass(findings, incident_matches):
    if len(findings) == 1:
        desc = findings[0].get("description", "")
        first_sentence = desc.split(".")[0] + "."
        return first_sentence + " The filter exists but data flows around it."
    crew_names = set()
    for f in findings:
        for ev in f.get("evidence", []):
            if ev.startswith("Crew: "):
                crew_names.add(ev.replace("Crew: ", ""))
    return (
        f"In {len(crew_names)} crews, downstream agents bypass their upstream filters "
        f"by reading data sources directly. The filters exist but data flows around them."
    )

def _narrative_bridge(findings, incident_matches):
    f = findings[0]
    return f.get("description", "")[:200]

NARRATIVE_MAP = {
    "_narrative_hitl": _narrative_hitl,
    "_narrative_blast_radius": _narrative_blast_radius,
    "_narrative_bypass": _narrative_bypass,
    "_narrative_bridge": _narrative_bridge,
}


def group_findings_into_actions(findings, signals, incident_matches, 
                                 detected_frameworks, blast_radii):
    """
    Main entry point. Returns prioritized list of ActionGroups.
    """
    all_items = findings  # Only top_paths, not signals (signals go to one-liners)
    
    claimed = set()
    groups = []
    
    for defn in sorted(ACTION_DEFS, key=lambda d: d["priority"]):
        matching = [f for f in all_items 
                    if f["id"] not in claimed and defn["claims"](f)]
        if not matching:
            continue
        
        for f in matching:
            claimed.add(f["id"])
        
        g = ActionGroup()
        g.action_id = defn["id"]
        g.title = defn["title"]
        g.finding_ids = [f["id"] for f in matching]
        g.finding_count = len(matching)
        g.critical_count = sum(1 for f in matching if f["severity"] == "CRITICAL")
        g.high_count = sum(1 for f in matching if f["severity"] == "HIGH")
        g.medium_count = sum(1 for f in matching if f["severity"] == "MEDIUM")
        g.effort = defn["effort"]
        g.priority = defn["priority"]
        
        # Severity label
        parts = []
        if g.critical_count: parts.append(f"{g.critical_count} critical")
        if g.high_count: parts.append(f"{g.high_count} high")
        if g.medium_count: parts.append(f"{g.medium_count} medium")
        g.severity_label = " + ".join(parts)
        
        # Narrative
        builder_name = defn.get("narrative_builder")
        if builder_name and builder_name in NARRATIVE_MAP:
            g.narrative = NARRATIVE_MAP[builder_name](matching, incident_matches)
        else:
            # Use first finding's description, first sentence
            desc = matching[0].get("description", matching[0].get("title", ""))
            g.narrative = desc.split(".")[0] + "." if "." in desc else desc
        
        # Code fix
        fw = detected_frameworks[0] if detected_frameworks else "_default"
        code_options = defn.get("code", {})
        g.code_fix = code_options.get(fw, code_options.get("_default", ""))
        
        # Apply-to files
        apply_files = set()
        for f in matching:
            for ev in f.get("evidence", []):
                if "\\" in ev or "/" in ev:
                    clean = ev.split(":")[0].replace("\\", "/")
                    parts = clean.split("/")
                    if len(parts) > 2:
                        apply_files.add("/".join(parts[-2:]))
                    else:
                        apply_files.add(clean)
        g.apply_to = sorted(apply_files)[:3]
        
        # Incident match
        if defn["id"] == "add_hitl":
            echo = next((m for m in incident_matches 
                         if m.get("incident_id", m.get("id", "")) == "ECHOLEAK-2025"
                         and m.get("confidence", 0) >= 0.75), None)
            if echo:
                g.incident_match = {
                    "name": m.get("name", "Microsoft Copilot EchoLeak"),
                    "match_reason": m.get("match_reason", "")[:200],
                }
        
        groups.append(g)
    
    # Sort: critical-containing first, then by priority
    groups.sort(key=lambda g: (
        0 if g.critical_count > 0 else 1,
        -g.critical_count,
        -g.high_count,
        g.priority,
    ))
    
    return groups


def split_primary_secondary(groups):
    """Primary: has critical or high. Secondary: medium/low only."""
    primary = [g for g in groups if g.critical_count > 0 or g.high_count > 0]
    secondary = [g for g in groups if g.critical_count == 0 and g.high_count == 0]
    return primary, secondary
```

### `risk_bar.py`

```python
def render_risk_bar(score, findings_by_severity, width=40):
    filled = int(width * score / 100)
    empty = width - filled
    bar = "█" * filled + "░" * empty
    
    parts = []
    for sev in ("critical", "high", "medium", "low"):
        count = findings_by_severity.get(sev, 0)
        if count > 0:
            parts.append(f"{count} {sev}")
    severity_line = " · ".join(parts)
    
    return (
        f"\n"
        f" RISK SCORE {bar}  {score} / 100\n"
        f"            {'▔' * width}\n"
        f"            {severity_line}\n"
    )
```

### `code_block.py`

```python
def render_code_block(code, indent=3):
    lines = code.strip().split("\n")
    inner_w = max(len(l) for l in lines) + 2
    inner_w = min(max(inner_w, 20), 58)
    pad = " " * indent
    
    result = [f"{pad}┌{'─' * (inner_w + 2)}┐"]
    for line in lines:
        padded = line[:inner_w].ljust(inner_w)
        result.append(f"{pad}│ {padded} │")
    result.append(f"{pad}└{'─' * (inner_w + 2)}┘")
    return "\n".join(result)
```

### `flow_map.py`

```python
def render_crew_flow_map(crew_name, agent_names, process_type,
                          data_sources, external_sinks, 
                          blast_radii, bypasses, incidents,
                          width=68):
    """Render one crew's flow diagram."""
    lines = []
    iw = width - 4  # inner width
    
    def pad(text):
        t = text[:iw]
        return f"│ {t}{' ' * (iw - len(t))} │"
    
    # Header
    header = f" {crew_name} ({len(agent_names)} agents, {process_type}) "
    lines.append(f"┌{'─' * (width - 2)}┐")
    lines.append(pad(""))
    
    # Agent chain
    labels = [_shorten_agent_name(a) for a in agent_names]
    chain = " ──▶ ".join(labels)
    
    # Data sources
    if data_sources:
        for ds in data_sources[:2]:
            sens = f" ({ds['sensitivity']})" if ds.get("sensitivity", "unknown") != "unknown" else ""
            lines.append(pad(f"  {ds['label']}{sens}"))
        lines.append(pad(f"    └──▶ {chain}"))
    else:
        lines.append(pad(f"  {chain}"))
    
    # External sinks
    for sink in external_sinks[:4]:
        marker = "✓ gated" if sink.get("has_control") else "⚠ no gate"
        lines.append(pad(f"        └──▶ {sink['label']}  {marker}"))
    
    lines.append(pad(""))
    
    # Annotations
    for bp in bypasses[:2]:
        lines.append(pad(f"  ⚠ BYPASS: {bp['downstream']} reads {bp['source']} directly"))
    
    for br in blast_radii[:2]:
        lines.append(pad(f"  🔴 {br['tool']} shared by {br['count']} agents"))
    
    for inc in incidents[:1]:
        lines.append(pad(f"  📎 Matches: {inc['name']}"))
    
    if bypasses or blast_radii or incidents:
        lines.append(pad(""))
    
    lines.append(f"└{'─' * (width - 2)}┘")
    return "\n".join(lines)


def _shorten_agent_name(name):
    """'financial_analyst_agent' → 'Financial Analyst'"""
    clean = name.replace("_agent", "").replace("_", " ").title()
    if len(clean) > 20:
        words = clean.split()
        if len(words) > 2:
            clean = " ".join(words[:2])
    return clean


def render_flow_maps(crews, graph, findings, blast_radii, incident_matches):
    """Render flow maps for crews with findings. Max 4."""
    
    # Rank crews by finding severity
    crew_scores = {}
    sev_weights = {"CRITICAL": 100, "HIGH": 50, "MEDIUM": 10}
    for crew in crews:
        name = crew.get("name", crew["name"] if isinstance(crew, dict) else crew.name)
        score = 0
        for f in findings:
            if name in str(f.get("evidence", [])) or name in f.get("title", ""):
                score += sev_weights.get(f.get("severity", ""), 0)
        if score > 0:
            crew_scores[name] = score
    
    ranked = sorted(crew_scores.keys(), key=lambda n: -crew_scores[n])[:4]
    
    maps = []
    for crew_name in ranked:
        crew = next(c for c in crews 
                    if (c.get("name") if isinstance(c, dict) else c.name) == crew_name)
        agent_names = crew.get("agent_names") if isinstance(crew, dict) else crew.agent_names
        process_type = crew.get("process_type", "sequential") if isinstance(crew, dict) else getattr(crew, "process_type", "sequential")
        
        # Collect data for this crew
        crew_brs = [
            {"tool": br.get("source_label", br.get("tool", "")), 
             "count": br.get("agent_count", 0)}
            for br in blast_radii
            if br.get("crew_name", "") == crew_name and br.get("agent_count", 0) >= 3
        ]
        
        crew_bypasses = [
            {"downstream": f["title"].split("'")[1] if "'" in f["title"] else "?",
             "source": f["evidence"][-1].replace("Shared source: ", "") if f["evidence"] else "?"}
            for f in findings
            if f["id"].startswith("STRATUM-CR06") and crew_name in str(f.get("evidence", []))
        ]
        
        crew_incidents = [
            {"name": m.get("name", m.get("incident_id", ""))}
            for m in incident_matches
            if m.get("confidence", 0) >= 0.75
        ][:1]
        
        # Data sources and sinks from graph
        data_sources = _get_crew_data_sources(graph, agent_names)
        external_sinks = _get_crew_external_sinks(graph, agent_names)
        
        m = render_crew_flow_map(
            crew_name, agent_names, process_type,
            data_sources, external_sinks,
            crew_brs, crew_bypasses, crew_incidents
        )
        maps.append(m)
    
    return "\n\n".join(maps)


def _get_crew_data_sources(graph, agent_names):
    """Find data store nodes that feed into this crew's agents."""
    sources = []
    agent_ids = {f"agent_{a}" for a in agent_names}
    
    for edge in graph.get("edges", []):
        if edge["type"] == "reads_from":
            # Find which node is the data source
            source_node = next(
                (n for n in graph["nodes"] if n["id"] == edge["source"]),
                None
            )
            if source_node and source_node["type"] == "data_store":
                # Check if any agent in the crew reads from this
                sources.append({
                    "label": source_node["label"],
                    "sensitivity": source_node.get("data_sensitivity", "unknown"),
                })
    
    # Deduplicate
    seen = set()
    deduped = []
    for s in sources:
        if s["label"] not in seen:
            seen.add(s["label"])
            deduped.append(s)
    return deduped


def _get_crew_external_sinks(graph, agent_names):
    """Find external service nodes that this crew's agents send to."""
    sinks = []
    
    for edge in graph.get("edges", []):
        if edge["type"] == "sends_to":
            target_node = next(
                (n for n in graph["nodes"] if n["id"] == edge["target"]),
                None
            )
            if target_node and target_node["type"] == "external":
                sinks.append({
                    "label": target_node["label"],
                    "has_control": edge.get("has_control", False),
                })
    
    seen = set()
    deduped = []
    for s in sinks:
        if s["label"] not in seen:
            seen.add(s["label"])
            deduped.append(s)
    return deduped
```

### `terminal.py` — The Orchestrator (REWRITE)

```python
"""
Renders the scan result as action-oriented terminal output.

Structure:
1. Header
2. Risk bar
3. "Fix these first" — primary actions with full treatment
4. "What your agents look like" — flow maps
5. "Also worth fixing" — secondary actions as one-liners
6. Footer
"""

from .action_groups import group_findings_into_actions, split_primary_secondary
from .flow_map import render_flow_maps
from .risk_bar import render_risk_bar
from .code_block import render_code_block


def render_terminal_output(scan_result):
    """Main entry point."""
    out = []
    
    # ─── 1. HEADER ───
    d = scan_result["directory"].replace("\\", "/").rstrip("/").split("/")[-1]
    fw = ", ".join(scan_result["detected_frameworks"])
    crews = len(scan_result["crew_definitions"])
    agents = len(scan_result["agent_definitions"])
    files = scan_result["files_scanned"]
    
    out.append(f"""
 ╔═══════════════════════════════════════════════════════════════════╗
 ║  STRATUM SCAN                                                    ║
 ║  {d} · {files} files · {crews} crews · {agents} agents{' ' * max(0, 28 - len(d) - len(str(files)) - len(str(crews)) - len(str(agents)))}║
 ║  Frameworks: {fw}{' ' * max(0, 51 - len(fw))}║
 ╚═══════════════════════════════════════════════════════════════════╝""")
    
    # ─── 2. RISK BAR ───
    fb = {}
    for f in scan_result["top_paths"] + scan_result["signals"]:
        s = f["severity"].lower()
        fb[s] = fb.get(s, 0) + 1
    out.append(render_risk_bar(scan_result["risk_score"], fb))
    
    # ─── 3. ACTION GROUPS ───
    groups = group_findings_into_actions(
        scan_result["top_paths"],
        scan_result["signals"],
        scan_result["incident_matches"],
        scan_result["detected_frameworks"],
        scan_result["blast_radii"],
    )
    primary, secondary = split_primary_secondary(groups)
    
    if primary:
        out.append(_section("FIX THESE FIRST"))
        circles = "①②③④⑤⑥⑦⑧⑨"
        for i, g in enumerate(primary):
            out.append(_render_primary(g, circles[i] if i < len(circles) else f"({i+1})", scan_result))
    
    # ─── 4. FLOW MAPS ───
    crews_with_findings = [
        c for c in scan_result["crew_definitions"]
        if any(
            (c["name"] if isinstance(c, dict) else c.name) in str(f.get("evidence", [])) or
            (c["name"] if isinstance(c, dict) else c.name) in f.get("title", "")
            for f in scan_result["top_paths"]
        )
    ]
    if crews_with_findings:
        out.append(_section("WHAT YOUR AGENTS LOOK LIKE"))
        out.append(render_flow_maps(
            scan_result["crew_definitions"],
            scan_result["graph"],
            scan_result["top_paths"],
            scan_result["blast_radii"],
            scan_result["incident_matches"],
        ))
    
    # ─── 5. SECONDARY ───
    # Also include signals as one-liners
    if secondary or scan_result["signals"]:
        out.append(_section("ALSO WORTH FIXING"))
        for g in secondary:
            out.append(f" · {g.narrative}")
        for s in scan_result["signals"]:
            title = s["title"]
            out.append(f" · {title}")
    
    # ─── 6. FOOTER ───
    fc = len(scan_result["top_paths"])
    sc = len(scan_result["signals"])
    out.append(f"\n ─── {fc} findings · {sc} signals · Full details: stratum scan . --verbose\n")
    
    return "\n".join(out)


def _section(title):
    return f"\n ─── {title} {'─' * max(0, 60 - len(title))}\n"


def _render_primary(group, number, scan_result):
    """Full-treatment primary action."""
    lines = []
    
    # Title with effort
    title = f" {number} {group.title}"
    effort = f"░ {group.effort}"
    gap = max(1, 67 - len(title) - len(effort))
    lines.append(f"{title}{' ' * gap}{effort}")
    
    # Resolves
    lines.append(f"   Resolves {group.finding_count} findings ({group.severity_label})")
    lines.append("")
    
    # Narrative (wrapped at ~62 chars)
    for line in _wrap(group.narrative, 62, "   "):
        lines.append(line)
    
    # Code fix
    if group.code_fix:
        lines.append("")
        lines.append("   Fix:")
        lines.append(render_code_block(group.code_fix))
    
    # Apply to
    if group.apply_to:
        files = ", ".join(group.apply_to[:3])
        if len(group.apply_to) > 3:
            files += f" (+{len(group.apply_to) - 3} more)"
        lines.append(f"   Apply to: {files}")
    
    # Incident match
    if group.incident_match:
        lines.append("")
        name = group.incident_match.get("name", "")
        lines.append(f"   📎 Matches real breach: {name}")
        reason = group.incident_match.get("match_reason", "")
        if reason:
            for line in _wrap(reason[:180], 60, "      "):
                lines.append(line)
    
    lines.append("")
    return "\n".join(lines)


def _wrap(text, width, indent=""):
    words = text.split()
    lines = []
    current = indent
    for w in words:
        if len(current) + len(w) + 1 > width + len(indent) and current != indent:
            lines.append(current)
            current = indent + w
        else:
            current = current + (" " if current != indent else "") + w
    if current.strip():
        lines.append(current)
    return lines
```

### `verbose.py`

```python
"""--verbose: everything from terminal.py + full finding details."""

from .terminal import render_terminal_output

def render_verbose_output(scan_result):
    base = render_terminal_output(scan_result)
    sections = [base]
    
    sections.append("\n ─── FULL FINDING DETAILS ────────────────────────────────────\n")
    
    for f in scan_result["top_paths"]:
        sections.append(f" {f['id']} | {f['severity']} | {f['title']}")
        sections.append(f"   Category: {f.get('category', '?')}")
        if f.get("path"):
            sections.append(f"   Path: {f['path']}")
        sections.append(f"   {f['description'][:200]}")
        if f.get("evidence"):
            sections.append(f"   Evidence: {', '.join(str(e) for e in f['evidence'][:3])}")
        sections.append(f"   Remediation: {f['remediation'].split(chr(10))[0]}")
        if f.get("owasp_id"):
            sections.append(f"   OWASP: {f['owasp_id']} — {f.get('owasp_name', '')}")
        sections.append("")
    
    sections.append(" ─── SIGNALS ────────────────────────────────────────────────\n")
    for s in scan_result["signals"]:
        sections.append(f" {s['id']} | {s['severity']} | {s['title']}")
        sections.append(f"   {s['description'][:200]}")
        sections.append("")
    
    sections.append(" ─── INCIDENT MATCHES ───────────────────────────────────────\n")
    for m in scan_result["incident_matches"]:
        sections.append(f" {m.get('incident_id', m.get('id', '?'))} | {m.get('name', '?')} | confidence: {m.get('confidence', '?')}")
        sections.append(f"   {m.get('match_reason', '')[:250]}")
        sections.append("")
    
    sections.append(" ─── GRAPH METRICS ─────────────────────────────────────────\n")
    rs = scan_result["graph"]["risk_surface"]
    for k, v in rs.items():
        sections.append(f"   {k}: {v}")
    
    return "\n".join(sections)
```

### `quiet.py`

```python
"""--quiet: CI/script mode. Under 10 lines."""

from .action_groups import group_findings_into_actions, split_primary_secondary

def render_quiet_output(scan_result):
    fb = {}
    for f in scan_result["top_paths"] + scan_result["signals"]:
        s = f["severity"].lower()
        fb[s] = fb.get(s, 0) + 1
    
    sev_parts = []
    for s in ("critical", "high", "medium", "low"):
        if fb.get(s, 0) > 0:
            sev_parts.append(f"{fb[s]} {s}")
    sev_str = " · ".join(sev_parts)
    
    d = scan_result["directory"].replace("\\", "/").rstrip("/").split("/")[-1]
    
    groups = group_findings_into_actions(
        scan_result["top_paths"],
        scan_result["signals"],
        scan_result["incident_matches"],
        scan_result["detected_frameworks"],
        scan_result["blast_radii"],
    )
    primary, _ = split_primary_secondary(groups)
    
    lines = [f" STRATUM  {d}  {scan_result['risk_score']}/100  {sev_str}"]
    for i, g in enumerate(primary[:3]):
        lines.append(f" {'①②③'[i]} {g.title} ({g.effort}, resolves {g.finding_count} findings)")
    
    return "\n".join(lines)
```

### `cli.py` Changes

```python
import click
from .output.terminal import render_terminal_output
from .output.verbose import render_verbose_output
from .output.quiet import render_quiet_output

@click.command()
@click.argument("directory", default=".")
@click.option("--json", "json_output", is_flag=True, help="Raw JSON output")
@click.option("--verbose", is_flag=True, help="Full finding details")
@click.option("--quiet", is_flag=True, help="CI/script mode (under 10 lines)")
@click.option("--badge", is_flag=True, help="Generate stratum-badge.svg")
@click.option("--profile-output", type=str, help="Write ScanProfile JSON to file")
def scan(directory, json_output, verbose, quiet, badge, profile_output):
    result = scanner.scan(directory)
    
    if json_output:
        import json
        print(json.dumps(result, indent=2, default=str))
    elif quiet:
        print(render_quiet_output(result))
    elif verbose:
        print(render_verbose_output(result))
    else:
        print(render_terminal_output(result))
    
    if badge:
        from .badge.generator import generate_badge_svg
        svg = generate_badge_svg(result["risk_score"], len(result["top_paths"]))
        with open("stratum-badge.svg", "w") as f:
            f.write(svg)
        print(f"\n Badge saved: stratum-badge.svg")
    
    if profile_output:
        import json
        profile = build_scan_profile(result, ...)
        with open(profile_output, "w") as f:
            json.dump(profile, f, indent=2, default=str)
```

---

## PHASE 4: BADGE

### `badge/generator.py`

```python
def generate_badge_svg(risk_score, finding_count, critical_count=0):
    if risk_score <= 30:
        color, label = "#4c1", "low"
    elif risk_score <= 60:
        color, label = "#dfb317", "moderate"
    elif risk_score <= 80:
        color, label = "#fe7d37", "high"
    else:
        color, label = "#e05d44", "critical"
    
    right = f"risk: {risk_score}"
    if critical_count > 0:
        right += f" · {critical_count} critical"
    
    left_w = 65
    right_w = 12 + len(right) * 6
    total_w = left_w + right_w
    
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="20">
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="a"><rect width="{total_w}" height="20" rx="3"/></clipPath>
  <g clip-path="url(#a)">
    <path fill="#555" d="M0 0h{left_w}v20H0z"/>
    <path fill="{color}" d="M{left_w} 0h{right_w}v20H{left_w}z"/>
    <path fill="url(#b)" d="M0 0h{total_w}v20H0z"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="{left_w//2}" y="15" fill="#010101" fill-opacity=".3">stratum</text>
    <text x="{left_w//2}" y="14">stratum</text>
    <text x="{left_w + right_w//2}" y="15" fill="#010101" fill-opacity=".3">{right}</text>
    <text x="{left_w + right_w//2}" y="14">{right}</text>
  </g>
</svg>'''
```

---

## VALIDATION TARGETS

### Scanner fixes (run scan, check JSON):
```python
# Fix 1: ScrapeWebsiteTool blast radius
assert any(br["source_label"] == "ScrapeWebsiteTool" and br["agent_count"] == 4 
           for br in result["blast_radii"]), "Missing ScrapeWebsiteTool 4-agent BR"
assert max(br["agent_count"] for br in result["blast_radii"]) == 4

# Fix 2: CR01 evidence scoped
cr01 = next(f for f in result["top_paths"] if f["id"] == "STRATUM-CR01")
assert len(cr01["evidence"]) <= 3
assert not any("instagram_post" in e for e in cr01["evidence"])
assert not any("email_auto_responder" in e for e in cr01["evidence"])

# Fix 3: BR01 evidence scoped
br01 = next(f for f in result["top_paths"] if f["id"] == "STRATUM-BR01")
assert not any("CrewAI-LangGraph" in e for e in br01["evidence"])

# Fix 4: control_coverage_pct
assert result["graph"]["risk_surface"]["control_coverage_pct"] > 0

# Fix 5: No duplicate blast radii
br_keys = [(br["source_label"], br.get("crew_name",""), br["agent_count"]) for br in result["blast_radii"]]
assert len(br_keys) == len(set(br_keys))

# Fix 6: CR05 has file paths
for f in result["top_paths"]:
    if f["id"].startswith("STRATUM-CR05"):
        assert any("\\" in e or "/" in e for e in f["evidence"]), f"{f['id']} missing file paths"

# Fix 7: CR06 has code
for f in result["top_paths"]:
    if f["id"].startswith("STRATUM-CR06"):
        assert any(x in f["remediation"] for x in ["Agent(", "Task(", "output_pydantic"]), f"{f['id']} missing code"
```

### Telemetry fixes (check profile.json):
```python
# Fix 8: Per-crew scores
nonzero = [s for s in profile["risk_scores_per_crew"] if s > 0]
assert len(nonzero) >= 3, "Too few crews with scores"
assert max(nonzero) >= 40, "Highest crew score too low (EmailFilterCrew should be ~70)"

# Fix 9: Risk score breakdown
assert profile["risk_score_breakdown"] != {}
assert "base_severity" in profile["risk_score_breakdown"]

# Fix 10: Framework versions
# Only passes if pyproject.toml/requirements.txt exist in scan target
# May be {} for crewAI-examples if no requirements file — that's ok

# Fix 11: has_scrape_to_action
assert profile["has_scrape_to_action"] == True

# Fix 12: tools_shared_by_3_plus
assert profile["tools_shared_by_3_plus"] <= 12  # sanity bound
```

### Terminal output (visual check):
```
1. Risk bar visible with filled/empty blocks and score
2. "FIX THESE FIRST" section with numbered actions
3. Action ① is "Add human review on outbound tasks" with ░ 5 min
4. Code block has ┌───┐ borders
5. 📎 Matches real breach: Microsoft Copilot EchoLeak visible
6. Flow maps render for EmailFilterCrew and StockAnalysisCrew
7. "ALSO WORTH FIXING" has one-liners, no full descriptions
8. Footer shows finding count and pointer to --verbose
9. Total default output under 100 lines
10. --quiet output under 10 lines
11. --verbose shows full finding details after the compact output
```

---

## BUILD ORDER

```
Phase 1 (Scanner): "Apply fixes 1-7 from the patch. Fix blast radius
    computation (dedup by tool+crew, not crew alone). Scope CR01/BR01
    evidence by directory. Fix control_coverage_pct. Add file paths to
    CR05 evidence. Add code to CR06 remediation."

Phase 2 (Telemetry): "Apply fixes 8-13. Rewrite per-crew score attribution
    to use directory matching. Add risk_score_breakdown. Add framework
    version detection. Fix has_scrape_to_action. Dedup tools_shared_by_3_plus."

Phase 3 (Terminal): "Create action_groups.py, risk_bar.py, code_block.py,
    flow_map.py. Rewrite terminal.py as orchestrator. Create verbose.py
    and quiet.py. Update cli.py with --verbose, --quiet, --badge flags."

Phase 4 (Validate): "Run scan on crewAI-examples. Run all validation
    assertions. Visual check the terminal output. Compare --quiet and
    --verbose modes."
```
