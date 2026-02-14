# STRATUM PATCH v4

## What A+ actually means

A+ isn't "bugs fixed." A+ is three behavior loops working without friction.

**Loop 1 (indie):** Scan → react → fix → rescan → feel progress → integrate into CI → tell someone.
**Loop 2 (enterprise):** Batch scan → fleet report → cold email → CISO sees something new → replies → pilot.
**Loop 3 (telemetry):** Ship → measure → learn → decide → ship better.

Every item in this patch exists because it makes one of these loops work. Nothing is included because it's "nice to have."

---

# LOOP 1: THE INDIE DEVELOPER

The developer's journey has 6 steps. Today, steps 1, 3, and 4 are broken, and step 4 doesn't exist at all.

## Step 1: First scan — must be correct

Three bugs make the scanner look wrong about the developer's own code. A developer who knows their codebase will notice immediately.

### 1A. Blast radius scoped to project, not crew

**What the developer sees:** "Activity Planner is shared by 56 agents in SurpriseTravelCrew."

**What they know:** SurpriseTravelCrew has 3 agents. Their code. They wrote it.

**What they think:** "This tool doesn't understand my project." They stop reading.

This is the first thing in the first finding in the default output. If this number is wrong, nothing else matters.

**Root cause:** `_calculate_blast_radius` iterates all agents globally, not per-crew.

**Fix:**

```python
def _calculate_blast_radius(tool_name, agent_definitions, crew_definitions):
    results = []
    for crew in crew_definitions:
        crew_agent_names = set(crew['agent_names'])
        crew_agents_with_tool = [
            a for a in agent_definitions
            if a['name'] in crew_agent_names and tool_name in a['tool_names']
        ]
        if len(crew_agents_with_tool) >= 2:
            results.append({
                'tool': tool_name,
                'crew': crew['name'],
                'agent_count': len(crew_agents_with_tool),
                'agent_names': [a['name'] for a in crew_agents_with_tool],
            })
    return results
```

Every downstream consumer — narrative templates, profile `blast_radii`, finding evidence — must use the per-crew count.

### 1B. Per-crew risk scores are all zero

**What the developer sees (verbose):**

```
SurpriseTravelCrew: 0/100
EmailFilterCrew:    0/100
StockAnalysisCrew:  0/100
```

**What the scanner just told them:** These crews have critical blast radius findings, unguarded email paths, and shared tool vulnerabilities.

**What they think:** "The scores don't match the findings. Which one is wrong?"

**Root cause:** Findings don't carry a `crew_id`. Per-crew scoring has nothing to sum.

**Fix:** Every finding generated in the per-crew analysis phase must tag itself with the crew it was detected in.

```python
def _generate_finding(finding_id, severity, category, crew_name=None, **kwargs):
    return {
        'id': finding_id,
        'severity': severity,
        'category': category,
        'crew_id': crew_name,    # Which crew, or None for project-level
        **kwargs,
    }
```

Per-crew scoring:

```python
SEVERITY_WEIGHT = {'critical': 15, 'high': 10, 'medium': 5, 'low': 2}

def _score_crew(crew_name, all_findings):
    crew_findings = [f for f in all_findings if f.get('crew_id') == crew_name]
    return min(100, sum(SEVERITY_WEIGHT[f['severity']] for f in crew_findings))
```

### 1C. Score = 0 with findings present

**What happens:** JoshuaC215/agent-service-toolkit: 18 agents, 8 findings, score 0. A VP Eng seeing this in a fleet report says "your scoring is broken."

**Root cause:** Either all findings are info-severity (contributing 0 to raw score) or maturity credits drive the score below zero and it clamps.

**Fix:** If any finding with severity ≥ low exists, score has a floor.

```python
def _finalize_score(raw_score, findings):
    has_real_findings = any(f['severity'] in ('critical','high','medium','low') for f in findings)
    if has_real_findings:
        floor = max(8, len([f for f in findings if f['severity'] != 'info']) * 2)
        return max(floor, min(raw_score, 100))
    return max(0, min(raw_score, 100))
```

8 findings × 2 = floor of 16. Not 0. Simple, defensible.

---

## Step 2: React — must be emotional

The developer needs to feel "oh shit" or "oh, I didn't know that." This requires (a) the flow map showing them something they didn't realize about their own architecture, and (b) the attack narrative being about THEIR code, not a generic pattern.

### 2A. Flow map must come first and must show data flow, not just agent sequence

**The current terminal layout:**

```
Line 1-6:   Header
Line 7-11:  Risk score bar
Line 12-80: Findings ("FIX THESE FIRST")
Line 82+:   Flow maps ("WHAT YOUR AGENTS LOOK LIKE")
```

The developer never sees the flow map without scrolling past all findings. This is the opposite of the v3 reframe. The flow map is the hook — it's what makes someone who wasn't worried about security suddenly see their architecture and think "wait, that agent sends WHERE?"

**The new terminal layout:**

```
Line 1-6:   Header
Line 7+:    Flow maps ("YOUR AGENT ARCHITECTURE")
            → Show 4 most interesting crews (by finding count, then outbound capability)
            → "+N more crews (stratum scan . --verbose to see all)"
After maps: Risk score bar
Then:       Findings ("FIX THESE FIRST" — top 3 action groups)
Then:       Hygiene ("ALSO WORTH FIXING")
Then:       Footer (totals, --verbose CTA, --fix CTA)
```

**But the current flow maps are too simple to create the "oh" moment.** They show:

```
researcher ──▶ matcher ──▶ communica.. ──▶ reporter
```

That's just agent names in a line. The developer already knows their agents run in sequence. There's no new information.

The v3 spec showed something much richer — tool connections and external service endpoints visible inside the box:

```
EmailFilterCrew (3 agents, sequential)                    38/100
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│  email_categorizer ──▶ email_filter ──▶ email_responder     │
│   │                     │                 │                  │
│   ├─ GmailGetThread     ├─ SerperDevTool  ├─ ✉ Gmail send   │
│   └─ GmailSearch        └─ WebScraper     └─ 💬 Slack post  │
│                                                              │
│  ⚠ email_responder sends to Gmail & Slack with no review    │
└──────────────────────────────────────────────────────────────┘
```

This flow map tells the developer: "Your email_responder agent has Gmail send AND Slack post capabilities, and there's no human review between the inbox read and the outbound send." That's the "oh shit" moment. They didn't realize the responder had both outbound paths.

**The difference:** The current flow map confirms what they know (agents run in sequence). The rich flow map reveals what they didn't realize (which agents have outbound access and where data flows to external services).

**Implementation:**

```python
def _render_crew_flowmap(crew, agents, findings, capabilities):
    lines = []
    crew_score = _score_crew(crew['name'], findings)
    lines.append(f" {crew['name']} ({len(crew['agent_names'])} agents, {crew['process_type']})  {crew_score}/100")
    lines.append(" ┌" + "─" * 60 + "┐")
    
    # Agent pipeline row
    agent_chain = " ──▶ ".join(_truncate(name, 14) for name in crew['agent_names'])
    lines.append(f" │  {agent_chain}")
    
    # Per-agent tool/capability rows — ONLY for agents with external tools
    for agent_name in crew['agent_names']:
        agent = _find_agent(agent_name, agents)
        outbound_tools = [t for t in agent.get('tool_names', []) 
                         if _is_outbound(t, capabilities)]
        data_tools = [t for t in agent.get('tool_names', [])
                     if _is_data_source(t, capabilities)]
        
        if outbound_tools or data_tools:
            # Show tool tree under this agent
            tool_lines = []
            for t in data_tools:
                tool_lines.append(f"├─ {t}")
            for t in outbound_tools:
                icon = _get_service_icon(t)  # ✉ for email, 💬 for slack, 🌐 for HTTP
                tool_lines.append(f"├─ {icon} {_get_external_dest(t)}")
            
            # Indent to align under agent name
            indent = " │  " + " " * _get_agent_offset(agent_name, crew['agent_names'])
            for tl in tool_lines:
                lines.append(f"{indent}{tl}")
    
    # Warning annotation if crew has critical/high findings
    crew_findings = [f for f in findings if f.get('crew_id') == crew['name']
                     and f['severity'] in ('critical', 'high')]
    if crew_findings:
        top = crew_findings[0]
        lines.append(f" │  ⚠ {_one_line_warning(top)}")
    
    lines.append(" └" + "─" * 60 + "┘")
    return lines
```

**What this changes for the first-screen experience:** The developer opens their terminal and sees their agent architecture with external service connections annotated. They see ⚠ warnings on crews that have unreviewed outbound paths. They see per-crew scores that correspond to the severity of issues in each crew. THEN they scroll down to see the specific findings and fix instructions.

**Crew selection for default output:** Show the 4 crews with the highest per-crew risk scores. These are the crews with the most interesting architecture and the most critical findings — the ones that create the "oh" moment. Crews with score 0 and no external tools (like `starter_template`) don't appear in default output.

```python
def _select_display_crews(crews, findings, max_display=4):
    scored = []
    for crew in crews:
        crew_score = _score_crew(crew['name'], findings)
        scored.append((crew_score, crew))
    scored.sort(key=lambda x: -x[0])
    
    # Show top crews by risk, but at least 1 even if all score 0
    display = [crew for score, crew in scored[:max_display] if score > 0]
    if not display and scored:
        display = [scored[0][1]]
    return display
```

### 2B. Breach narrative must match the finding, not the project

**Current bug:** Finding ① is about CR05 (shared tool blast radius). But its breach match describes a Gmail-to-external pattern (STRATUM-001's breach). The narrative templates are pulling project-level breach matches and attaching them to action groups regardless of which finding the action group addresses.

**Fix:** Each finding type maps to specific breach patterns. The action group uses the breach match from its primary finding, not from the project.

```python
FINDING_BREACH_MAP = {
    'STRATUM-001':  ['ECHOLEAK-2025', 'SLACK-AI-EXFIL-2024'],
    'STRATUM-002':  ['DOCKER-GORDON-2025'],
    'STRATUM-CR05': ['SERVICENOW-NOWASSIST-2025'],  # Shared resource → multi-agent compromise
    'STRATUM-CR06': [],                               # No known breach match — don't show section
    'STRATUM-BR01': ['ECHOLEAK-2025'],
}

def _get_breach_match_for_finding(finding_id):
    base_id = finding_id.split('.')[0]  # CR05.1 → CR05
    matched_ids = FINDING_BREACH_MAP.get(base_id, [])
    if not matched_ids:
        return None  # Don't show 📎 section
    return BREACH_DB[matched_ids[0]]
```

If no breach matches the finding, omit the 📎 section entirely. Showing no breach is better than showing the wrong one.

### 2C. Separate architecture findings from hygiene findings

**The problem:** A project's "17 findings" includes BR03 (no audit trail), BR04 (no cost controls), OP02 (no human oversight), TELEMETRY-003 (no observability) — findings that fire on literally every project. The finding count is inflated. When everything is a finding, nothing is.

**The fix is already partially implemented** — the "Also Worth Fixing" section at the bottom of the default output. But the header still says "13 findings total" without distinguishing types.

**Change the header to:**

```
7 architecture risks · 6 operational recommendations
```

And add `findings_by_class` to the profile:

```python
FINDING_CLASS = {
    # Architecture — specific to this project's code structure
    'STRATUM-001': 'architecture',
    'STRATUM-002': 'architecture',
    'STRATUM-003': 'architecture',
    'STRATUM-CR01': 'architecture',
    'STRATUM-CR02': 'architecture',
    'STRATUM-CR05': 'architecture',
    'STRATUM-CR06': 'architecture',
    'STRATUM-BR01': 'architecture',
    'STRATUM-BR02': 'architecture',
    
    # Operational — code-specific but lower urgency
    'STRATUM-007': 'operational',
    'STRATUM-008': 'operational',
    'STRATUM-009': 'operational',
    'STRATUM-010': 'operational',
    
    # Hygiene — fire on almost every project
    'STRATUM-BR03': 'hygiene',
    'STRATUM-BR04': 'hygiene',
    'STRATUM-OP01': 'hygiene',
    'STRATUM-OP02': 'hygiene',
    'TELEMETRY-003': 'hygiene',
    
    # Meta — scanner observations, not risks
    'CONTEXT-001': 'meta', 'CONTEXT-002': 'meta',
    'IDENTITY-001': 'meta', 'IDENTITY-002': 'meta',
    'ENV-001': 'meta', 'ENV-002': 'meta',
}
```

**In the fleet report:** Only count architecture + operational findings. "ACME has 23 architecture risks across 8 projects" is credible. "ACME has 47 findings" when 24 are hygiene is discoverable and embarrassing.

---

## Step 3: Fix — must be easy AND must resolve what it promises

### 3A. Auto-fix must resolve STRATUM-001 and BR01

**The core problem:** `--fix` adds `human_input=True` to Task() calls. The STRATUM-001 finding rule checks for unguarded data-to-external paths. But the rule doesn't recognize `human_input=True` as a guardrail on the path.

There are two things that must both be true:

**(1) The guardrail detector must recognize `human_input=True`.**

```python
def _detect_guardrails(tree, source_file):
    guardrails = []
    for node in ast.walk(tree):
        # NEW: CrewAI human_input=True on Task()
        if isinstance(node, ast.Call) and _is_task_call(node):
            for kw in node.keywords:
                if kw.arg == 'human_input' and _is_true_literal(kw.value):
                    guardrails.append({
                        'kind': 'hitl',
                        'source_file': source_file,
                        'line_number': node.lineno,
                        'detail': 'human_input=True on Task',
                        'scope': 'task',
                        'task_var': _get_assignment_target(node),
                    })
        
        # NEW: LangGraph interrupt_before on compile()
        if isinstance(node, ast.Call) and _is_compile_call(node):
            for kw in node.keywords:
                if kw.arg == 'interrupt_before':
                    guardrails.append({
                        'kind': 'hitl',
                        'source_file': source_file,
                        'line_number': node.lineno,
                        'detail': 'interrupt_before on compile()',
                        'scope': 'graph',
                        'interrupt_nodes': _extract_list_values(kw.value),
                    })
    return guardrails
```

**(2) The STRATUM-001 path analysis must check guardrail coverage.**

```python
def _find_unguarded_data_external_paths(graph, guardrails):
    all_paths = _find_data_to_external_paths(graph)
    unguarded = []
    
    for path in all_paths:
        # Does any HITL guardrail cover a node in this path?
        path_agents = set(path['agent_names'])
        guarded = False
        for g in guardrails:
            if g['kind'] != 'hitl':
                continue
            # Task-level: check if the task's agent is in the path
            if g['scope'] == 'task':
                task_agent = _resolve_task_to_agent(g, graph)
                if task_agent in path_agents:
                    guarded = True
                    break
            # Graph-level: check if any interrupt node is in the path
            if g['scope'] == 'graph':
                if set(g.get('interrupt_nodes', [])) & path_agents:
                    guarded = True
                    break
        
        if not guarded:
            unguarded.append(path)
    
    return unguarded
```

**After both fixes:** Run `--fix` → human_input=True added to tasks with outbound tools → rescan → guardrail detector sees human_input=True → path analysis filters guarded paths → STRATUM-001 and BR01 don't fire if all paths are guarded.

**Partial resolution:** If 10 of 12 paths are guarded but 2 remain (in files `--fix` couldn't patch), the finding fires with reduced scope AND shows the progress:

```
② Unguarded data-to-external path (2 paths)            ░ 5 min
   ↓ was 12 paths — 10 fixed by --fix

   Your EmailFilterCrew reads Gmail inbox and sends to
   Gmail outbound with no human check on 2 remaining tasks.

   Fix manually in:
     email_filter_crew.py:47 — add human_input=True
     auto_responder.py:23   — add human_input=True
```

The developer sees progress (12→2), not the same finding restated.

### 3B. Auto-fix CTA only on findings that are auto-fixable

**Current:** Global CTA says "Run stratum scan . --fix to auto-fix 5 findings" without specifying which 5. Per-finding CTAs on action groups don't distinguish fixable from non-fixable.

**Fix:** Mark which action groups are auto-fixable. Only show "→ Or run: stratum scan . --fix" on action groups whose primary findings are in the auto-fixable set.

```python
AUTO_FIXABLE = {'STRATUM-001', 'STRATUM-002', 'STRATUM-BR01', 'STRATUM-008', 'STRATUM-009'}

def _render_action_group(group):
    # ... render description, narrative, code fix ...
    
    finding_ids = set(f['id'].split('.')[0] for f in group['findings'])
    if finding_ids & AUTO_FIXABLE:
        fixable_count = len(finding_ids & AUTO_FIXABLE)
        print(f"   → Or run: stratum scan . --fix  ({fixable_count} auto-fixable)")
```

Global footer counts only auto-fixable:

```
→ Run stratum scan . --fix to auto-fix 5 of 13 findings
```

"5 of 13" is honest. "5" alone implies all findings are fixable.

### 3C. Add STRATUM-008 auto-fix (try/except wrapper)

v3 deferred STRATUM-008 auto-fix because generating smart fallback logic is hard. But you don't need smart fallback. You need crash prevention:

```python
# Auto-fix for STRATUM-008:
# Find the function containing the unhandled external call
# Wrap the function body in try/except

# BEFORE:
def search_tool(query: str) -> str:
    response = requests.get(f"https://api.serper.dev/search?q={query}")
    return response.json()

# AFTER:
def search_tool(query: str) -> str:
    try:
        response = requests.get(f"https://api.serper.dev/search?q={query}")
        return response.json()
    except Exception as e:
        return f"Tool error: {type(e).__name__}: {e}"
```

This prevents the crash (the primary risk). The agent receives an error string instead of a stack trace and decides what to do. The developer can refine later.

**Implementation constraint:** Only wrap functions identified in the finding's evidence (file + line number). Don't wrap every function in the project.

**After adding 008:** Auto-fixable findings = 001, 002, BR01, 008, 009. On crewAI-examples, this covers ~8 of 13 architecture findings. Expected score drop: 69 → ~25.

---

## Step 4: Rescan — must show progress

**This step doesn't exist today.** The developer applies the patch, rescans, and sees... the same terminal layout with new numbers. No delta. No celebration. No acknowledgment that anything improved. The satisfaction moment — "that worked, my project is safer now" — never happens.

This is the Snyk merge-PR-and-see-green-checkmark moment. It's what makes the developer think "this tool actually works" and integrate it into CI.

**The rescan must detect it's a rescan and show the diff.**

The data already exists. The profile has `has_previous_scan`, `previous_risk_score`, `risk_score_delta`, `new_finding_ids`, `resolved_finding_ids`. These fields are populated in the JSON but never rendered in the terminal.

**Rescan terminal header:**

```
 ╔═══════════════════════════════════════════════════════════╗
 ║  STRATUM SCAN                                             ║
 ║  crewAI-examples · 116 files · 30 crews · 56 agents      ║
 ╚═══════════════════════════════════════════════════════════╝

 RISK SCORE ██████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  34 / 100
            ▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔
            ↓35 points (was 69)

 ─── RESOLVED SINCE LAST SCAN ───────────────────────────────

  ✓ STRATUM-001  Unguarded data-to-external path — RESOLVED
  ✓ STRATUM-002  Destructive tool with no gate — RESOLVED
  ✓ STRATUM-009  No timeout on HTTP calls — RESOLVED
  ✓ STRATUM-BR01 External messages without review — RESOLVED
  ✓ STRATUM-008  No error handling — RESOLVED (29 functions wrapped)

  5 findings resolved · 0 new · 8 remaining
```

**Implementation:**

```python
def _render_rescan_header(current_profile, previous_profile):
    if not current_profile.get('has_previous_scan'):
        return  # First scan, no delta to show
    
    prev_score = current_profile['previous_risk_score']
    curr_score = current_profile['risk_score']
    delta = current_profile['risk_score_delta']
    
    resolved = current_profile.get('resolved_finding_ids', [])
    new_findings = current_profile.get('new_finding_ids', [])
    
    if delta < 0:  # Score improved
        print(f" ↓{abs(delta)} points (was {prev_score})")
        print()
        if resolved:
            print(" ─── RESOLVED SINCE LAST SCAN ─────────────────────")
            for fid in resolved:
                title = FINDING_TITLES.get(fid, fid)
                print(f"  ✓ {fid}  {title} — RESOLVED")
            print()
            remaining = current_profile['finding_count']
            print(f"  {len(resolved)} resolved · {len(new_findings)} new · {remaining} remaining")
    
    elif delta > 0:  # Score worsened
        print(f" ↑{delta} points (was {prev_score})")
        if new_findings:
            print(" ─── NEW SINCE LAST SCAN ──────────────────────────")
            for fid in new_findings:
                title = FINDING_TITLES.get(fid, fid)
                print(f"  ⚠ {fid}  {title} — NEW")
    
    else:
        print(f" No change (score: {curr_score})")
```

**This is the single most important missing feature for indie PMF.** Without the rescan delta, the developer has no feedback on whether their work mattered. With it, they see green checkmarks next to the findings they fixed. That's the dopamine hit that makes them add the GitHub Action.

---

## Step 5 & 6: Integrate and share

These depend on steps 1-4 working. The GitHub Action and badge are already specified in v3. No changes needed — they just need the foundation to be solid.

One addition: **The GitHub Action PR comment should also show the delta** when it detects a previous scan in the repo's `.stratum/history.jsonl`:

```markdown
## Stratum Scan Results

**Score: 34/100** (↓35 from previous scan)

✓ 5 findings resolved | 0 new | 8 remaining

| Finding | Status |
|---------|--------|
| STRATUM-001 Unguarded data path | ✅ Resolved |
| STRATUM-002 Destructive no gate | ✅ Resolved |
| STRATUM-CR05 Shared tool blast radius | ⚠️ Open |
```

---

# LOOP 2: THE ENTERPRISE CISO

The CISO receives a fleet report PDF. They need to see ONE thing they didn't know. If every insight in the report is obvious ("your agents have risks"), they don't reply to the email. If one insight is surprising ("6 of your 8 projects depend on a single LLM provider"), they reply.

## The fleet-level insight that no other tool provides

Three insights are unique to Stratum because they require cross-project topology:

**Insight 1: Provider concentration.** "6 of 8 projects depend on gpt-4o. If OpenAI has a 4-hour outage, 75% of your AI fleet is down." No security scanner tells you this. It requires scanning multiple repos and correlating LLM model usage.

**Insight 2: Shared service coupling.** "3 projects share the same Postgres database (DATABASE_URL). A prompt injection in any of them compromises the others' data." This comes from env_var_names_specific overlap detection.

**Insight 3: Breach pattern prevalence.** "5 of 8 projects match the architecture pattern that caused the EchoLeak breach. Here are the specific code paths." This combines per-project incident matching with fleet-level aggregation.

These three insights require the connectable surfaces that Sprint 1 built. But they're not making it into the fleet report because of two gaps.

## Gap 1: Batch output is missing connectable surfaces

batch-results.json has `frameworks` per repo but not `llm_models`, `env_var_names_specific`, or `vector_stores`. The fleet report can't generate the model dependency page or shared service map.

**Fix:** The batch pipeline already generates full profiles. The batch output just needs to carry the connectable fields through.

```python
def _batch_record(profile):
    return {
        # Existing
        'repo': profile['repo_url'],
        'org': profile['org_id'],
        'project_name': profile['project_name'],
        'risk_score': profile['risk_score'],
        'finding_count': profile['finding_count'],
        'agent_count': profile['agent_count'],
        'frameworks': profile['frameworks'],
        'parse_quality': profile['framework_parse_quality'],
        
        # ADD THESE — they're already in the profile
        'llm_models': profile.get('llm_models', []),
        'llm_providers': profile.get('llm_providers', []),
        'has_multiple_providers': profile.get('has_multiple_providers', False),
        'env_var_names_specific': profile.get('env_var_names_specific', []),
        'vector_stores': profile.get('vector_stores', []),
        'incident_matches': profile.get('incident_matches', []),
        'what_if_controls': profile.get('what_if_controls', []),
        'finding_ids': profile.get('finding_ids', []),
        'findings_by_severity': profile.get('findings_by_severity', {}),
        'findings_by_class': profile.get('findings_by_class', {}),
    }
```

## Gap 2: Batch discovery doesn't find multi-repo orgs

10 repos from 10 different orgs. Zero fleet stories possible.

**Fix:** Two-phase discovery.

Phase 1: Broad search (existing) finds repos across GitHub.

Phase 2: For every org that appears 2+ times in phase 1, fetch ALL that org's repos and scan them for agent framework imports. Also seed with known multi-repo orgs.

```python
SEED_ORGS = [
    'langchain-ai',   # 50+ repos, many with LangGraph/LangChain
    'crewAIInc',      # 20+ repos
    'run-llama',      # LlamaIndex repos
    'microsoft',      # AutoGen and semantic-kernel
    'anthropics',     # Agent examples
    'huggingface',    # SmolAgents
    'phidatahq',      # Phidata agent repos
]

def discover_clustered(github_token):
    # Phase 1
    repos_by_org = _broad_search(github_token)
    
    # Phase 2
    multi_orgs = [org for org, repos in repos_by_org.items() if len(repos) >= 2]
    target_orgs = set(multi_orgs) | set(SEED_ORGS)
    
    for org in target_orgs:
        for repo in _fetch_org_repos(org, github_token):
            if _quick_check_for_agent_imports(repo, github_token):
                repos_by_org.setdefault(org, []).append(repo)
    
    return repos_by_org
```

## Gap 3: Score calibration undermines credibility

60% of batch repos score 80+. The mean is 70, the median is 83. If almost every project is "critical," the score loses meaning. A CISO who sees 7 of 8 projects scoring 80+ thinks "this tool just rates everything as bad."

**The problem isn't a bug — it's a formula calibration issue.** The severity weights are too high, and hygiene findings that fire everywhere inflate the raw score.

**Fix:** Recalibrate to target a roughly normal distribution centered around 50.

The key insight: **hygiene findings should contribute less to the score.** "No observability" is not the same severity as "unguarded data-to-external path," even if both are tagged "medium."

```python
# Severity weights by finding class
SCORE_WEIGHTS = {
    ('critical', 'architecture'): 12,
    ('high', 'architecture'):     8,
    ('medium', 'architecture'):   5,
    ('low', 'architecture'):      2,
    
    ('critical', 'operational'):  8,
    ('high', 'operational'):      5,
    ('medium', 'operational'):    3,
    ('low', 'operational'):       1,
    
    # Hygiene findings contribute minimally
    ('critical', 'hygiene'):      3,
    ('high', 'hygiene'):          2,
    ('medium', 'hygiene'):        1,
    ('low', 'hygiene'):           0,
    
    # Meta findings don't contribute at all
    ('critical', 'meta'):         0,
    ('high', 'meta'):             0,
    ('medium', 'meta'):           0,
    ('low', 'meta'):              0,
}

def _calculate_risk_score(findings):
    raw = 0
    for f in findings:
        cls = FINDING_CLASS.get(f['id'].split('.')[0], 'meta')
        weight = SCORE_WEIGHTS.get((f['severity'], cls), 0)
        raw += weight
    
    # Normalize: cap at 100, floor at 0 (or floor from Bug 1C)
    return min(100, raw)
```

**Expected effect:** A project with only hygiene findings (BR03, BR04, OP02, TELEMETRY-003) scores ~7/100, not 40+. A project with 3 critical architecture findings scores ~36. A project with 3 critical + 4 high architecture + 5 hygiene scores ~72. The distribution spreads out.

**The fleet report benefits directly:** "2 projects critical (80+), 3 high-risk (50-79), 3 moderate (20-49)" is a more useful distribution than "7 projects critical."

## Gap 4: Example repo detection

AgentOps-AI/agentops: 48 agents, 135 findings, 7 frameworks. This is a test/example suite, not production code. If it appears in a fleet report, the numbers are noise.

```python
def _is_example_repo(profile):
    return (
        len(profile.get('frameworks', [])) >= 4 or
        profile.get('finding_count', 0) > 80 or
        any(kw in profile.get('project_name', '').lower() 
            for kw in ('example', 'demo', 'tutorial', 'sample', 'test', 'starter'))
    )
```

Fleet report excludes example repos or shows them in a separate "test/example repositories" section with a note: "Excluded from fleet statistics."

## What the fleet report executive summary should say

After all fixes:

```
┌──────────────────────────────────────────────────────────┐
│  ACME Corp — AI Agent Fleet Assessment                   │
│                                                          │
│  8 agent projects · 47 agents · 3 frameworks             │
│  Fleet Risk Score: 52/100                                │
│                                                          │
│  ⚠ KEY FINDING: 6 of 8 projects depend on gpt-4o.      │
│    An OpenAI outage affects 75% of your AI fleet.        │
│    Your competitor using Anthropic + OpenAI survives.    │
│                                                          │
│  ⚠ 3 projects share DATABASE_URL credentials.           │
│    A prompt injection in one project compromises         │
│    the others' database access.                          │
│                                                          │
│  TOP ACTION: Add human review on outbound tasks          │
│  Resolves 11 architecture findings across 5 projects     │
│  (5 min per project)                                     │
│                                                          │
│  Next step: 15-minute walkthrough of your fleet risks.   │
│  Book at calendly.com/stratum/fleet-review               │
└──────────────────────────────────────────────────────────┘
```

The model dependency and shared credentials insights are the hooks. No other tool provides them. The "15 minutes" CTA is low commitment.

---

# LOOP 3: TELEMETRY

## The one field that blocks everything

`project_hash` is not in the UsagePing. This single omission blocks 4 of 6 critical queries:

1. **Rescan rate (PMF signal):** "What % of projects are scanned more than once?" Without project_hash, every scan is an island. You can count total scans but can't group them by project.

2. **Fix-to-retention:** "Do developers who use --fix come back at higher rates?" You need to compare rescan rates for project_hash values that have flags_used containing "fix" vs those that don't.

3. **Finding delta:** "Which finding categories drive behavior change?" You need two scans of the same project_hash to compute what changed.

4. **Terminal correlation:** "Does the output mode affect rescan rate?" You need to correlate output_mode with subsequent scans of the same project_hash.

**This is the difference between "1,000 people ran the scanner" and "340 people ran it twice and 180 improved their score."** The first is a vanity metric. The second is PMF. You can only compute the second with project_hash.

## The full UsagePing

```python
@dataclass
class UsagePing:
    # Identity
    project_hash: str       # hash(git remote) — THE critical field
    sig: str                # topology_signature for dedup
    scan_source: str        # "cli" | "github_action" | "gitlab_ci"
    
    # Scanner
    v: str                  # scanner version
    os: str                 # platform.system()
    py: str                 # platform.python_version()
    
    # Project
    fw: list[str]           # frameworks detected
    parse_quality: str      # full/partial/tools_only/empty
    agents: int
    crews: int
    files: int
    
    # Results
    findings: int           # total finding count
    arch_findings: int      # architecture class only (not inflated)
    max_sev: str            # highest severity
    score: int
    findings_by_cat: dict   # {security: 2, compounding: 5, ...}
    findings_by_class: dict # {architecture: 7, operational: 3, hygiene: 3}
    
    # Behavior
    flags_used: list[str]   # [fix, verbose, badge, quiet, json, ...]
    fix_count: int          # auto-fixes generated
    output_mode: str        # default/verbose/quiet/json
    duration_ms: int
    
    # Delta (if rescan)
    is_rescan: bool
    prev_score: int | None
    score_delta: int | None
    resolved_count: int | None
    new_count: int | None
    
    # Errors
    error: str | None       # error message if scan failed
    error_module: str | None # which module failed
```

**New in v4:** `arch_findings` (non-inflated count), `findings_by_class`, `is_rescan`, `prev_score`, `score_delta`, `resolved_count`, `new_count`. These enable queries the v3 spec couldn't support:

**Query 7: What's the average score improvement after --fix?**
```sql
SELECT AVG(score_delta) FROM pings 
WHERE is_rescan = true AND 'fix' = ANY(flags_used)
-- "Developers who use --fix improve by 28 points on average"
```

**Query 8: How many rescans until developers stop improving?**
```sql
SELECT scan_number, AVG(score_delta) FROM (
  SELECT project_hash, ROW_NUMBER() OVER (PARTITION BY project_hash ORDER BY ts) as scan_number, score_delta
  FROM pings WHERE is_rescan = true
) t GROUP BY scan_number
-- "Biggest improvement on scan 2, diminishing by scan 4"
```

**Query 9: Which finding class drives the most rescans?**
```sql
SELECT findings_by_class, COUNT(DISTINCT project_hash) FILTER (WHERE is_rescan) as rescan_count
FROM pings GROUP BY findings_by_class
-- "Projects with 3+ architecture findings rescan 2.4x more than hygiene-only"
```

## Phase transition signals

**Phase 1→2 (individual → team):** Detected when the upload API receives 3+ profiles with different `project_hash` values but the same `org_id`. Telemetry contribution: `scan_source` distinguishes CLI (individual) from GitHub Action (team process).

**Phase 2→3 (team → fleet):** Detected when connection validation (run on uploaded profiles per org) shows >40% cross-project overlap. Telemetry contribution: `findings_by_class` and `arch_findings` determine whether fleet-level insights are architecture-specific or just hygiene noise.

**Phase 3→4 (fleet → runtime):** Detected when a paying customer asks for runtime monitoring. No telemetry needed — it's a sales signal.

---

# CROSS-CUTTING: SCORE CALIBRATION

The score serves three masters: the terminal (indie motivation), the fleet report (enterprise credibility), and telemetry (measurement). If the score distribution is skewed (60% scoring 80+), it fails all three:

- **Indie:** "69/100" and "83/100" sound different but aren't — both are "you're bad like everyone else."
- **Enterprise:** 7 of 8 projects "critical" means the word "critical" means nothing.
- **Telemetry:** Score delta after --fix (69→48) sounds like improvement but if 48 is still "above average," the developer doesn't feel motivated.

The recalibration from Loop 2 (severity × class weighting) is the primary fix. But there's an additional element: **percentile benchmarking.**

Once the batch scan has 1,000+ profiles, every score can show its percentile:

```
RISK SCORE ██████████░░░░░░░░░░░░░░░░░░░  34 / 100
           Better than 71% of similar-sized projects
```

"34/100" is abstract. "Better than 71%" is concrete. And it self-calibrates: as the ecosystem improves, the percentile adjusts.

```python
def _get_percentile(score, agent_count, benchmark_data):
    # Bucket by project size
    if agent_count <= 3:
        bucket = benchmark_data['small']  # 1-3 agents
    elif agent_count <= 10:
        bucket = benchmark_data['medium']  # 4-10 agents
    else:
        bucket = benchmark_data['large']   # 10+ agents
    
    # Percentile: what % of projects score HIGHER (worse) than you
    worse_count = sum(1 for s in bucket if s > score)
    return round(worse_count / len(bucket) * 100)
```

This requires the batch scan data to be persisted and accessible. Sprint 5 already planned this — the ecosystem stats script generates percentile distributions. The scanner just needs to embed the latest distribution as a lookup table (updated monthly from batch data).

---

# WHAT THIS PATCH DOES NOT INCLUDE

**Dashboard web app.** Build after 5+ orgs request it from fleet reports. Not before.

**AutoGen parser.** 5% of market. Build when telemetry shows demand (>10% of scans are tools_only quality on repos with AutoGen imports).

**Runtime SDK.** Phase 4. Build when a paying customer asks.

**LCEL chain parsing.** Low incremental value. LangChain parser already handles AgentExecutor which is the primary pattern.

**Score recalibration to achieve perfect normal distribution.** The class-weighted approach gets close enough. Perfect calibration requires 10,000+ profiles and iterative adjustment. Ship the improvement, iterate later.

---

# IMPLEMENTATION ORDER

These are not independent. Each depends on the ones above it.

**Day 1-2: Correctness foundation**
- Bug 1A: blast radius per-crew scoping
- Bug 1B: crew_id on findings → per-crew scoring
- Bug 1C: score floor
- Bug 6: breach narrative per-finding

**Day 3-4: Auto-fix loop**
- Bug 3A: guardrail detector recognizes human_input=True
- Bug 3A: path analysis checks guardrail coverage
- Gap 3C: STRATUM-008 try/except auto-fix
- Gap 3B: CTA only on auto-fixable findings
- Partial resolution rendering (12→2 paths remaining)

**Day 5-6: Terminal experience**
- Reorder: flow maps before findings
- Rich flow maps with tool/service annotations and per-crew scores
- Crew selection (top 4 by risk score)
- Rescan delta rendering (Step 4)
- Finding class separation in header

**Day 7-8: Telemetry and scoring**
- Add all missing UsagePing fields (project_hash, sig, scan_source, etc.)
- Add rescan fields (is_rescan, prev_score, score_delta, resolved_count)
- Score recalibration (class-weighted severity)
- findings_by_class in profile

**Day 9-10: Enterprise data**
- Batch output includes connectable surfaces
- Two-phase batch discovery with seed orgs
- Example repo detection
- Env var classification expansion
- Fleet report uses arch_finding_count

---

# VALIDATION

After all changes applied, run this sequence:

```bash
# === CORRECTNESS ===

# 1. Blast radius
stratum scan crewai-examples --json | jq '.blast_radii[] | select(.tool=="SerperDevTool")'
# MUST show agent_count: 3 for SurpriseTravelCrew, NOT 56

# 2. Per-crew scores
stratum scan crewai-examples --verbose 2>&1 | grep "/100"
# SurpriseTravelCrew MUST be >0
# EmailFilterCrew MUST be >0

# 3. Score floor
stratum scan agent-service-toolkit --json | jq '.risk_score'
# MUST be >0 if any findings exist

# === AUTO-FIX LOOP ===

# 4. Fix resolves 001
stratum scan crewai-examples --json | jq '.finding_ids'
# Pre-fix: includes STRATUM-001, STRATUM-BR01

stratum scan crewai-examples --fix --patch-output fix.patch
git apply fix.patch

stratum scan crewai-examples --json | jq '.finding_ids'
# Post-fix: STRATUM-001 MUST NOT be present (or reduced path count)
# Post-fix: STRATUM-BR01 MUST NOT be present

# 5. Score drop
stratum scan crewai-examples --json | jq '.risk_score'
# Post-fix: ≤35 (was 69, expect ≥34 point drop)

# === RESCAN EXPERIENCE ===

# 6. Terminal shows delta
stratum scan crewai-examples 2>&1 | grep "was\|RESOLVED\|resolved"
# MUST show "↓XX points (was 69)"
# MUST show "✓ STRATUM-001 ... RESOLVED"

# === TERMINAL LAYOUT ===

# 7. Flow maps before findings
stratum scan crewai-examples 2>&1 | grep -n "ARCHITECTURE\|FIX THESE"
# "ARCHITECTURE" line number MUST be < "FIX THESE" line number

# 8. Rich flow maps
stratum scan crewai-examples 2>&1 | grep -A5 "EmailFilterCrew"
# MUST show tool annotations and external service destinations

# === TELEMETRY ===

# 9. UsagePing completeness
stratum scan crewai-examples --json | jq '.usage_ping'
# MUST contain: project_hash, scan_source, is_rescan, findings_by_class

# === ENTERPRISE ===

# 10. Batch with multi-repo org
stratum batch-scan --org langchain-ai --max-repos 10 --output batch.json
cat batch.json | jq '.[0].llm_models'
# MUST have llm_models array, not null

cat batch.json | jq '[.[] | .org] | unique'
# MUST have at least one org with 3+ repos
```

**Target grades after v4:**

```
Indie PMF:     A
Enterprise PMF: A-  (A requires sending fleet reports and measuring reply rate)
Telemetry:     A+
```

Not A+ on indie because that requires real-world validation — actual developers running the tool and coming back. The product is A+ ready. The grade comes from market response.

Not A+ on enterprise because the fleet report pipeline works but hasn't been tested on a real outbound campaign. A- because the infrastructure is complete and the insights are unique. A+ requires a CISO replying "yes, let's talk."
