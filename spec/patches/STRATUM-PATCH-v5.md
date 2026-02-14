# STRATUM PATCH v5

## Summary

5 bugs. 2 root causes. Everything else in v4 shipped correctly.

The v4 implementation delivered: flow maps before findings, per-crew scores in flow map headers, per-agent tool lists, finding class separation, rescan delta section with checkmarks, honest auto-fix CTAs, STRATUM-008 partial fix, all 14 telemetry fields, batch connectable surfaces, multi-repo org discovery, example repo detection, and crew selection by score. These are all working. Do not regress them.

What's still broken:

| # | Bug | Root cause | Loop broken | Grade blocked |
|---|-----|-----------|-------------|---------------|
| 1 | Score formula has no normalization | Score formula | All three | Indie C+, Enterprise B, Telemetry A |
| 2 | Blast radius narrative uses global count | Narrative plumbing | Indie | Indie C+ |
| 3 | STRATUM-001 and BR01 not resolved by --fix | Guardrail detection | Indie | Indie C+ |
| 4 | Breach narrative attached to wrong finding | Narrative plumbing | Indie | Indie C+ |
| 5 | CR06.1 shows ID as title in rescan | Finding titles | Indie | Indie C+ |

Root cause 1 (score formula) creates cascading failures: the fix loop shows "No change (score: 100)" despite 3 resolved findings, the fleet report shows scores of 0 and 222, and the telemetry score_delta field is always 0.

Root cause 2 (narrative plumbing) means the presentation layer reads project-level data where it should read per-finding or per-crew data.

---

# BUG 1: SCORE FORMULA

**This is the single highest-impact bug in the product.** Fixing it immediately unblocks the fix loop (Indie), the fleet report (Enterprise), and the rescan telemetry (Telemetry).

## What's happening

The score formula sums severity weights with no normalization. The raw sum is used directly as the score.

```
crewAIInc/crewAI:               raw ~222 → displayed as 222 (exceeds 100)
crewAI-examples pre-fix:        raw ~130 → displayed as 100 (visual cap only)
crewAI-examples post-fix:       raw ~100 → displayed as 100 (SAME AS PRE-FIX)
JoshuaC215/agent-service-toolkit: raw 0  → displayed as 0   (8 findings present)
```

The v4 patch specified class-weighted severity scoring. The evaluation shows `findings_by_class` IS present in profiles — so the classification was implemented. But the weights appear to have been added ON TOP of the old weights rather than REPLACING them, which is why crewAI-examples went from 69 (v3) to 100 (v4) instead of going down.

## Why this formula is wrong

The formula is `score = sum(weight[severity] for f in findings)`. This has three mathematical problems:

**No upper bound.** A project with 20 critical findings scores 300 (at weight=15 each). The score must be bounded at 100.

**No diminishing returns.** The 20th critical finding adds the same weight as the 1st. In practice, the marginal risk of the 20th unguarded path is much lower than the 1st — the developer is already at high risk. Every risk scoring system (CVSS, Snyk Risk Score, SonarQube debt ratio) handles this through normalization, not linear sums.

**No floor.** JoshuaC215 has 18 agents and 8 findings but scores 0. Either all findings are info-severity (weight=0) or the formula has an edge case where certain finding types contribute nothing. A project with findings must score above 0.

## The replacement: asymptotic normalization

The function `score = raw / (raw + k) × 100` has the properties Stratum needs:

- Always bounded [0, 100) — can never exceed 100
- Diminishing returns — the 20th finding adds less than the 1st
- Tunable via `k` — controls how fast the curve approaches 100

The constant `k` determines the inflection point: when `raw = k`, the score is exactly 50. Setting `k = 50` means a project needs ~50 raw severity points to hit 50/100. This produces a good distribution across the batch.

```python
SCORE_WEIGHTS = {
    # (severity, class): weight
    # Architecture findings contribute most — they're specific to this project's structure
    ('critical', 'architecture'): 12,
    ('high', 'architecture'): 8,
    ('medium', 'architecture'): 5,
    ('low', 'architecture'): 2,

    # Operational findings are code-specific but lower urgency
    ('critical', 'operational'): 8,
    ('high', 'operational'): 5,
    ('medium', 'operational'): 3,
    ('low', 'operational'): 1,

    # Hygiene findings fire on almost every project — low signal
    ('critical', 'hygiene'): 3,
    ('high', 'hygiene'): 2,
    ('medium', 'hygiene'): 1,
    ('low', 'hygiene'): 0,

    # Meta findings (CONTEXT-*, IDENTITY-*, ENV-*) contribute nothing
    # They are observations, not risks
}

# FINDING_CLASS dict is already implemented in v4 — reuse it exactly as-is.
# The dict maps finding ID prefixes to 'architecture', 'operational', 'hygiene', or 'meta'.


def calculate_risk_score(findings):
    """
    Compute a 0-100 risk score using class-weighted severity and asymptotic normalization.

    THIS FUNCTION REPLACES the current scoring logic entirely.
    Do not add these weights on top of existing weights. Remove the old formula.
    """

    # Step 1: Compute raw weighted sum
    raw = 0
    for f in findings:
        sev = f['severity']
        # Look up class from FINDING_CLASS using the base finding ID (CR05.1 → STRATUM-CR05)
        base_id = f['id'].rsplit('.', 1)[0] if '.' in f['id'] else f['id']
        cls = FINDING_CLASS.get(base_id, 'meta')
        weight = SCORE_WEIGHTS.get((sev, cls), 0)
        raw += weight

    # Step 2: Asymptotic normalization
    # k=50: raw=50 → score=50, raw=100 → score=67, raw=200 → score=80
    K = 50
    if raw == 0:
        score = 0.0
    else:
        score = (raw / (raw + K)) * 100

    # Step 3: Floor — if real findings exist, minimum score is 8
    has_real = any(
        f['severity'] in ('critical', 'high', 'medium', 'low')
        for f in findings
    )
    if has_real:
        real_count = len([f for f in findings if f['severity'] != 'info'])
        floor = max(8, real_count * 2)
        score = max(floor, score)

    # Step 4: Round to integer, cap at 100 (the asymptote approaches but never reaches 100,
    # but rounding could push 99.7 to 100 which is fine — only a project with no findings scores 0)
    return min(100, round(score))
```

## Expected distribution after fix

I computed the expected scores using the asymptotic formula with k=50 against the 16 batch repos, estimating raw weighted sums from the evaluation data:

```
Repo                                          Current → Expected  
crewAIInc/crewAI (raw ~180 arch-weighted)       222  →  78
AgentOps-AI/agentops (raw ~100)                  100  →  67
bytedance/deer-flow (raw ~90)                    100  →  64
langchain-ai/deepagents (raw ~85)                100  →  63
strnad/CrewAI-Studio (raw ~40)                   100  →  44
langchain-ai/streamlit-agent (raw ~60)            93  →  55
crewAIInc/crewAI-tools (raw ~55)                  90  →  52
jgravelle/AutoGroq (raw ~35)                      83  →  41
wassim249/fastapi... (raw ~30)                    74  →  38
steamship-core/langchain... (raw ~25)             64  →  33
lightninglabs/LangChainBitcoin (raw ~18)          49  →  26
alexfazio/viral-clips-crew (raw ~12)              34  →  19
langchain-ai/langgraph-bigtool (raw ~5)            8  →  10 (floor)
langchain-ai/oap-langgraph... (raw ~5)             8  →  10 (floor)
langchain-ai/react-agent... (raw ~2)               8  →   8 (floor)
JoshuaC215/agent-service-toolkit (raw ~0)          0  →  16 (floor: 8 findings × 2)
```

**Result:** No score exceeds 100. No score is 0 with findings. Median ≈ 41. Mean ≈ 40. The distribution has spread from the current top-heavy shape (50% scoring 80+) to a roughly even spread.

**The critical number:** crewAI-examples (the demo project) would score approximately 67 pre-fix. After --fix resolves STRATUM-001, 002, 009, BR01, and 008, the architecture findings drop significantly — estimated post-fix raw ≈ 35, yielding score ≈ 41. That's a **visible 26-point improvement** that the rescan terminal can celebrate.

## Per-crew scoring must also use the new formula

The same formula applies at the crew level. Each crew's score uses only findings tagged with that crew's `crew_id`:

```python
def calculate_crew_risk_score(crew_name, all_findings):
    crew_findings = [f for f in all_findings if f.get('crew_id') == crew_name]
    return calculate_risk_score(crew_findings)
```

This is already implemented correctly in v4 — the per-crew scores are non-zero and display in flow map headers. The only change is that `calculate_risk_score` now uses the asymptotic formula instead of `min(100, sum(...))`.

## Tuning k

After implementing, run the formula against the 16 batch repos. Check:

1. Median should be 35-55. If too low, decrease k. If too high, increase k.
2. No more than 2 repos should score above 80 (excluding example repos).
3. crewAI-examples post-fix must score at least 10 points below pre-fix.

If the distribution is still too compressed, try k=40 (more sensitive) or k=60 (more lenient).

## Where this function is called

Every place that computes or stores a risk score must call the new `calculate_risk_score`:

1. **Project-level score** in profile generation
2. **Per-crew score** in crew analysis
3. **Batch record score** in batch pipeline (each repo's profile is already computed with the formula, so the batch just carries it through)
4. **Rescan delta** — `score_delta = current_score - previous_score` (already in profile, but now the delta will be non-zero)

The score in the UsagePing comes from the profile, so it automatically uses the new formula.

---

# BUG 2: BLAST RADIUS NARRATIVE

## What's happening

The profile correctly computes per-crew blast radius:

```json
{
  "SerperDevTool": {
    "occurrences": [
      {"crew_name": "SurpriseTravelCrew", "agent_count": 3, "is_per_crew": true}
    ]
  }
}
```

But the terminal says:

```
Activity Planner is shared by 56 agents in SurpriseTravelCrew.
```

And the rescan makes it worse:

```
Financial Agent is shared by 56 agents in StockAnalysisCrew.
```

StockAnalysisCrew has 4 agents. The developer knows this.

## Root cause

The narrative template in the finding action group reads from a project-level variable (the global count of agents that share a tool) instead of from the finding's own evidence (the crew-specific count).

The data flow should be:

```
blast_radius_occurrence → finding.evidence.agent_count → narrative template
```

But currently it's:

```
global_agents_with_tool → narrative template
```

## The fix

This is a rendering-layer fix. The data is already correct in the profile. The finding evidence must carry the crew-specific count, and the narrative template must read from it.

### Step 1: When generating a CR05 finding, attach the crew-scoped evidence

Each CR05 finding is generated per-crew-occurrence. The finding's evidence must include the crew's agent count, not the global count:

```python
def _generate_cr05_finding(tool_name, occurrence):
    """
    Generate one CR05 finding per crew where tool is shared by 2+ agents.
    The 'occurrence' dict comes from _calculate_blast_radius and already
    has the correct per-crew agent_count.
    """
    return {
        'id': f'STRATUM-CR05',  # or CR05.1, CR05.2 etc
        'severity': 'critical',
        'category': 'compounding',
        'class': 'architecture',
        'crew_id': occurrence['crew'],
        'evidence': {
            'tool': tool_name,
            'crew_name': occurrence['crew'],
            'agent_count': occurrence['agent_count'],       # ← This is 3, not 56
            'agent_names': occurrence['agent_names'],       # ← The 3 specific agents
        },
    }
```

### Step 2: The narrative template reads from finding.evidence

The action group renderer builds the narrative paragraph from the finding's evidence:

```python
def _render_action_group_narrative(action_group):
    primary = action_group['primary_finding']
    evidence = primary.get('evidence', {})

    if primary['id'].startswith('STRATUM-CR05'):
        tool = evidence['tool']
        crew = evidence['crew_name']
        agent_count = evidence['agent_count']            # ← From finding, not global
        agent_names = evidence.get('agent_names', [])
        exemplar = agent_names[0] if agent_names else tool

        narrative = (
            f"{exemplar} is shared by {agent_count} agents in {crew}. "
            f"If {exemplar} returns poisoned results (SEO spam, prompt injection "
            f"in API response), all {agent_count} agents process that payload. "
            f"One compromised API response corrupts your entire crew in a single request."
        )
        return narrative

    # ... other finding type narratives
```

### Step 3: Verify the chain

The verification is: grep the terminal output for the string "shared by N agents in CREW_NAME" and confirm N matches the crew's actual agent count.

```bash
# In terminal-default.txt, for SurpriseTravelCrew (3 agents):
grep "shared by.*agents in SurpriseTravelCrew" terminal-default.txt
# MUST show: "shared by 3 agents in SurpriseTravelCrew"
# MUST NOT show: "shared by 56 agents in SurpriseTravelCrew"

# In the flow map box for SurpriseTravelCrew:
grep "SurpriseTravelCrew.*agents" terminal-default.txt
# MUST show: "SurpriseTravelCrew (3 agents, sequential)"
```

The same fix applies to the rescan terminal. The rescan generates fresh findings from the post-fix code, so if the finding generation attaches per-crew evidence correctly, the rescan narrative will also be correct.

---

# BUG 3: GUARDRAIL DETECTION FOR STRATUM-001 AND BR01

## What's happening

`--fix` adds `human_input=True` to Task() calls. This is the correct remediation for STRATUM-001 (unguarded data-to-external path) and BR01 (external messages without review). But the rescan still fires both findings because the scanner doesn't recognize `human_input=True` as a guardrail.

From the evaluation:

```
Resolved finding_ids: ['STRATUM-002', 'STRATUM-009', 'STRATUM-CR06.1']
STRATUM-001 resolved: False
BR01 resolved: False
Notes: "STRATUM-001 and BR01 remain: guardrail coverage insufficient for all paths"
```

## Root cause: two-part failure

**(A)** The guardrail detector doesn't have patterns for CrewAI `human_input=True` or LangGraph `interrupt()`.

**(B)** Even if it did, the STRATUM-001 rule (path analysis) doesn't consult the guardrail list when deciding whether a path is unguarded.

Both parts must be fixed. Fixing only (A) means guardrails are detected but ignored. Fixing only (B) means the check exists but the guardrail list is empty.

## Part A: Guardrail detector — add HITL patterns

The guardrail detector walks the AST and returns a list of detected guardrails. It currently detects things like rate limits and content filters. It needs to also detect human-in-the-loop patterns.

From the CrewAI documentation: `human_input=True` on a `Task()` call causes the agent to prompt the user for review before delivering its final answer. This is a direct guardrail on the task's outbound path.

From the LangGraph documentation: `interrupt()` within a node function pauses the graph and requires human input before resuming. `interrupt_before` and `interrupt_after` on `.compile()` set static breakpoints that pause execution at specific nodes.

```python
def _detect_guardrails(tree, source_file, import_map):
    """
    Walk the AST and return a list of detected guardrails.
    
    import_map: dict mapping local names to their import sources,
    e.g. {'Task': 'crewai', 'interrupt': 'langgraph.types'}
    """
    guardrails = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func_name = _resolve_call_name(node)

        # ── CrewAI: human_input=True on Task() ──
        if func_name == 'Task' and _import_resolves_to(func_name, 'crewai', import_map):
            for kw in node.keywords:
                if kw.arg == 'human_input' and _is_true_literal(kw.value):
                    guardrails.append({
                        'kind': 'hitl',
                        'framework': 'crewai',
                        'mechanism': 'human_input',
                        'source_file': source_file,
                        'line': node.lineno,
                        'scope': 'task',
                        # Which task variable this is assigned to — needed to resolve to an agent
                        'assignment_target': _get_assignment_target(node),
                    })

        # ── LangGraph: interrupt() call within a node function ──
        if func_name == 'interrupt' and _import_resolves_to(func_name, 'langgraph.types', import_map):
            # Find the enclosing function — that's the graph node this interrupt lives in
            enclosing_func = _find_enclosing_function(tree, node.lineno)
            guardrails.append({
                'kind': 'hitl',
                'framework': 'langgraph',
                'mechanism': 'interrupt',
                'source_file': source_file,
                'line': node.lineno,
                'scope': 'node',
                'node_function': enclosing_func,
            })

        # ── LangGraph: interrupt_before / interrupt_after on .compile() ──
        if _is_method_call(node, 'compile'):
            for kw in node.keywords:
                if kw.arg in ('interrupt_before', 'interrupt_after'):
                    node_names = _extract_list_of_strings(kw.value)
                    guardrails.append({
                        'kind': 'hitl',
                        'framework': 'langgraph',
                        'mechanism': kw.arg,
                        'source_file': source_file,
                        'line': node.lineno,
                        'scope': 'graph',
                        'interrupted_nodes': node_names,
                    })

                # Also note checkpointer presence — without a checkpointer,
                # interrupt() doesn't actually persist state. Not a guardrail itself,
                # but adds confidence to other interrupt-based guardrails.
                if kw.arg == 'checkpointer':
                    guardrails.append({
                        'kind': 'hitl_support',
                        'framework': 'langgraph',
                        'mechanism': 'checkpointer',
                        'source_file': source_file,
                        'line': node.lineno,
                    })

    return guardrails
```

### Helper functions needed

```python
def _resolve_call_name(node):
    """Return the function name from an ast.Call. Handles Name, Attribute, etc."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None

def _import_resolves_to(local_name, expected_module, import_map):
    """Check if 'local_name' was imported from 'expected_module'."""
    source = import_map.get(local_name, '')
    return expected_module in source

def _is_true_literal(node):
    """Check if an AST node is a True constant."""
    return isinstance(node, ast.Constant) and node.value is True

def _is_method_call(node, method_name):
    """Check if node is a method call like obj.compile()"""
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == method_name
    )

def _get_assignment_target(call_node):
    """
    Walk up to find if this Call is assigned to a variable.
    e.g., task1 = Task(...) → returns 'task1'
    Requires parent tracking in the AST walk.
    """
    # Implementation depends on how the AST walker tracks parents.
    # If using ast.walk(), you'll need a parent map built beforehand.
    # Return None if not assigned.
    pass

def _find_enclosing_function(tree, lineno):
    """Find the function definition that contains the given line number."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.lineno <= lineno <= node.end_lineno:
                return node.name
    return None

def _extract_list_of_strings(node):
    """Extract string values from an ast.List node. e.g., ["node_a", "node_b"]"""
    if isinstance(node, ast.List):
        return [
            elt.value for elt in node.elts
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
        ]
    return []
```

### Import map construction

The import map must be built before the guardrail detection pass:

```python
def _build_import_map(tree):
    """
    Build a dict: local_name → source_module.
    e.g., 'from crewai import Task' → {'Task': 'crewai'}
    e.g., 'from langgraph.types import interrupt' → {'interrupt': 'langgraph.types'}
    """
    import_map = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                local_name = alias.asname or alias.name
                import_map[local_name] = node.module
        if isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname or alias.name
                import_map[local_name] = alias.name
    return import_map
```

## Part B: Path analysis checks guardrail coverage

The STRATUM-001 rule finds data-to-external paths and fires a finding for each unguarded one. It currently does NOT check the guardrail list. It must.

```python
def _evaluate_stratum_001(graph, all_guardrails):
    """
    STRATUM-001: Unguarded data-to-external path.
    
    Find all paths from external input to external output.
    For each path, check if any HITL guardrail covers it.
    Only fire the finding for UNGUARDED paths.
    """
    all_paths = _find_data_to_external_paths(graph)
    hitl_guardrails = [g for g in all_guardrails if g['kind'] == 'hitl']

    unguarded_paths = []

    for path in all_paths:
        if _path_is_guarded(path, hitl_guardrails, graph):
            continue  # This path has human review — don't fire
        unguarded_paths.append(path)

    if not unguarded_paths:
        return None  # All paths guarded — STRATUM-001 does not fire

    # Fire with reduced scope showing only unguarded paths
    return {
        'id': 'STRATUM-001',
        'severity': 'critical',
        'category': 'security',
        'class': 'architecture',
        'evidence': {
            'unguarded_paths': unguarded_paths,
            'total_paths': len(all_paths),
            'guarded_paths': len(all_paths) - len(unguarded_paths),
        }
    }


def _path_is_guarded(path, hitl_guardrails, graph):
    """
    Check if any HITL guardrail covers this specific path.
    
    A path is guarded if a human review point exists at or before
    the external output step — i.e., somewhere in the path, a human
    gets to approve before the data reaches the external service.
    """
    path_agents = set(path.get('agent_names', []))
    path_tasks = set(path.get('task_names', []))
    path_nodes = set(path.get('node_names', []))

    for g in hitl_guardrails:
        # CrewAI: human_input=True on a Task
        # Check if the task belongs to an agent in this path
        if g['framework'] == 'crewai' and g['mechanism'] == 'human_input':
            # Resolve task → agent mapping from the graph
            task_agent = _resolve_task_to_agent(g['assignment_target'], graph)
            if task_agent and task_agent in path_agents:
                return True

        # LangGraph: interrupt() in a node function
        if g['framework'] == 'langgraph' and g['mechanism'] == 'interrupt':
            if g.get('node_function') in path_nodes:
                return True

        # LangGraph: interrupt_before/after at compile time
        if g['framework'] == 'langgraph' and g['mechanism'] in ('interrupt_before', 'interrupt_after'):
            interrupted = set(g.get('interrupted_nodes', []))
            if interrupted & path_nodes:
                return True

    return False


def _resolve_task_to_agent(task_var_name, graph):
    """
    Given a task variable name (e.g., 'task1'), find which agent it's assigned to.
    
    In CrewAI, tasks are assigned to agents via:
      task = Task(..., agent=my_agent)
    
    The graph should track task→agent assignments from the AST analysis.
    Returns the agent name if found, None otherwise.
    """
    # Look up in graph's task→agent mapping
    return graph.get('task_agent_map', {}).get(task_var_name)
```

### The same logic applies to BR01

BR01 (external messages without review) is the same pattern — fire only for unguarded outbound paths. The fix is identical: check `_path_is_guarded()` before firing.

```python
def _evaluate_br01(graph, all_guardrails):
    """
    STRATUM-BR01: External messages sent without human review.
    Same guard check as STRATUM-001.
    """
    outbound_paths = _find_outbound_message_paths(graph)
    hitl_guardrails = [g for g in all_guardrails if g['kind'] == 'hitl']

    unguarded = [p for p in outbound_paths if not _path_is_guarded(p, hitl_guardrails, graph)]

    if not unguarded:
        return None

    return {
        'id': 'STRATUM-BR01',
        'severity': 'high',
        'category': 'business',
        'class': 'architecture',
        'evidence': {
            'unguarded_paths': unguarded,
            'total_paths': len(outbound_paths),
            'guarded_paths': len(outbound_paths) - len(unguarded),
        }
    }
```

### Partial resolution rendering

If --fix guards 10 of 12 paths but 2 remain (in files the auto-fixer couldn't patch), the finding fires with reduced scope AND shows progress:

```python
def _render_partial_resolution(finding, previous_finding):
    """
    When a finding still fires but with fewer instances than before,
    show the progress.
    """
    if previous_finding is None:
        return  # First scan, no comparison

    curr_paths = len(finding['evidence']['unguarded_paths'])
    prev_paths = len(previous_finding['evidence']['unguarded_paths'])

    if curr_paths < prev_paths:
        return f"↓ was {prev_paths} paths — {prev_paths - curr_paths} fixed by --fix"
    return None
```

Terminal output when partial:

```
② Unguarded data-to-external path (2 paths)            ░ 5 min
   ↓ was 12 paths — 10 fixed by --fix

   Your EmailFilterCrew reads Gmail inbox and sends to
   Gmail outbound with no human check on 2 remaining tasks.

   Fix manually in:
     email_filter_crew.py:47 — add human_input=True
     auto_responder.py:23   — add human_input=True
```

### Integration into the scan pipeline

The guardrail detection must run BEFORE the finding evaluation, and its results must be passed to all finding rules:

```python
def run_scan(project_dir, options):
    # ... existing parse steps ...

    # NEW: Detect guardrails before evaluating findings
    all_guardrails = []
    for source_file, tree in parsed_files.items():
        import_map = _build_import_map(tree)
        file_guardrails = _detect_guardrails(tree, source_file, import_map)
        all_guardrails.extend(file_guardrails)

    # Store in profile
    profile['guardrails'] = all_guardrails
    profile['guardrail_count'] = len(all_guardrails)

    # Pass guardrails to finding evaluation
    findings = _evaluate_findings(graph, all_guardrails)  # ← guardrails passed here
    # ...
```

---

# BUG 4: BREACH NARRATIVE MATCHING

## What's happening

Finding ① (STRATUM-CR05, shared tool blast radius) shows:

```
📎 Matches real breach: Docker Ask Gordon Prompt Injection
   Your agent auto-executes Gmail inbox to fetch external content
   (Gmail inbox -> GmailGetThread -> TavilySearchResults -> Tavily API)
   -- the same pattern as Docker Ask Gordon Prompt Injection.
```

This is wrong in two ways:

1. CR05 is about **shared tools amplifying poisoned results**, not about auto-execution. The correct breach match is ServiceNow Now Assist (March 2025), where a shared AI service processed malicious input from one user and propagated it to others via the same resource.

2. The "Gmail inbox → GmailGetThread → TavilySearchResults" data path belongs to STRATUM-001 (unguarded data-to-external), not to CR05.

## Root cause

The breach match is computed at the project level and attached to action groups by position. Action group ① gets the first breach match regardless of which finding type it addresses. When action groups are reordered (which v4 did — moving flow maps before findings changed the group ordering), the breach matches become misaligned.

## The fix

The v4 patch already specified `FINDING_BREACH_MAP` — a dict mapping finding types to breach IDs. It was in the patch but not implemented.

```python
FINDING_BREACH_MAP = {
    # Finding ID prefix → list of matching breach IDs
    'STRATUM-001':  ['ECHOLEAK-2025', 'SLACK-AI-EXFIL-2024'],
    'STRATUM-002':  ['DOCKER-GORDON-2025'],
    'STRATUM-CR05': ['SERVICENOW-NOWASSIST-2025'],
    'STRATUM-CR06': [],  # No known match — omit 📎 section
    'STRATUM-BR01': ['ECHOLEAK-2025'],
    'STRATUM-008':  [],
    'STRATUM-009':  [],
    'STRATUM-010':  [],
}

BREACH_DB = {
    'ECHOLEAK-2025': {
        'name': 'Microsoft Copilot EchoLeak',
        'date': 'March 2024',
        'pattern': 'data-to-external without review',
        'summary_template': (
            'Your agent reads {input_source} and sends data to '
            '{output_dest} with no filter — the same data→external '
            'pattern that enabled the EchoLeak exfiltration.'
        ),
    },
    'DOCKER-GORDON-2025': {
        'name': 'Docker Ask Gordon Prompt Injection',
        'date': 'January 2025',
        'pattern': 'auto-execution of external content',
        'summary_template': (
            'Your agent auto-executes tool output without validation '
            '— the same auto-execution pattern exploited in Docker\'s '
            'Ask Gordon assistant.'
        ),
    },
    'SERVICENOW-NOWASSIST-2025': {
        'name': 'ServiceNow Now Assist Shared Resource',
        'date': 'March 2025',
        'pattern': 'shared resource amplifies compromise',
        'summary_template': (
            '{tool_name} is shared by {agent_count} agents — one '
            'poisoned response cascades to all consumers. This matches '
            'the ServiceNow Now Assist pattern where a shared AI service '
            'propagated malicious input across users.'
        ),
    },
    'SLACK-AI-EXFIL-2024': {
        'name': 'Slack AI Data Exfiltration',
        'date': 'August 2024',
        'pattern': 'channel data exfiltration via prompt injection',
        'summary_template': (
            'Your agent ingests external content and can write to '
            '{output_dest} — the same read→exfiltrate pattern used '
            'in the Slack AI data exfiltration attack.'
        ),
    },
}
```

### Using the map in action group rendering

```python
def _get_breach_match_for_action_group(action_group):
    """
    Get the breach match for an action group based on its PRIMARY finding type.
    Returns None if no match — in which case the 📎 section is omitted entirely.
    """
    primary_finding = action_group['primary_finding']
    base_id = primary_finding['id'].split('.')[0]  # CR05.1 → STRATUM-CR05

    breach_ids = FINDING_BREACH_MAP.get(base_id, [])
    if not breach_ids:
        return None

    breach = BREACH_DB.get(breach_ids[0])
    if not breach:
        return None

    # Fill in the template with evidence from the finding
    evidence = primary_finding.get('evidence', {})
    summary = breach['summary_template'].format(
        input_source=evidence.get('input_source', 'external input'),
        output_dest=evidence.get('output_dest', 'external service'),
        tool_name=evidence.get('tool', 'shared tool'),
        agent_count=evidence.get('agent_count', 'multiple'),
    )

    return {
        'name': breach['name'],
        'date': breach['date'],
        'summary': summary,
    }
```

### When to omit the 📎 section

If `_get_breach_match_for_action_group` returns None, do NOT render the 📎 section at all. Showing no breach is better than showing the wrong one. The v4 evaluation shows this was already stated in the v4 patch. Implement it.

---

# BUG 5: FINDING TITLES IN RESCAN

## What's happening

The rescan delta section shows:

```
✓ STRATUM-CR06.1  STRATUM-CR06.1 — RESOLVED
```

The finding ID is used as the title because `FINDING_TITLES` doesn't have an entry for `STRATUM-CR06.1`.

## The fix

Add entries for all sub-finding IDs (the `.N` variants) to the `FINDING_TITLES` dict:

```python
FINDING_TITLES = {
    # Core findings
    'STRATUM-001':  'Unguarded data-to-external path',
    'STRATUM-002':  'Destructive tool with no gate',
    'STRATUM-003':  'Missing input validation',
    'STRATUM-007':  'No rate limiting',
    'STRATUM-008':  'No error handling on external calls',
    'STRATUM-009':  'No timeout on HTTP calls',
    'STRATUM-010':  'No checkpointing on long pipeline',
    'STRATUM-BR01': 'External messages without review',
    'STRATUM-BR02': 'Sensitive data in agent prompts',
    'STRATUM-BR03': 'No audit trail',
    'STRATUM-BR04': 'No cost controls',
    'STRATUM-CR01': 'Circular delegation',
    'STRATUM-CR02': 'Single point of failure',
    'STRATUM-CR05': 'Shared tool blast radius',
    'STRATUM-CR06': 'Data access bypass',
    'STRATUM-OP01': 'No observability',
    'STRATUM-OP02': 'No human oversight',

    # Context and identity
    'CONTEXT-001':  'Multiple frameworks detected',
    'CONTEXT-002':  'Large agent fleet',
    'IDENTITY-001': 'Multiple LLM providers',
    'IDENTITY-002': 'External service dependencies',
    'ENV-001':      'Sensitive environment variables',
    'ENV-002':      'Database credentials detected',
    'TELEMETRY-003':'No observability telemetry',
}
```

And the lookup function should handle sub-IDs by falling back to the base ID:

```python
def _get_finding_title(finding_id):
    """
    Look up the human-readable title for a finding.
    For sub-findings like CR05.1, try the full ID first, then fall back to the base.
    """
    # Try exact match
    if finding_id in FINDING_TITLES:
        return FINDING_TITLES[finding_id]

    # Try base ID (strip .N suffix)
    base_id = finding_id.rsplit('.', 1)[0]
    if base_id in FINDING_TITLES:
        return FINDING_TITLES[base_id]

    # Last resort: return the ID itself (but this should not happen
    # if FINDING_TITLES is complete)
    return finding_id
```

After this fix, the rescan shows:

```
✓ STRATUM-CR06.1  Data access bypass — RESOLVED
```

---

# ENTERPRISE POLISH: PROVIDER INFERENCE FROM ENV VARS

This is not a bug — it's a gap that prevents the killer fleet-level insight from working.

## The problem

langchain-ai has 5 repos in the batch. Zero of them have detected LLM models. These repos configure models via environment variables (e.g., `OPENAI_API_KEY`) rather than hardcoding model strings in the source code. The AST parser doesn't pick up environment-based configuration.

This means the fleet report for langchain-ai can't generate the model dependency page — the single insight most likely to make a CISO reply.

## The fix: infer provider from API key env vars

When a repo has 0 detected LLM models but has API key env vars, infer the provider:

```python
ENV_TO_PROVIDER = {
    'OPENAI_API_KEY':        {'provider': 'openai',       'confidence': 'high'},
    'ANTHROPIC_API_KEY':     {'provider': 'anthropic',    'confidence': 'high'},
    'GOOGLE_API_KEY':        {'provider': 'google',       'confidence': 'medium'},
    'GOOGLE_GENAI_API_KEY':  {'provider': 'google',       'confidence': 'high'},
    'AZURE_OPENAI_API_KEY':  {'provider': 'azure_openai', 'confidence': 'high'},
    'AZURE_OPENAI_ENDPOINT': {'provider': 'azure_openai', 'confidence': 'high'},
    'GROQ_API_KEY':          {'provider': 'groq',         'confidence': 'high'},
    'TOGETHER_API_KEY':      {'provider': 'together',     'confidence': 'high'},
    'MISTRAL_API_KEY':       {'provider': 'mistral',      'confidence': 'high'},
    'COHERE_API_KEY':        {'provider': 'cohere',       'confidence': 'high'},
    'FIREWORKS_API_KEY':     {'provider': 'fireworks',    'confidence': 'high'},
    'DEEPSEEK_API_KEY':      {'provider': 'deepseek',     'confidence': 'high'},
    'XAI_API_KEY':           {'provider': 'xai',          'confidence': 'high'},
}


def infer_providers_from_env(env_var_names, detected_models):
    """
    When no hardcoded model strings are found, infer providers from API key env vars.
    
    Returns a list of inferred provider dicts.
    Only called when detected_models is empty or contains only generic entries.
    """
    inferred = []
    seen_providers = set()

    # Don't infer if we already have detected models
    if detected_models:
        return []

    for var_name in env_var_names:
        match = ENV_TO_PROVIDER.get(var_name)
        if match and match['provider'] not in seen_providers:
            seen_providers.add(match['provider'])
            inferred.append({
                'provider': match['provider'],
                'model': None,  # Specific model unknown
                'source': 'env_inference',
                'env_var': var_name,
                'confidence': match['confidence'],
            })

    return inferred
```

### Integration into the profile

```python
def _build_profile(scan_result):
    # ... existing profile building ...

    # After LLM model detection
    detected_models = profile.get('llm_models', [])
    if not detected_models:
        env_vars = profile.get('env_var_names', [])
        inferred = infer_providers_from_env(env_vars, detected_models)
        if inferred:
            profile['llm_providers_inferred'] = inferred
            # Also populate llm_providers for fleet report consumption
            profile['llm_providers'] = [p['provider'] for p in inferred]
```

### Fleet report uses inferred providers

The fleet report model dependency page should combine detected models and inferred providers:

```python
def _fleet_model_dependency(batch_records):
    provider_counts = defaultdict(int)
    for record in batch_records:
        # Detected models
        for model in record.get('llm_models', []):
            provider = model.get('provider', 'unknown')
            provider_counts[provider] += 1
        # Inferred providers (when no detected models)
        for provider in record.get('llm_providers_inferred', []):
            provider_counts[provider['provider']] += 1

    total_repos = len(batch_records)
    # "4 of 5 repos use OpenAI (80%). 1 uses Anthropic (20%)."
    # "Provider concentration: HIGH — 80% single-provider dependency."
```

---

# WHAT THIS PATCH DOES NOT CHANGE

Everything from v4 that's working stays exactly as-is:

- Terminal layout (flow maps before findings) — **working**
- Per-crew risk scores in flow map headers — **working** (just needs the new score formula)
- Per-agent tool lists in flow maps — **working**
- Finding class separation in footer — **working**
- Rescan delta section structure (checkmarks, resolved/new/remaining) — **working**
- Auto-fix CTA honesty ("X of Y findings") — **working**
- STRATUM-008 auto-fix (29→21 unhandled calls) — **working**
- All 14 telemetry UsagePing fields — **working**
- Batch connectable surfaces (llm_models, env_vars, vector_stores) — **working**
- Multi-repo org discovery — **working**
- Example repo detection — **working**
- findings_by_class in profiles — **working**
- Crew selection by score — **working**

---

# IMPLEMENTATION ORDER

## Day 1: Score formula

1. Replace the existing scoring function with `calculate_risk_score` (the asymptotic formula above).
2. Remove any existing severity weight constants that were being summed linearly.
3. Ensure `FINDING_CLASS` and `SCORE_WEIGHTS` dicts are the ONLY weight sources.
4. Run the new formula against all 16 batch repos. Check:
   - No score > 100
   - No score = 0 with findings
   - Median 35-55
   - Tune k if needed
5. Run the single-project scan on crewAI-examples:
   - Pre-fix score should be approximately 55-70
   - Run --fix
   - Post-fix score should be at least 10 points lower
6. Generate new terminal-rescan.txt — confirm it shows "↓N points (was M)" instead of "No change"

## Day 2: Narrative plumbing

1. Fix CR05 finding generation: each finding carries per-crew agent_count in evidence.
2. Fix narrative template: reads `finding.evidence.agent_count`, not global count.
3. Implement `FINDING_BREACH_MAP` and `BREACH_DB` — attach breach match per-finding type.
4. Implement `_get_finding_title` with sub-ID fallback.
5. Generate new terminal-default.txt — confirm "shared by 3 agents in SurpriseTravelCrew."
6. Generate new terminal-rescan.txt — confirm CR06.1 shows human-readable title.

## Day 3: Guardrail detection

1. Implement `_build_import_map` for each source file.
2. Implement `_detect_guardrails` with CrewAI and LangGraph HITL patterns.
3. Wire guardrail detection into the scan pipeline (before finding evaluation).
4. Modify `_evaluate_stratum_001` and `_evaluate_br01` to check `_path_is_guarded`.
5. Run --fix → rescan → confirm STRATUM-001 and BR01 resolved (or partial).
6. Generate new evaluation-summary.json with resolved_finding_ids including 001 and BR01.

## Day 4: Enterprise polish and validation

1. Implement `infer_providers_from_env`.
2. Wire into profile builder and batch record output.
3. Run full batch scan. Check langchain-ai repos have inferred providers.
4. Generate fleet report — check model dependency page has data.
5. Run full validation sequence (below).

---

# VALIDATION SEQUENCE

Every check must pass. Do not ship until they all do.

## V1: Score sanity

```bash
# No score > 100 in batch
python -c "
import json
batch = json.load(open('batch-results.json'))
for r in batch:
    score = r.get('risk_score', 0)
    assert score <= 100, f'{r[\"repo_name\"]}: score={score} exceeds 100'
    if r.get('finding_count', 0) > 0 and not r.get('is_example'):
        assert score > 0, f'{r[\"repo_name\"]}: score=0 with {r[\"finding_count\"]} findings'
print('V1 PASSED: All scores in [0, 100], no zero-with-findings')
"
```

## V2: Score delta after fix

```bash
# crewAI-examples post-fix score < pre-fix score
python -c "
import json
e = json.load(open('evaluation-summary.json'))
fc = e['fix_cycle']
assert fc['post_fix_risk_score'] < fc['pre_fix_risk_score'], \
    f'Post-fix {fc[\"post_fix_risk_score\"]} >= pre-fix {fc[\"pre_fix_risk_score\"]}'
assert fc['risk_score_delta'] < 0, f'Delta is {fc[\"risk_score_delta\"]}, expected negative'
print(f'V2 PASSED: Score dropped {fc[\"pre_fix_risk_score\"]} → {fc[\"post_fix_risk_score\"]}')
"
```

## V3: Blast radius per-crew

```bash
# Terminal shows per-crew agent count, not global
python -c "
import re
text = open('terminal-default.txt').read()
text = re.sub(r'\x1b\[[0-9;]*m', '', text)  # strip ANSI

# Should NOT contain '56 agents in SurpriseTravelCrew' or similar
assert 'shared by 56 agents' not in text, 'Still showing global agent count'

# Should contain 'shared by 3 agents in SurpriseTravelCrew' (or similar small number)
# The exact number depends on the crew
print('V3 PASSED: No global agent count in blast radius narrative')
"
```

## V4: STRATUM-001 resolved by fix

```bash
# Post-fix findings should not include STRATUM-001 (or should show reduced paths)
python -c "
import json
e = json.load(open('evaluation-summary.json'))
resolved = e['fix_cycle']['resolved_finding_ids']
assert 'STRATUM-001' in resolved or 'STRATUM-BR01' in resolved, \
    f'Neither 001 nor BR01 in resolved: {resolved}'
print(f'V4 PASSED: Resolved includes {[r for r in resolved if \"001\" in r or \"BR01\" in r]}')
"
```

## V5: Breach narrative matches finding type

```bash
# Finding ① (CR05) should NOT mention Docker Gordon or Gmail inbox
python -c "
import re
text = open('terminal-default.txt').read()
text = re.sub(r'\x1b\[[0-9;]*m', '', text)

# Find the first action group (①)
lines = text.split('\n')
in_group_1 = False
group_1_text = []
for line in lines:
    if '①' in line:
        in_group_1 = True
    elif '②' in line:
        in_group_1 = False
    if in_group_1:
        group_1_text.append(line)

group_1 = '\n'.join(group_1_text)

# CR05 should NOT have Docker Gordon or Gmail narrative
if 'CR05' in group_1 or 'shared' in group_1.lower():
    assert 'Docker' not in group_1, 'CR05 still matched to Docker Gordon'
    assert 'Gmail inbox' not in group_1, 'CR05 still has Gmail data path narrative'
    print('V5 PASSED: CR05 action group has correct breach match')
else:
    print('V5 SKIPPED: First action group is not CR05')
"
```

## V6: Finding titles in rescan

```bash
# Rescan should not show finding ID as title
python -c "
import re
text = open('terminal-rescan.txt').read()
text = re.sub(r'\x1b\[[0-9;]*m', '', text)

# Find resolved lines
for line in text.split('\n'):
    if '✓' in line and 'RESOLVED' in line:
        # Check that the line doesn't repeat the finding ID as the title
        # Bad: '✓ STRATUM-CR06.1  STRATUM-CR06.1 — RESOLVED'
        # Good: '✓ STRATUM-CR06.1  Data access bypass — RESOLVED'
        parts = line.split('STRATUM-')
        if len(parts) >= 3:
            # If the ID appears twice, the title is just the ID
            finding_id = 'STRATUM-' + parts[1].strip().split()[0]
            rest = 'STRATUM-' + ''.join(parts[2:])
            assert finding_id not in rest.split('—')[0], \
                f'Finding ID used as title: {line.strip()}'

print('V6 PASSED: All resolved findings have human-readable titles')
"
```

## V7: Rescan delta display

```bash
# Rescan should show score delta, not "No change"
python -c "
import re
text = open('terminal-rescan.txt').read()
text = re.sub(r'\x1b\[[0-9;]*m', '', text)

assert 'No change' not in text, 'Rescan still shows \"No change\"'
assert '↓' in text or 'points' in text, 'No score delta shown in rescan'
print('V7 PASSED: Rescan shows score delta')
"
```

## V8: Telemetry rescan fields

```bash
# UsagePing for a rescan should have non-zero delta
python -c "
import json
# This requires generating a rescan usage ping
# If sample-usage-ping.json is for a first scan, generate a rescan ping separately
ping = json.load(open('sample-usage-ping.json'))
if ping.get('is_rescan'):
    assert ping['score_delta'] != 0, 'Rescan ping has zero score_delta'
    assert ping['prev_score'] > 0, 'Rescan ping has zero prev_score'
    print(f'V8 PASSED: Rescan delta={ping[\"score_delta\"]}')
else:
    print('V8 SKIPPED: Sample ping is first scan (need rescan ping to verify)')
"
```

## V9: Fleet score credibility

```bash
# No score anomalies in batch that would undermine fleet report
python -c "
import json
batch = json.load(open('batch-results.json'))
anomalies = []
for r in batch:
    name = r.get('repo_name', r.get('org', ''))
    score = r.get('risk_score', 0)
    findings = r.get('finding_count', 0)
    if score > 100:
        anomalies.append(f'{name}: score={score} > 100')
    if findings > 0 and score == 0 and not r.get('is_example'):
        anomalies.append(f'{name}: score=0 with {findings} findings')
assert not anomalies, f'Score anomalies found: {anomalies}'
print('V9 PASSED: All fleet scores credible')
"
```

## V10: Provider inference

```bash
# langchain-ai repos should have inferred providers (if no detected models)
python -c "
import json
batch = json.load(open('batch-results.json'))
langchain_repos = [r for r in batch if 'langchain-ai' in r.get('repo_name', r.get('org', ''))]
repos_with_providers = [
    r for r in langchain_repos
    if r.get('llm_models') or r.get('llm_providers_inferred')
]
print(f'langchain-ai repos with model/provider data: {len(repos_with_providers)}/{len(langchain_repos)}')
if len(repos_with_providers) > 0:
    print('V10 PASSED: Provider inference working')
else:
    print('V10 WARN: No langchain-ai repos have provider data')
"
```

---

# FILES TO UPLOAD FOR EVALUATION

After implementing all fixes, generate and upload these 6 files:

1. **evaluation-summary.json** — full scorecard with fix_cycle showing negative score_delta
2. **terminal-default.txt** — verify blast radius says 3 not 56, breach narrative matches finding type
3. **terminal-rescan.txt** — verify "↓N points (was M)", STRATUM-001 in resolved, human-readable titles
4. **sample-usage-ping.json** — verify all fields (ideally include a rescan ping too)
5. **batch-results.json** — verify no score > 100, no score = 0 with findings, llm_providers_inferred on langchain-ai repos
6. **connection-validation.json** — verify langchain-ai fleet story includes provider data

---

# TARGET GRADES AFTER v5

| Loop | Current | After v5 | What unlocks A+ |
|------|---------|----------|-----------------|
| Indie PMF | C+ | A+ | Developer scans → sees architecture → fixes → rescans → sees ↓26 points + green checkmarks → adds GitHub Action |
| Enterprise PMF | B | A+ | Fleet report shows scores [0,100] with provider concentration insight for langchain-ai |
| Telemetry | A | A+ | Rescan ping shows non-zero score_delta, all 8 PMF queries return meaningful data |
