# STRATUM CLI — Terminal Output Redesign

## THE PROBLEM

The scanner currently dumps 13 findings, 5 signals, 4 incident matches, and 8 blast radii as a wall of text. That's ~157 lines at 80 chars. A developer's eyes glaze over after finding #3. The information is there but the experience is hostile.

A 10/10 developer tool respects two things: your time and your cognitive load. The developer typed `stratum scan .` because they want to know: **"Am I in trouble, and what do I do about it?"** The answer should take 5 seconds to understand, not 5 minutes to read.

## THE INSIGHT

13 findings collapse into 7 unique actions. All 9 CRITICAL+HIGH findings are resolved by just 3 actions:

1. **Add `human_input=True` on outbound tasks** → resolves STRATUM-001, 002, BR01, CR01 (1 CRITICAL + 3 HIGH)
2. **Add input validation on shared tools** → resolves CR05, CR05.1, CR05.2 (2 CRITICAL + 1 HIGH)
3. **Fix data access bypass in 2 crews** → resolves CR06, CR06.1 (2 HIGH)

The terminal output should lead with those 3 actions, not 13 findings.

## THE NEW TERMINAL EXPERIENCE

### What the developer sees (full output):

```
 ╔═══════════════════════════════════════════════════════════════════╗
 ║  STRATUM SCAN                                                    ║
 ║  crewAI-examples · 116 files · 29 crews · 53 agents             ║
 ║  Frameworks: CrewAI, LangChain                                   ║
 ╚═══════════════════════════════════════════════════════════════════╝


 RISK SCORE ████████████████████████████░░░░░░░░░░  69 / 100
             ▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔
             2 critical · 7 high · 4 medium


 ─── FIX THESE FIRST ──────────────────────────────────────────────

 ① Add human review on outbound tasks                     ░ 5 min
   Resolves 4 findings (1 critical + 3 high)

   Your agents send emails and take actions with no human check.
   One crafted email can make your agent forward inbox contents
   to an attacker — this is the exact pattern behind the Microsoft
   Copilot EchoLeak breach ($200M+ impact across 160+ incidents).

   Fix:
   ┌─────────────────────────────────────────────────────────┐
   │  task = Task(                                           │
   │      description="...",                                 │
   │ +    human_input=True   # review before external calls  │
   │  )                                                      │
   └─────────────────────────────────────────────────────────┘
   Apply to: email_filter_crew.py, crew.py (landing_page_generator)

   📎 Matches real breach: Microsoft Copilot EchoLeak (2025)
      Your EmailFilterCrew reads Gmail inbox via GmailGetThread
      and routes to Gmail outbound with no filter — same pattern.


 ② Add input validation on shared tools                    ░ 30 min
   Resolves 3 findings (2 critical + 1 high)

   SerperDevTool feeds 3 agents in SurpriseTravelCrew.
   WebsiteSearchTool feeds 3 agents in StockAnalysisCrew.
   One poisoned search result compromises all of them at once.

   Fix:
   ┌─────────────────────────────────────────────────────────┐
   │  class ValidatedSearch(BaseTool):                       │
   │      def _run(self, query: str) -> str:                 │
   │          raw = SerperDevTool()._run(query)              │
   │ +        if contains_injection_patterns(raw):           │
   │ +            raise ValueError("Suspicious content")     │
   │          return raw                                     │
   └─────────────────────────────────────────────────────────┘


 ③ Fix data access bypass in 2 crews                       ░ 15 min
   Resolves 2 findings (2 high)

   In EmailFilterCrew, Email Response Writer reads Gmail inbox
   directly — bypassing Email Action Agent entirely. The filter
   exists but data flows around it. Same issue in MatchToProposalCrew
   where Matcher bypasses CV Reader.

   Fix: Remove direct data source access from downstream agents,
   or route all reads through the upstream filter agent.


 ─── WHAT YOUR AGENTS LOOK LIKE ───────────────────────────────────

 EmailFilterCrew (3 agents, sequential)
 ┌──────────────────────────────────────────────────────────────────┐
 │                                                                  │
 │  Gmail inbox (personal data)                                     │
 │    └──▶ Email Filter Agent ──▶ Email Action Agent ──▶ Response Writer
 │                                  ├──▶ Gmail outbound  ⚠ no gate │
 │                                  └──▶ Tavily API  ⚠ no gate     │
 │                                                                  │
 │  ⚠ BYPASS: Response Writer reads inbox directly                 │
 │  📎 Matches: EchoLeak breach pattern                             │
 │                                                                  │
 └──────────────────────────────────────────────────────────────────┘

 StockAnalysisCrew (4 agents, sequential)
 ┌──────────────────────────────────────────────────────────────────┐
 │                                                                  │
 │  Financial Agent ──▶ Research Analyst ──▶ Financial Analyst ──▶ Investment Advisor
 │                                                                  │
 │  🔴 ScrapeWebsiteTool shared by all 4 agents                    │
 │  🔴 WebsiteSearchTool shared by 3 agents                        │
 │  No validation between any step in the chain                     │
 │                                                                  │
 └──────────────────────────────────────────────────────────────────┘

 SurpriseTravelCrew (3 agents, sequential)
 ┌──────────────────────────────────────────────────────────────────┐
 │                                                                  │
 │  Activity Planner ──▶ Restaurant Scout ──▶ Itinerary Compiler   │
 │                                                                  │
 │  🔴 SerperDevTool shared by all 3 agents                        │
 │                                                                  │
 └──────────────────────────────────────────────────────────────────┘


 ─── ALSO WORTH FIXING ────────────────────────────────────────────

 · No error handling on 27 external calls — one timeout crashes everything
 · No request timeouts on 2 HTTP calls (sec_tools.py, trello_helper.py)
 · No checkpointing — a crash at step 3 of 4 loses all progress
 · 3-agent chain in GameBuilderCrew has no output validation between steps
 · No observability — you can't debug agent behavior in production

 ─── 13 findings total · 5 signals · Full details: stratum scan . --json
```

That's it. The whole output. The developer understands their risk in 5 seconds (score bar + "fix these first"), knows exactly what to do (3 numbered actions with code), can see their architecture (flow maps), and has a reference for lower-priority items (the one-liner list at the bottom).

---

## DESIGN PRINCIPLES

### 1. Actions, not findings

Developers don't care about STRATUM-001, STRATUM-002, STRATUM-BR01, and STRATUM-CR01 as separate items. They care that they need to add `human_input=True`. Group findings by the action that resolves them. Lead with the action, not the finding ID.

Finding IDs still exist in `--json` output and in the "Full details" reference. They're useful for tracking and dedup. They're not useful for the human reading the terminal.

### 2. The 5-second test

A developer should understand their situation within 5 seconds of the scan completing:
- **Risk bar** tells them severity at a glance (visual, not a number in a list)
- **"Fix these first"** tells them how many actions and how urgent
- **Time estimates** tell them this is doable, not overwhelming

If they close the terminal after 5 seconds, they still know: "I have 2 critical issues and the first fix takes 5 minutes."

### 3. Show the architecture, not just the problems

The flow maps serve two purposes:
- They make findings concrete ("oh, that's why the filter doesn't work — the data goes around it")
- They give the developer a mental model of their own system that they probably don't have

Many developers build agent systems iteratively and don't have a clear picture of how data actually flows. The flow map is valuable even if there were zero findings.

### 4. Collapse low-priority items

MEDIUM findings and signals get one line each in the "also worth fixing" section. No descriptions, no evidence, no remediation — just enough to know they exist. The developer who wants details can run `--json` or `--verbose`.

This is the difference between a security report (comprehensive, exhausting) and a developer tool (actionable, respectful of time).

### 5. Time estimates are mandatory

Every action gets a time estimate. This converts "a list of problems" into "a plan I can execute." The estimates are rough (5 min / 15 min / 30 min / 1 hour) but the psychological effect is massive: the developer thinks "I can fix the critical stuff in an hour" instead of "I have 13 problems."

---

## IMPLEMENTATION

### File structure:

```
stratum/output/
├── __init__.py
├── terminal.py              # REWRITTEN: orchestrates the full output
├── flow_map.py              # NEW: per-crew ASCII flow diagrams
├── action_groups.py         # NEW: groups findings into actionable fixes
├── risk_bar.py              # NEW: visual risk score bar
├── code_block.py            # NEW: bordered code snippet renderer
└── json_output.py           # existing, unchanged
```

---

### `output/action_groups.py` — The Core Innovation

This module takes the list of findings and collapses them into deduplicated, prioritized actions.

```python
"""
Groups findings by the action that resolves them.

13 findings → 7 action groups → 3 that matter right now

Each ActionGroup contains:
- A human-readable action title
- The findings it resolves
- A severity summary
- The code fix
- A time estimate
- The most compelling narrative (from the highest-severity finding)
- Incident matches (if any)
- Which files to apply the fix to
"""

from dataclasses import dataclass, field

@dataclass
class ActionGroup:
    action_id: str                      # "add_hitl", "add_tool_validation", etc.
    title: str                          # "Add human review on outbound tasks"
    finding_ids: list = field(default_factory=list)
    finding_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    severity_label: str = ""            # "1 critical + 3 high"
    effort: str = ""                    # "5 min", "15 min", "30 min", "1 hour"
    narrative: str = ""                 # The compelling "why" — from best finding
    code_fix: str = ""                  # The actual code snippet
    apply_to: list = field(default_factory=list)  # File paths to apply fix
    incident_match: dict = None         # Best matching incident, if any
    priority: int = 0                   # Sort order (lower = more urgent)


# ─── Action definitions ─────────────────────────────────────────
# Each action defines: which findings it claims, how to describe it,
# what the fix looks like, and how long it takes.

ACTION_DEFINITIONS = {
    "add_hitl": {
        "title": "Add human review on outbound tasks",
        "claims": lambda f: (
            f.get("quick_fix_type") == "add_hitl" or
            "human_input=True" in f.get("remediation", "") or
            f["id"] in ("STRATUM-001", "STRATUM-002", "STRATUM-BR01")
        ),
        "narrative_source": "STRATUM-001",  # Use this finding's description as the narrative
        "effort": "5 min",
        "code_fix": {
            "CrewAI": (
                '  task = Task(\n'
                '      description="...",\n'
                ' +    human_input=True   # review before external calls\n'
                '  )'
            ),
            "LangGraph": (
                '  graph = workflow.compile(\n'
                ' +    interrupt_before=["send_email", "file_management"]\n'
                '  )'
            )
        },
        "priority": 1
    },

    "add_tool_validation": {
        "title": "Add input validation on shared tools",
        "claims": lambda f: f["id"].startswith("STRATUM-CR05"),
        "effort": "30 min",
        "code_fix": {
            "CrewAI": (
                '  class ValidatedSearch(BaseTool):\n'
                '      def _run(self, query: str) -> str:\n'
                '          raw = SerperDevTool()._run(query)\n'
                ' +        if contains_injection_patterns(raw):\n'
                ' +            raise ValueError("Suspicious content")\n'
                '          return raw'
            )
        },
        "priority": 2
    },

    "fix_bypass": {
        "title": "Fix data access bypass",
        "claims": lambda f: f["id"].startswith("STRATUM-CR06"),
        "effort": "15 min",
        "code_fix": None,  # No universal code fix — narrative explains what to do
        "priority": 3
    },

    "isolate_tools": {
        "title": "Isolate shared tool contexts between agents",
        "claims": lambda f: f["id"] == "STRATUM-CR01",
        "effort": "15 min",
        "code_fix": {
            "CrewAI": (
                '  # Give each agent its own tool instance:\n'
                '  matcher = Agent(\n'
                ' -    tools=[shared_serper],\n'
                ' +    tools=[SerperDevTool()],  # independent instance\n'
                '  )'
            )
        },
        "priority": 4
    },

    "add_error_handling": {
        "title": "Add error handling on external calls",
        "claims": lambda f: f["id"] == "STRATUM-008",
        "effort": "30 min",
        "code_fix": {
            "CrewAI": (
                '  try:\n'
                '      result = crew.kickoff()\n'
                '  except Exception as e:\n'
                '      logger.error(f"Crew failed: {e}")\n'
                '      # graceful degradation'
            )
        },
        "priority": 10
    },

    "add_timeout": {
        "title": "Add timeouts on HTTP calls",
        "claims": lambda f: f["id"] == "STRATUM-009",
        "effort": "2 min",
        "code_fix": {
            "_default": 'requests.get(url, timeout=30)'
        },
        "priority": 11
    },

    "add_checkpointing": {
        "title": "Add checkpointing for crash recovery",
        "claims": lambda f: f["id"] == "STRATUM-010",
        "effort": "5 min",
        "code_fix": {
            "CrewAI": (
                '  crew = Crew(\n'
                '      agents=[...],\n'
                '      tasks=[...],\n'
                ' +    memory=True,\n'
                '  )'
            )
        },
        "priority": 12
    },

    "add_structured_output": {
        "title": "Add output validation between agent steps",
        "claims": lambda f: f["id"] == "STRATUM-CR02",
        "effort": "15 min",
        "code_fix": {
            "CrewAI": (
                '  task = Task(\n'
                '      description="...",\n'
                ' +    output_pydantic=IntermediateResult,\n'
                '  )'
            )
        },
        "priority": 13
    },
}


def group_findings_into_actions(
    findings: list,
    signals: list,
    incident_matches: list,
    detected_frameworks: list,
    blast_radii: list,
) -> list:
    """
    Takes raw findings and returns prioritized ActionGroups.

    Process:
    1. Each finding is claimed by at most one action (first match wins by priority)
    2. Actions with 0 findings are dropped
    3. Remaining findings that no action claimed go into an "other" bucket
    4. Actions are sorted by priority (critical actions first)
    """

    # Sort action definitions by priority
    sorted_actions = sorted(ACTION_DEFINITIONS.items(), key=lambda x: x[1]["priority"])

    claimed = set()
    groups = []

    for action_id, defn in sorted_actions:
        # Find findings this action claims
        matching = []
        for f in findings:
            if f["id"] not in claimed and defn["claims"](f):
                matching.append(f)
                claimed.add(f["id"])

        if not matching:
            continue

        # Build the group
        group = ActionGroup(action_id=action_id)
        group.title = defn["title"]
        group.finding_ids = [f["id"] for f in matching]
        group.finding_count = len(matching)
        group.critical_count = sum(1 for f in matching if f["severity"] == "CRITICAL")
        group.high_count = sum(1 for f in matching if f["severity"] == "HIGH")
        group.medium_count = sum(1 for f in matching if f["severity"] == "MEDIUM")
        group.priority = defn["priority"]
        group.effort = defn["effort"]

        # Severity label
        parts = []
        if group.critical_count:
            parts.append(f"{group.critical_count} critical")
        if group.high_count:
            parts.append(f"{group.high_count} high")
        if group.medium_count:
            parts.append(f"{group.medium_count} medium")
        group.severity_label = " + ".join(parts)

        # Narrative — from the highest-severity finding, prefer the one named in narrative_source
        source_id = defn.get("narrative_source")
        narrative_finding = None
        if source_id:
            narrative_finding = next((f for f in matching if f["id"] == source_id), None)
        if not narrative_finding:
            # Fall back to highest severity
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            matching.sort(key=lambda f: severity_order.get(f["severity"], 99))
            narrative_finding = matching[0]

        group.narrative = _build_narrative(narrative_finding, matching, blast_radii)

        # Code fix — pick the right framework
        if defn.get("code_fix"):
            fw = detected_frameworks[0] if detected_frameworks else "_default"
            group.code_fix = defn["code_fix"].get(fw, defn["code_fix"].get("_default", ""))

        # Apply-to files — collect unique evidence file paths
        apply_files = set()
        for f in matching:
            for ev in f.get("evidence", []):
                if "\\" in ev or "/" in ev:  # Only actual file paths
                    # Clean up the path for display
                    clean = ev.split(":")[0]  # Remove :line_number
                    # Shorten to just the relevant part
                    parts = clean.replace("\\", "/").split("/")
                    if len(parts) > 2:
                        apply_files.add("/".join(parts[-2:]))
                    else:
                        apply_files.add(clean)
        group.apply_to = sorted(apply_files)

        # Incident match — find the best matching incident
        for m in incident_matches:
            if m.get("confidence", 0) >= 0.75:
                # Check if any of this group's findings relate to this incident
                # Simple: if the finding is security-related and incident is high-confidence
                group.incident_match = {
                    "name": m["name"],
                    "confidence": m["confidence"],
                    "match_reason": m.get("match_reason", ""),
                }
                break

        groups.append(group)

    # Sort: critical-containing groups first, then by priority
    groups.sort(key=lambda g: (
        0 if g.critical_count > 0 else 1,
        -g.critical_count,
        -g.high_count,
        g.priority
    ))

    return groups


def _build_narrative(primary_finding, all_findings, blast_radii) -> str:
    """
    Build a 2-3 sentence narrative that explains WHY this matters.
    
    Not a description of the finding. A description of what goes wrong 
    in the real world if you don't fix it.
    """
    fid = primary_finding["id"]

    if fid == "STRATUM-001":
        return (
            "Your agents send emails and take actions with no human check. "
            "One crafted email can make your agent forward inbox contents "
            "to an attacker — this is the exact pattern behind the Microsoft "
            "Copilot EchoLeak breach ($200M+ impact across 160+ incidents)."
        )

    if fid.startswith("STRATUM-CR05"):
        # Collect blast radius info from all CR05 findings
        br_descriptions = []
        for f in all_findings:
            title = f["title"]
            # Extract "ToolName -> N agents in crew 'CrewName'" from title
            br_descriptions.append(title.replace("Shared tool blast radius: ", ""))
        return (
            f"{'. '.join(br_descriptions)}. "
            "One poisoned search result compromises all of them at once."
        )

    if fid.startswith("STRATUM-CR06"):
        bypass_descriptions = []
        for f in all_findings:
            bypass_descriptions.append(f["title"])
        desc = primary_finding["description"]
        return (
            f"In {primary_finding['evidence'][0].replace('Crew: ', '')}, "
            f"{desc.split('.')[0]}. "
            "The filter exists but data flows around it."
        )

    # Generic fallback
    return primary_finding["description"][:200]


def split_primary_and_secondary(groups: list) -> tuple:
    """
    Split action groups into:
    - primary: groups with critical or high findings (get full treatment)
    - secondary: groups with only medium/low findings (get one-liner treatment)
    """
    primary = [g for g in groups if g.critical_count > 0 or g.high_count > 0]
    secondary = [g for g in groups if g.critical_count == 0 and g.high_count == 0]
    return primary, secondary
```

---

### `output/risk_bar.py` — Visual Risk Score

```python
def render_risk_bar(risk_score: int, findings: list, width: int = 40) -> str:
    """
    Render a visual risk bar:

     RISK SCORE ████████████████████████████░░░░░░░░░░  69 / 100
                 ▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔
                 2 critical · 7 high · 4 medium
    """
    filled = int(width * risk_score / 100)
    empty = width - filled

    # Color selection (for Rich)
    if risk_score <= 30:
        color = "green"
    elif risk_score <= 60:
        color = "yellow"
    elif risk_score <= 80:
        color = "orange1"
    else:
        color = "red"

    bar = "█" * filled + "░" * empty
    underline = "▔" * width

    # Severity summary
    sev = {}
    for f in findings:
        s = f["severity"] if isinstance(f, dict) else f.severity
        sev[s] = sev.get(s, 0) + 1

    parts = []
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev.get(s, 0) > 0:
            parts.append(f"{sev[s]} {s.lower()}")
    severity_line = " · ".join(parts)

    return f"""
 RISK SCORE {bar}  {risk_score} / 100
            {underline}
            {severity_line}
"""
```

---

### `output/flow_map.py` — Per-Crew ASCII Diagrams

```python
def render_crew_flow_map(
    crew,
    graph,
    blast_radii: list,
    control_bypasses: list,
    incident_matches: list,
    max_width: int = 68
) -> str:
    """
    Render a single crew's flow diagram.
    Only called for crews that have findings.

    Layout:
    ┌──────────────────────────────────────────────────────────────────┐
    │                                                                  │
    │  [data source] (sensitivity)                                     │
    │    └──▶ Agent 1 ──▶ Agent 2 ──▶ Agent 3                        │
    │                       ├──▶ External Service  ⚠ no gate          │
    │                       └──▶ External Service  ⚠ no gate          │
    │                                                                  │
    │  ⚠ BYPASS: Agent 3 reads data source directly                   │
    │  🔴 ToolName shared by N agents                                  │
    │  📎 Matches: Incident Name                                       │
    │                                                                  │
    └──────────────────────────────────────────────────────────────────┘
    """
    lines = []
    inner_width = max_width - 4  # Account for "│  " and " │"

    # Get crew agents in order
    agent_names = crew.get("agent_names", crew.agent_names if hasattr(crew, "agent_names") else [])
    agent_labels = _get_agent_labels(graph, agent_names)

    # Get data sources for this crew
    data_sources = _get_crew_data_sources(graph, agent_names)

    # Get external sinks for this crew
    external_sinks = _get_crew_external_sinks(graph, agent_names)

    # Get crew-specific blast radii
    crew_name = crew.get("name", crew.name if hasattr(crew, "name") else "")
    crew_brs = [br for br in blast_radii if br.get("crew_name", "") == crew_name]

    # Get crew-specific bypasses
    crew_bypasses = [b for b in control_bypasses
                     if crew_name in str(b.get("evidence", []))]

    # Get matching incidents
    crew_incidents = _get_crew_incidents(incident_matches, crew_name, graph, agent_names)

    # ─── Render ───

    # Header line
    header = f" {crew_name} ({len(agent_names)} agents, {crew.get('process_type', 'sequential')}) "

    lines.append(f"┌{'─' * (max_width - 2)}┐")
    lines.append(_pad(f"", max_width))

    # Agent chain
    chain = " ──▶ ".join(agent_labels)
    if data_sources:
        for ds in data_sources:
            sens = f" ({ds['sensitivity']})" if ds.get("sensitivity", "unknown") != "unknown" else ""
            lines.append(_pad(f"  {ds['label']}{sens}", max_width))
            lines.append(_pad(f"    └──▶ {chain}", max_width))
    else:
        lines.append(_pad(f"  {chain}", max_width))

    # External sinks
    for sink in external_sinks:
        control_marker = "✓ gated" if sink.get("has_control") else "⚠ no gate"
        # Indent to align with the agent that has this outbound capability
        indent = "      " + "     " * _find_agent_position(agent_names, sink.get("via_agent", ""))
        lines.append(_pad(f"{indent}├──▶ {sink['label']}  {control_marker}", max_width))

    lines.append(_pad("", max_width))

    # Annotations
    for bypass in crew_bypasses:
        bypasser = bypass.get("downstream", "?")
        source = bypass.get("shared_source", "?")
        lines.append(_pad(f"  ⚠ BYPASS: {bypasser} reads {source} directly", max_width))

    for br in crew_brs:
        count = br.get("agent_count", br["agent_count"])
        tool = br.get("source_label", br["source_label"])
        lines.append(_pad(f"  🔴 {tool} shared by {count} agents", max_width))

    for incident in crew_incidents:
        lines.append(_pad(f"  📎 Matches: {incident['name']}", max_width))

    # Add spacing if we had annotations
    if crew_bypasses or crew_brs or crew_incidents:
        lines.append(_pad("", max_width))

    # Footer
    lines.append(f"└{'─' * (max_width - 2)}┘")

    return "\n".join(lines)


def _pad(text: str, width: int) -> str:
    """Pad a line to fit within box borders."""
    inner = text[:width - 4]  # Truncate if too long
    padding = width - 4 - len(inner)
    return f"│ {inner}{' ' * padding} │"


def render_all_crew_maps(
    crews: list,
    graph,
    findings: list,
    blast_radii: list,
    incident_matches: list,
) -> str:
    """
    Render flow maps for crews that have findings.
    Max 4 crews shown. If more, show the 4 with highest finding severity.
    """
    # Find crews that have findings
    crews_with_findings = _rank_crews_by_severity(crews, findings)

    # Limit to top 4
    show = crews_with_findings[:4]

    maps = []
    for crew in show:
        m = render_crew_flow_map(
            crew, graph, blast_radii,
            _get_bypass_findings(findings),
            incident_matches,
        )
        maps.append(m)

    return "\n\n".join(maps)


def _rank_crews_by_severity(crews, findings) -> list:
    """Return crews sorted by sum of finding severity in that crew."""
    severity_scores = {"CRITICAL": 100, "HIGH": 50, "MEDIUM": 10, "LOW": 1}
    scored = []
    for crew in crews:
        crew_name = crew.get("name", "")
        score = 0
        for f in findings:
            if crew_name in str(f.get("evidence", [])) or crew_name in f.get("title", ""):
                score += severity_scores.get(f.get("severity", ""), 0)
        if score > 0:
            scored.append((crew, score))
    scored.sort(key=lambda x: -x[1])
    return [c for c, s in scored]
```

---

### `output/code_block.py` — Bordered Code Snippets

```python
def render_code_block(code: str, max_width: int = 60) -> str:
    """
    Render code in a bordered box:

    ┌────────────────────────────────────────────────────────┐
    │  task = Task(                                          │
    │      description="...",                                │
    │ +    human_input=True   # review before external calls │
    │  )                                                     │
    └────────────────────────────────────────────────────────┘
    """
    lines = code.strip().split("\n")
    inner_width = max(len(line) for line in lines) + 2
    inner_width = max(inner_width, 20)
    inner_width = min(inner_width, max_width - 4)

    result = [f"   ┌{'─' * (inner_width + 2)}┐"]
    for line in lines:
        padded = line[:inner_width].ljust(inner_width)
        result.append(f"   │ {padded} │")
    result.append(f"   └{'─' * (inner_width + 2)}┘")

    return "\n".join(result)
```

---

### `output/terminal.py` — The Orchestrator (REWRITE)

```python
"""
Terminal output renderer.

Renders the scan result as a developer-friendly, action-oriented terminal output.

Structure:
1. Header (project info)
2. Risk bar (visual score)
3. "Fix these first" (primary action groups with full treatment)
4. "What your agents look like" (flow maps for affected crews)
5. "Also worth fixing" (secondary actions as one-liners)
6. Footer (total counts, pointer to --json for details)
"""

from .action_groups import group_findings_into_actions, split_primary_and_secondary
from .flow_map import render_all_crew_maps
from .risk_bar import render_risk_bar
from .code_block import render_code_block


def render_terminal_output(scan_result) -> str:
    """Main entry point. Returns the full terminal output as a string."""

    sections = []

    # ─── 1. HEADER ───
    sections.append(_render_header(scan_result))

    # ─── 2. RISK BAR ───
    all_findings = scan_result["top_paths"] + scan_result["signals"]
    sections.append(render_risk_bar(
        scan_result["risk_score"],
        all_findings
    ))

    # ─── 3. ACTION GROUPS ───
    action_groups = group_findings_into_actions(
        findings=scan_result["top_paths"],
        signals=scan_result["signals"],
        incident_matches=scan_result["incident_matches"],
        detected_frameworks=scan_result["detected_frameworks"],
        blast_radii=scan_result["blast_radii"],
    )

    primary, secondary = split_primary_and_secondary(action_groups)

    if primary:
        sections.append(_render_section_header("FIX THESE FIRST"))
        for i, group in enumerate(primary):
            sections.append(_render_primary_action(group, i + 1, scan_result))

    # ─── 4. FLOW MAPS ───
    crews_for_maps = _get_crews_with_findings(
        scan_result["crew_definitions"],
        scan_result["top_paths"]
    )
    if crews_for_maps:
        sections.append(_render_section_header("WHAT YOUR AGENTS LOOK LIKE"))
        sections.append(render_all_crew_maps(
            scan_result["crew_definitions"],
            scan_result["graph"],
            scan_result["top_paths"],
            scan_result["blast_radii"],
            scan_result["incident_matches"],
        ))

    # ─── 5. SECONDARY ACTIONS ───
    if secondary:
        sections.append(_render_section_header("ALSO WORTH FIXING"))
        for group in secondary:
            sections.append(_render_secondary_action(group))

    # ─── 6. FOOTER ───
    sections.append(_render_footer(scan_result, all_findings))

    return "\n".join(sections)


def _render_header(scan_result) -> str:
    directory = scan_result["directory"]
    # Use just the last component of the path
    project_name = directory.replace("\\", "/").rstrip("/").split("/")[-1]

    frameworks = ", ".join(scan_result["detected_frameworks"])
    crews = len(scan_result["crew_definitions"])
    agents = len(scan_result["agent_definitions"])
    files = scan_result["files_scanned"]

    return f"""
 ╔═══════════════════════════════════════════════════════════════════╗
 ║  STRATUM SCAN                                                    ║
 ║  {project_name} · {files} files · {crews} crews · {agents} agents{' ' * max(0, 27 - len(project_name) - len(str(files)) - len(str(crews)) - len(str(agents)))}║
 ║  Frameworks: {frameworks}{' ' * max(0, 50 - len(frameworks))}║
 ╚═══════════════════════════════════════════════════════════════════╝"""


def _render_section_header(title: str) -> str:
    return f"\n ─── {title} {'─' * max(0, 60 - len(title))}\n"


def _render_primary_action(group, number: int, scan_result) -> str:
    """
    Render a primary action with full treatment:

     ① Add human review on outbound tasks                     ░ 5 min
       Resolves 4 findings (1 critical + 3 high)

       [narrative]

       Fix:
       [code block]
       Apply to: [files]

       📎 Matches real breach: [incident]
    """
    lines = []

    # Number circles
    circles = {1: "①", 2: "②", 3: "③", 4: "④", 5: "⑤", 6: "⑥", 7: "⑦", 8: "⑧", 9: "⑨"}
    num = circles.get(number, f"({number})")

    # Title line with effort right-aligned
    title_part = f" {num} {group.title}"
    effort_part = f"░ {group.effort}"
    gap = max(1, 66 - len(title_part) - len(effort_part))
    lines.append(f"{title_part}{' ' * gap}{effort_part}")

    # Resolves line
    lines.append(f"   Resolves {group.finding_count} findings ({group.severity_label})")
    lines.append("")

    # Narrative
    # Wrap narrative at ~60 chars per line, indented 3 spaces
    wrapped = _wrap_text(group.narrative, 60, indent="   ")
    lines.append(wrapped)

    # Code fix
    if group.code_fix:
        lines.append("")
        lines.append("   Fix:")
        lines.append(render_code_block(group.code_fix))

    # Apply to
    if group.apply_to:
        files_str = ", ".join(group.apply_to[:3])
        if len(group.apply_to) > 3:
            files_str += f" (+{len(group.apply_to) - 3} more)"
        lines.append(f"   Apply to: {files_str}")

    # Incident match
    if group.incident_match:
        lines.append("")
        m = group.incident_match
        lines.append(f"   📎 Matches real breach: {m['name']}")
        if m.get("match_reason"):
            reason_wrapped = _wrap_text(m["match_reason"][:200], 58, indent="      ")
            lines.append(reason_wrapped)

    lines.append("")
    return "\n".join(lines)


def _render_secondary_action(group) -> str:
    """
    Render a secondary action as a one-liner:

     · No error handling on 27 external calls — one timeout crashes everything
    """
    # Use the narrative, truncated to one line
    narrative = group.narrative.split(".")[0] if group.narrative else group.title
    return f" · {narrative}"


def _render_footer(scan_result, all_findings) -> str:
    finding_count = len(scan_result["top_paths"])
    signal_count = len(scan_result["signals"])
    return f"""
 ─── {finding_count} findings total · {signal_count} signals · Full details: stratum scan . --verbose
"""


def _wrap_text(text: str, width: int, indent: str = "") -> str:
    """Word-wrap text to width, with indent on each line."""
    words = text.split()
    lines = []
    current = indent
    for word in words:
        if len(current) + len(word) + 1 > width + len(indent):
            lines.append(current)
            current = indent + word
        else:
            if current == indent:
                current += word
            else:
                current += " " + word
    if current.strip():
        lines.append(current)
    return "\n".join(lines)


def _get_crews_with_findings(crews, findings) -> list:
    """Return crews that have at least one finding."""
    result = []
    for crew in crews:
        name = crew.get("name", "")
        has_finding = any(
            name in str(f.get("evidence", []))
            or name in f.get("title", "")
            for f in findings
        )
        if has_finding:
            result.append(crew)
    return result
```

---

### `output/verbose.py` — Full Detail Mode (NEW)

For `stratum scan . --verbose`, show everything the current output shows: all finding IDs, full evidence arrays, all incident details, all blast radii. This is the existing output behavior, moved to a `--verbose` flag.

```python
def render_verbose_output(scan_result) -> str:
    """
    The comprehensive output. Shows:
    - Everything from terminal.py (header, risk bar, action groups, flow maps)
    - PLUS: every finding with full detail (ID, evidence, description, remediation)
    - PLUS: every signal with full detail
    - PLUS: every incident match with full match_reason
    - PLUS: every blast radius with full agent list
    - PLUS: risk surface metrics
    - PLUS: per-crew risk scores
    """
    # Start with the standard output
    base = render_terminal_output(scan_result)

    # Add full finding details
    sections = [base]
    sections.append(_render_section_header("FULL FINDING DETAILS"))

    for f in scan_result["top_paths"]:
        sections.append(_render_full_finding(f))

    sections.append(_render_section_header("SIGNALS"))
    for s in scan_result["signals"]:
        sections.append(_render_full_finding(s))

    sections.append(_render_section_header("INCIDENT MATCHES"))
    for m in scan_result["incident_matches"]:
        sections.append(_render_full_incident(m))

    sections.append(_render_section_header("GRAPH TOPOLOGY"))
    rs = scan_result["graph"]["risk_surface"]
    for k, v in rs.items():
        sections.append(f"  {k}: {v}")

    return "\n".join(sections)
```

---

### `cli.py` Updates

```python
# Add --verbose flag
@click.option("--verbose", is_flag=True, help="Show full finding details")
@click.option("--json", "json_output", is_flag=True, help="Output raw JSON")
@click.option("--quiet", is_flag=True, help="Only show risk score and critical findings")
def scan(directory, verbose, json_output, quiet):
    result = scanner.scan(directory)

    if json_output:
        print(json.dumps(result, indent=2))
    elif quiet:
        print(render_quiet_output(result))
    elif verbose:
        print(render_verbose_output(result))
    else:
        print(render_terminal_output(result))
```

### Quiet mode — for CI/scripts:

```
stratum scan . --quiet

 STRATUM  crewAI-examples  69/100  2 critical · 7 high · 4 medium
 ① Add human_input=True on outbound tasks (5 min, resolves 4 findings)
 ② Add input validation on shared tools (30 min, resolves 3 findings)
 ③ Fix data access bypass in 2 crews (15 min, resolves 2 findings)
```

Six lines. Done.

---

## WHAT CHANGES IN THE SCANNER

### Modified files:
1. `output/terminal.py` — full rewrite (action-oriented layout)
2. `cli.py` — add `--verbose`, `--quiet` flags

### New files:
3. `output/action_groups.py` — finding→action grouping engine
4. `output/risk_bar.py` — visual risk score bar
5. `output/flow_map.py` — per-crew ASCII flow diagrams
6. `output/code_block.py` — bordered code snippet renderer
7. `output/verbose.py` — full detail mode (current behavior)

### NOT changed:
- Scanner pipeline (capabilities, graph, findings, scoring — all untouched)
- JSON output (all data still available via `--json`)
- Finding generation
- Telemetry
- All other existing functionality

---

## THE COGNITIVE FLOW

Here's what happens in the developer's head when they see the new output:

**Second 1-2:** Header → "ok, it scanned my project"
**Second 2-3:** Risk bar → "69/100, 2 critical — that's not great"
**Second 3-5:** "Fix these first" → "ok, 3 things to do"
**Second 5-10:** Action ① → "oh shit, I need human_input=True — that's the EchoLeak pattern"
**Second 10-15:** Action ② → "ok, shared tools need validation, makes sense"
**Second 15-20:** Flow maps → "oh THAT'S how my agents connect — the response writer bypasses the filter?!"
**Second 20-30:** "Also worth fixing" → "error handling, timeouts — yeah I'll get to those"
**Second 30:** → they copy the code fix and paste it into their editor

The entire experience is under 30 seconds. From "stratum scan ." to "I know what to fix and I'm fixing it."

---

## VALIDATION TARGETS

### On crewAI-examples:

1. **Action groups:** Exactly 7 groups. Top 3 are: add_hitl (4 findings), add_tool_validation (3 findings), fix_bypass (2 findings)
2. **Primary actions:** 3-4 actions get full treatment (those with CRITICAL or HIGH)
3. **Secondary actions:** 3-4 actions rendered as one-liners
4. **Flow maps:** At least 2 crews rendered (EmailFilterCrew, StockAnalysisCrew)
5. **Risk bar:** Shows "69 / 100" with "2 critical · 7 high · 4 medium"
6. **Code blocks:** Action ① shows `human_input=True` in bordered box
7. **Incident match:** Action ① references EchoLeak with path-specific match_reason
8. **Total output:** Under 80 lines (excluding flow maps). Under 100 including flow maps.
9. **--verbose:** Shows everything above PLUS full finding details
10. **--quiet:** Under 10 lines. Shows score + top 3 actions as one-liners.
11. **--json:** Unchanged from current behavior
12. **No finding IDs in default output** (they're in --verbose and --json)
13. **Time estimates on every primary action**
14. **"Apply to" file paths** on actions where evidence includes real files
15. **Footer** references `--verbose` for full details

### The "show your friend" test:

A developer should be able to screenshot the output and post it in Slack with zero additional context, and their coworker understands:
- The project has 2 critical issues
- The #1 fix is adding human_input=True
- It takes 5 minutes
- It prevents the EchoLeak pattern

If the screenshot communicates all of that, it's a 10.

---

## BUILD ORDER FOR CLAUDE CODE

```
Message 1: "Create stratum/output/action_groups.py exactly as specified in the patch.
            Include all ACTION_DEFINITIONS, the group_findings_into_actions function,
            split_primary_and_secondary, and _build_narrative.
            Test with: python -c 'from stratum.output.action_groups import ...'"

Message 2: "Create stratum/output/risk_bar.py, stratum/output/code_block.py,
            and stratum/output/flow_map.py exactly as specified.
            These are pure rendering functions with no dependencies on the scanner."

Message 3: "Rewrite stratum/output/terminal.py as the orchestrator.
            Import from action_groups, risk_bar, code_block, flow_map.
            The render_terminal_output function is the main entry point.
            Create stratum/output/verbose.py for --verbose mode."

Message 4: "Update stratum/cli.py to add --verbose and --quiet flags.
            Default: render_terminal_output. --verbose: render_verbose_output.
            --quiet: render_quiet_output. --json: unchanged."

Message 5: "Run stratum scan on crewAI-examples. Verify:
            - 7 action groups form correctly
            - Top 3 are add_hitl, add_tool_validation, fix_bypass
            - Flow maps render for EmailFilterCrew and StockAnalysisCrew
            - Output is under 100 lines
            - Code blocks have borders
            - Effort estimates appear on every primary action
            Compare default vs --verbose vs --quiet output."
```
