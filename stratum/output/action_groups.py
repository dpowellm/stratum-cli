"""Groups findings by the action that resolves them.

13 findings -> 7 action groups -> 3 that matter right now

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
from __future__ import annotations

from dataclasses import dataclass, field

from stratum.models import BlastRadius, Finding, IncidentMatch, Severity


@dataclass
class ActionGroup:
    action_id: str = ""                     # "add_hitl", "add_tool_validation", etc.
    title: str = ""                         # "Add human review on outbound tasks"
    finding_ids: list[str] = field(default_factory=list)
    finding_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    severity_label: str = ""                # "1 critical + 3 high"
    effort: str = ""                        # "5 min", "15 min", "30 min", "1 hour"
    narrative: str = ""                     # The compelling "why"
    code_fix: str = ""                      # The actual code snippet
    apply_to: list[str] = field(default_factory=list)  # File paths to apply fix
    incident_match: dict | None = None      # Best matching incident, if any
    priority: int = 0                       # Sort order (lower = more urgent)


# ── Action definitions ─────────────────────────────────────────
# Each action defines: which findings it claims, how to describe it,
# what the fix looks like, and how long it takes.

ACTION_DEFINITIONS: dict[str, dict] = {
    "add_hitl": {
        "title": "Add human review on outbound tasks",
        "claims": lambda f: (
            f.quick_fix_type == "add_hitl"
            or "human_input=True" in f.remediation
            or f.id in ("STRATUM-001", "STRATUM-002", "STRATUM-BR01")
        ),
        "narrative_source": "STRATUM-001",
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
            ),
        },
        "priority": 1,
    },
    "add_tool_validation": {
        "title": "Add input validation on shared tools",
        "claims": lambda f: f.id.startswith("STRATUM-CR05"),
        "effort": "30 min",
        "code_fix": {
            "CrewAI": (
                '  class ValidatedSearch(BaseTool):\n'
                '      def _run(self, query: str) -> str:\n'
                '          raw = SerperDevTool()._run(query)\n'
                ' +        if contains_injection_patterns(raw):\n'
                ' +            raise ValueError("Suspicious content")\n'
                '          return raw'
            ),
        },
        "priority": 2,
    },
    "fix_bypass": {
        "title": "Fix data access bypass",
        "claims": lambda f: f.id.startswith("STRATUM-CR06"),
        "effort": "15 min",
        "code_fix": None,
        "priority": 3,
    },
    "isolate_tools": {
        "title": "Isolate shared tool contexts between agents",
        "claims": lambda f: f.id == "STRATUM-CR01",
        "effort": "15 min",
        "code_fix": {
            "CrewAI": (
                '  # Give each agent its own tool instance:\n'
                '  matcher = Agent(\n'
                ' -    tools=[shared_serper],\n'
                ' +    tools=[SerperDevTool()],  # independent instance\n'
                '  )'
            ),
        },
        "priority": 4,
    },
    "add_error_handling": {
        "title": "Add error handling on external calls",
        "claims": lambda f: f.id == "STRATUM-008",
        "effort": "30 min",
        "code_fix": {
            "CrewAI": (
                '  try:\n'
                '      result = crew.kickoff()\n'
                '  except Exception as e:\n'
                '      logger.error(f"Crew failed: {e}")\n'
                '      # graceful degradation'
            ),
        },
        "priority": 10,
    },
    "add_timeout": {
        "title": "Add timeouts on HTTP calls",
        "claims": lambda f: f.id == "STRATUM-009",
        "effort": "2 min",
        "code_fix": {
            "_default": 'requests.get(url, timeout=30)',
        },
        "priority": 11,
    },
    "add_checkpointing": {
        "title": "Add checkpointing for crash recovery",
        "claims": lambda f: f.id == "STRATUM-010",
        "effort": "5 min",
        "code_fix": {
            "CrewAI": (
                '  crew = Crew(\n'
                '      agents=[...],\n'
                '      tasks=[...],\n'
                ' +    memory=True,\n'
                '  )'
            ),
        },
        "priority": 12,
    },
    "add_structured_output": {
        "title": "Add output validation between agent steps",
        "claims": lambda f: f.id == "STRATUM-CR02",
        "effort": "15 min",
        "code_fix": {
            "CrewAI": (
                '  task = Task(\n'
                '      description="...",\n'
                ' +    output_pydantic=IntermediateResult,\n'
                '  )'
            ),
        },
        "priority": 13,
    },
}


def group_findings_into_actions(
    findings: list[Finding],
    signals: list[Finding],
    incident_matches: list[IncidentMatch],
    detected_frameworks: list[str],
    blast_radii: list[BlastRadius],
    scan_result=None,
) -> list[ActionGroup]:
    """Takes raw findings and returns prioritized ActionGroups.

    Process:
    1. Each finding is claimed by at most one action (first match wins by priority)
    2. Actions with 0 findings are dropped
    3. Actions are sorted by priority (critical actions first)
    """
    all_findings = findings + signals

    # Sort action definitions by priority
    sorted_actions = sorted(ACTION_DEFINITIONS.items(), key=lambda x: x[1]["priority"])

    claimed: set[str] = set()
    groups: list[ActionGroup] = []

    for action_id, defn in sorted_actions:
        matching: list[Finding] = []
        for f in all_findings:
            if f.id not in claimed and defn["claims"](f):
                matching.append(f)
                claimed.add(f.id)

        if not matching:
            continue

        group = ActionGroup(action_id=action_id)
        group.title = defn["title"]
        group.finding_ids = [f.id for f in matching]
        group.finding_count = len(matching)
        group.critical_count = sum(
            1 for f in matching if f.severity == Severity.CRITICAL
        )
        group.high_count = sum(
            1 for f in matching if f.severity == Severity.HIGH
        )
        group.medium_count = sum(
            1 for f in matching if f.severity == Severity.MEDIUM
        )
        group.priority = defn["priority"]
        group.effort = defn["effort"]

        # Severity label
        parts: list[str] = []
        if group.critical_count:
            parts.append(f"{group.critical_count} critical")
        if group.high_count:
            parts.append(f"{group.high_count} high")
        if group.medium_count:
            parts.append(f"{group.medium_count} medium")
        group.severity_label = " + ".join(parts)

        # Narrative
        source_id = defn.get("narrative_source")
        narrative_finding = None
        if source_id:
            narrative_finding = next(
                (f for f in matching if f.id == source_id), None
            )
        if not narrative_finding:
            severity_order = {
                Severity.CRITICAL: 0, Severity.HIGH: 1,
                Severity.MEDIUM: 2, Severity.LOW: 3,
            }
            matching.sort(key=lambda f: severity_order.get(f.severity, 99))
            narrative_finding = matching[0]

        group.narrative = _build_narrative(narrative_finding, matching, blast_radii, scan_result)

        # Code fix — pick the right framework
        if defn.get("code_fix"):
            fw = detected_frameworks[0] if detected_frameworks else "_default"
            group.code_fix = defn["code_fix"].get(
                fw, defn["code_fix"].get("_default", "")
            )

        # Apply-to files — collect unique evidence file paths
        apply_files: set[str] = set()
        for f in matching:
            for ev in f.evidence:
                if "\\" in ev or "/" in ev:
                    clean = ev.split(":")[0]
                    parts_list = clean.replace("\\", "/").split("/")
                    if len(parts_list) > 2:
                        apply_files.add("/".join(parts_list[-2:]))
                    else:
                        apply_files.add(clean)
        group.apply_to = sorted(apply_files)

        # Incident match — use finding-type-based matching (v5)
        group.incident_match = _get_breach_for_finding(narrative_finding, incident_matches)

        groups.append(group)

    # Sort: critical-containing groups first, then by priority
    groups.sort(key=lambda g: (
        0 if g.critical_count > 0 else 1,
        -g.critical_count,
        -g.high_count,
        g.priority,
    ))

    return groups


def split_primary_and_secondary(
    groups: list[ActionGroup],
) -> tuple[list[ActionGroup], list[ActionGroup]]:
    """Split action groups into primary (critical/high) and secondary (medium/low)."""
    primary = [g for g in groups if g.critical_count > 0 or g.high_count > 0]
    secondary = [g for g in groups if g.critical_count == 0 and g.high_count == 0]
    return primary, secondary


def _build_narrative(
    primary_finding: Finding,
    all_findings: list[Finding],
    blast_radii: list[BlastRadius],
    scan_result=None,
) -> str:
    """Build a 2-3 sentence narrative explaining WHY this matters.

    Uses attack scenario narratives when available, with project-specific
    context from the scan result.
    """
    fid = primary_finding.id

    # Try attack scenario narratives first (project-specific)
    if scan_result:
        try:
            from stratum.research.narratives import render_narrative, build_narrative_context
            ctx = build_narrative_context(primary_finding, scan_result)
            narrative = render_narrative(fid, ctx)
            if narrative and "{" not in narrative:
                return narrative
        except Exception:
            pass

    # Hardcoded fallbacks for specific finding types
    if fid == "STRATUM-001":
        return (
            "Your agents send emails and take actions with no human check. "
            "One crafted email can make your agent forward inbox contents "
            "to an attacker \u2014 this is the exact pattern behind the Microsoft "
            "Copilot EchoLeak breach ($200M+ impact across 160+ incidents)."
        )

    if fid.startswith("STRATUM-CR05"):
        br_descriptions: list[str] = []
        for f in all_findings:
            br_descriptions.append(
                f.title.replace("Shared tool blast radius: ", "")
            )
        return (
            f"{'. '.join(br_descriptions)}. "
            "One poisoned search result compromises all of them at once."
        )

    if fid.startswith("STRATUM-CR06"):
        desc = primary_finding.description
        crew_ref = ""
        if primary_finding.evidence:
            crew_ref = primary_finding.evidence[0].replace("Crew: ", "")
        if crew_ref:
            return (
                f"In {crew_ref}, {desc.split('.')[0]}. "
                "The filter exists but data flows around it."
            )
        return f"{desc.split('.')[0]}. The filter exists but data flows around it."

    # Generic fallback
    return primary_finding.description[:200]


def _get_breach_for_finding(
    primary_finding: Finding,
    incident_matches: list[IncidentMatch],
) -> dict | None:
    """Get breach match based on the finding's type using FINDING_BREACH_MAP.

    Returns None if no match — omits the 📎 section entirely.
    Falls back to keyword-based matching if the finding isn't in the map.
    """
    from stratum.research.narratives import FINDING_BREACH_MAP, BREACH_DB

    base_id = primary_finding.id.split(".")[0]
    breach_ids = FINDING_BREACH_MAP.get(base_id)

    if breach_ids is not None:
        # Finding is in the map
        if not breach_ids:
            return None  # Explicitly no breach match (empty list)
        breach = BREACH_DB.get(breach_ids[0])
        if breach:
            return {
                "name": breach["name"],
                "confidence": 0.8,
                "match_reason": (
                    f"Your agent's {breach['pattern']} matches the pattern "
                    f"from {breach['name']} ({breach['date']})."
                ),
            }

    # Fallback: use keyword matching for unmapped findings
    return _find_best_incident([primary_finding], incident_matches)


def _find_best_incident(
    findings: list[Finding],
    incident_matches: list[IncidentMatch],
) -> dict | None:
    """Find the most relevant incident match for a set of findings.

    Only returns an incident if there's meaningful keyword overlap
    between the findings' evidence/title and the incident.
    """
    if not incident_matches:
        return None

    # Build keyword set from all findings in this action group
    finding_words: set[str] = set()
    for f in findings:
        finding_words.update(w.lower() for w in f.title.split())
        for ev in f.evidence:
            finding_words.update(
                ev.lower().split("/")[-1].replace(".py", "").split("_")
            )
        # Include finding IDs for direct matching
        finding_words.add(f.id.lower())

    best: dict | None = None
    best_score = 0

    for m in incident_matches:
        if m.confidence < 0.5:
            continue

        # Build keyword set from incident
        match_words: set[str] = set()
        match_words.update(w.lower() for w in m.name.split())
        for cap in getattr(m, "matching_capabilities", []):
            if cap:
                match_words.update(cap.lower().strip("[]").split("_"))
        for mf in getattr(m, "matching_files", []):
            match_words.update(
                mf.lower().split("/")[-1].replace(".py", "").split("_")
            )

        overlap = finding_words & match_words
        # Filter out very common words
        overlap -= {"the", "a", "an", "in", "on", "of", "to", "and", "no", "is"}

        score = len(overlap) * m.confidence
        if score > best_score and len(overlap) >= 2:
            best_score = score
            best = {
                "name": m.name,
                "confidence": m.confidence,
                "match_reason": m.match_reason or "",
            }

    return best
