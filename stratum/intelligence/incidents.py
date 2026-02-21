"""Known real-world AI security incidents mapped to graph patterns."""
from __future__ import annotations

from dataclasses import dataclass, field

from stratum.models import IncidentMatch


INCIDENT_DB: list[dict] = [
    {
        "id": "ECHOLEAK-2025",
        "name": "Microsoft Copilot EchoLeak",
        "date": "2025-Q1",
        "impact": "$200M+ est. across 160+ reported incidents",
        "attack_summary": (
            "Zero-click prompt injection via email. Copilot ingested crafted email, "
            "extracted data from OneDrive/SharePoint/Teams, and exfiltrated it through "
            "trusted Microsoft domains."
        ),
        "source_url": "https://embracethered.com/blog/posts/2024/m365-copilot-echo-leak/",
        "required_cap_kinds": ["data_access", "outbound"],
        "tool_signals": ["gmail", "email", "outlook", "inbox", "thread"],
        "pattern": "data_ingestion_to_outbound",
    },
    {
        "id": "SLACK-AI-EXFIL-2024",
        "name": "Slack AI Data Exfiltration",
        "date": "2024-H2",
        "impact": "Private channel data leaked via crafted message links",
        "attack_summary": (
            "Hidden instructions in Slack messages caused AI assistant to insert "
            "malicious link. Clicking it sent private channel data to attacker's server."
        ),
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
        "attack_summary": (
            "Second-order prompt injection: low-privilege agent tricks high-privilege "
            "agent into exporting case files to external URL."
        ),
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
        "attack_summary": (
            "Prompt injection via crafted Docker Hub repository metadata. AI assistant "
            "auto-executed tools to fetch payloads from attacker-controlled servers "
            "without user consent."
        ),
        "source_url": "https://www.docker.com/blog/docker-security-advisory-ask-gordon/",
        "required_cap_kinds": ["outbound"],
        "tool_signals": ["fetch", "http", "requests", "scrape", "search"],
        "pattern": "auto_tool_execution",
    },
]


def match_incidents(result) -> list[IncidentMatch]:
    """Match scan results against known incident patterns and explain WHY.

    Args:
        result: ScanResult object (uses capabilities, agent_relationships,
                graph.uncontrolled_paths, agent_definitions).

    Returns:
        List of IncidentMatch objects sorted by confidence.
    """
    matches: list[IncidentMatch] = []
    cap_kinds = {c.kind for c in result.capabilities if c.confidence.value == "confirmed"}
    tool_names: set[str] = set()
    for c in result.capabilities:
        if c.library:
            tool_names.add(c.library.lower())
        fn = (c.function_name or "").lower().strip("[]")
        if fn:
            tool_names.add(fn)

    for incident in INCIDENT_DB:
        # Check required capability kinds
        if not all(k in cap_kinds for k in incident["required_cap_kinds"]):
            continue

        # Compute confidence based on pattern + tool match
        confidence = 0.5  # base: capability kinds match
        tool_matches = [
            sig for sig in incident["tool_signals"]
            if any(sig in tn for tn in tool_names)
        ]
        if tool_matches:
            confidence += 0.25

        # Pattern-specific boosts
        if incident["pattern"] == "cross_agent_privilege_escalation":
            if any(
                r.relationship_type == "delegates_to"
                for r in result.agent_relationships
            ):
                confidence += 0.25

        if incident["pattern"] == "data_ingestion_to_outbound":
            graph = getattr(result, 'graph', None)
            if graph and hasattr(graph, 'uncontrolled_paths'):
                if any(
                    p.source_sensitivity in ("personal", "financial")
                    for p in graph.uncontrolled_paths
                ):
                    confidence += 0.25

        if confidence < 0.5:
            continue

        # Cap Slack AI confidence if no Slack data source (only Slack outbound)
        if incident["id"] == "SLACK-AI-EXFIL-2024":
            has_slack_source = any(
                "slack" in (c.library or "").lower() and c.kind == "data_access"
                for c in result.capabilities
            )
            if not has_slack_source:
                confidence = min(confidence, 0.5)

        confidence = min(confidence, 1.0)

        match_reason = _generate_match_reason(incident, result, tool_matches)
        matching_files = _get_matching_files(incident, result, tool_matches)
        matching_caps = [
            c.function_name for c in result.capabilities
            if c.kind in incident["required_cap_kinds"]
            and c.confidence.value == "confirmed"
        ][:5]

        matches.append(IncidentMatch(
            incident_id=incident["id"],
            name=incident["name"],
            date=incident["date"],
            impact=incident["impact"],
            confidence=round(confidence, 2),
            attack_summary=incident["attack_summary"],
            source_url=incident["source_url"],
            match_reason=match_reason,
            matching_capabilities=matching_caps,
            matching_files=matching_files[:5],
        ))

    matches.sort(key=lambda m: m.confidence, reverse=True)
    return matches


def _generate_match_reason(
    incident: dict, result, tool_matches: list[str],
) -> str:
    """Generate a human-readable explanation of WHY this incident pattern matched.

    For data_ingestion_to_outbound, finds the best-matching graph path whose
    source/sink labels overlap with the incident's tool_signals — so EchoLeak
    cites the Gmail path, not a generic FileReadTool → SerperDevTool pair.
    """
    if incident["pattern"] == "data_ingestion_to_outbound":
        # Try to find the best graph path that matches this incident's signals
        graph = getattr(result, 'graph', None)
        best_path = None
        best_score = 0

        if graph and hasattr(graph, 'uncontrolled_paths'):
            for path in graph.uncontrolled_paths:
                if not path.nodes:
                    continue
                src_node = graph.nodes.get(path.nodes[0])
                sink_node = graph.nodes.get(path.nodes[-1])
                if not src_node or not sink_node:
                    continue
                score = 0
                src_lbl = src_node.label.lower()
                sink_lbl = sink_node.label.lower()
                for sig in incident["tool_signals"]:
                    if sig in src_lbl:
                        score += 2  # Source match is more important
                    if sig in sink_lbl:
                        score += 1
                # Bonus for personal/financial data
                if path.source_sensitivity in ("personal", "financial"):
                    score += 1
                if score > best_score:
                    best_score = score
                    best_path = path

        if best_path and best_score > 0:
            nodes = best_path.nodes
            labels = [
                graph.nodes[nid].label for nid in nodes if nid in graph.nodes
            ]
            source_label = labels[0] if labels else "data source"
            sink_label = labels[-1] if labels else "external service"
            path_str = " -> ".join(labels)
            first_sentence = incident["attack_summary"].split(".")[0].lower()
            return (
                f"Your agent reads {source_label} and sends data to "
                f"{sink_label} with no filter ({path_str}) -- the same "
                f"data->external pattern that enabled {incident['name']}. "
                f"In that incident, {first_sentence}."
            )

        # Fallback: use first data_access / outbound capability
        data_sources = [c for c in result.capabilities if c.kind == "data_access"]
        outbound_targets = [c for c in result.capabilities if c.kind == "outbound"]
        source_name = (
            data_sources[0].function_name.strip("[]") if data_sources else "data source"
        )
        target_name = (
            outbound_targets[0].function_name.strip("[]") if outbound_targets else "external service"
        )
        first_sentence = incident["attack_summary"].split(".")[0].lower()
        return (
            f"Your code reads data via {source_name} and sends it externally via "
            f"{target_name} -- the same data->external pattern that enabled "
            f"{incident['name']}. In that incident, {first_sentence}."
        )

    elif incident["pattern"] == "cross_agent_privilege_escalation":
        agents_with_power = [
            a for a in result.agent_definitions
            if _agent_has_power(a, result)
        ]
        agent_name = agents_with_power[0].name if agents_with_power else "a high-privilege agent"
        return (
            f"Your agent architecture has cross-agent delegation where one agent can "
            f"influence {agent_name}'s actions -- similar to the {incident['name']} pattern "
            f"where a low-privilege agent tricked a high-privilege agent into exfiltrating data."
        )

    elif incident["pattern"] == "auto_tool_execution":
        # Try graph paths for scrape/web patterns
        graph = getattr(result, 'graph', None)
        if graph and hasattr(graph, 'uncontrolled_paths'):
            for path in graph.uncontrolled_paths:
                if not path.nodes:
                    continue
                labels_lower = " ".join(
                    graph.nodes[nid].label.lower()
                    for nid in path.nodes if nid in graph.nodes
                )
                if any(sig in labels_lower for sig in incident["tool_signals"]):
                    labels = [
                        graph.nodes[nid].label
                        for nid in path.nodes if nid in graph.nodes
                    ]
                    return (
                        f"Your agent auto-executes {labels[0]} to fetch external content "
                        f"({' -> '.join(labels)}) -- the same pattern as "
                        f"{incident['name']}. In that incident, poisoned metadata "
                        f"triggered tools to fetch attacker-controlled payloads."
                    )

        http_tools = [
            c for c in result.capabilities
            if c.kind == "outbound" and c.library in ("requests", "httpx")
        ]
        tool_name = http_tools[0].function_name.strip("[]") if http_tools else "HTTP tools"
        return (
            f"Your agent auto-executes {tool_name} to fetch external content -- "
            f"the same pattern as {incident['name']}. In that incident, "
            f"poisoned metadata triggered tools to fetch attacker-controlled payloads."
        )

    return f"Architectural similarity to {incident['name']}."


def _agent_has_power(agent, result) -> bool:
    """Check if agent has destructive/financial/outbound capabilities."""
    for tool in agent.tool_names:
        for cap in result.capabilities:
            fn = cap.function_name.strip("[]")
            if fn == tool and cap.kind in ("destructive", "financial", "outbound"):
                return True
    return False


def _get_matching_files(
    incident: dict, result, tool_matches: list[str],
) -> list[str]:
    """Get source files implicated in the match."""
    files: set[str] = set()
    for cap in result.capabilities:
        if cap.kind in incident["required_cap_kinds"]:
            files.add(cap.source_file)
    return sorted(files)
