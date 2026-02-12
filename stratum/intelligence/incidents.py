"""Known real-world AI security incidents mapped to graph patterns."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class GraphPattern:
    """A pattern that matches against a RiskGraph's serialized dict."""
    source_keywords: list[str] = field(default_factory=list)
    sink_keywords: list[str] = field(default_factory=list)
    requires_no_control: bool = True
    sensitivity_types: list[str] = field(default_factory=list)


@dataclass
class Incident:
    id: str
    name: str
    date: str
    impact: str
    url: str
    attack_summary: str
    graph_pattern: GraphPattern


KNOWN_INCIDENTS: list[Incident] = [
    Incident(
        id="ECHOLEAK-2025",
        name="Microsoft Copilot EchoLeak",
        date="2025-Q1",
        impact="$200M+ est. across 160+ reported incidents",
        url="https://embracethered.com/blog/posts/2024/m365-copilot-echo-leak/",
        attack_summary=(
            "Zero-click prompt injection via email. Copilot ingested "
            "crafted email, extracted data from OneDrive/SharePoint/Teams, "
            "and exfiltrated it through trusted Microsoft domains."
        ),
        graph_pattern=GraphPattern(
            source_keywords=["email", "gmail", "messaging", "inbox"],
            sink_keywords=["email", "gmail", "http", "search", "api", "outbound"],
            requires_no_control=True,
            sensitivity_types=["personal", "credentials"],
        ),
    ),
    Incident(
        id="SLACK-AI-EXFIL-2024",
        name="Slack AI Data Exfiltration",
        date="2024-H2",
        impact="Private channel data leaked via crafted message links",
        url="https://promptarmor.substack.com/p/data-exfiltration-from-slack-ai-via",
        attack_summary=(
            "Hidden instructions in Slack messages caused AI assistant "
            "to insert malicious link. Clicking it sent private channel "
            "data to attacker's server."
        ),
        graph_pattern=GraphPattern(
            source_keywords=["messaging", "slack"],
            sink_keywords=["http", "messaging", "api"],
            requires_no_control=True,
            sensitivity_types=["personal", "internal"],
        ),
    ),
    Incident(
        id="SERVICENOW-NOWASSIST-2025",
        name="ServiceNow Now Assist Privilege Escalation",
        date="2025-H2",
        impact="Cross-tenant case file exfiltration",
        url="https://sombrainc.com/blog/llm-security-risks-2026",
        attack_summary=(
            "Second-order prompt injection: low-privilege agent tricks "
            "high-privilege agent into exporting case files to external URL."
        ),
        graph_pattern=GraphPattern(
            source_keywords=["database", "internal", "sql", "postgres"],
            sink_keywords=["http", "email", "api"],
            requires_no_control=True,
            sensitivity_types=["personal", "internal", "credentials"],
        ),
    ),
    Incident(
        id="DOCKER-GORDON-2025",
        name="Docker Ask Gordon Prompt Injection",
        date="2025-Q4",
        impact="Sensitive data exfiltration via poisoned Docker Hub metadata",
        url="https://www.docker.com/blog/docker-security-advisory-ask-gordon/",
        attack_summary=(
            "Prompt injection via crafted Docker Hub repository metadata. "
            "AI assistant auto-executed tools to fetch payloads from "
            "attacker-controlled servers without user consent."
        ),
        graph_pattern=GraphPattern(
            source_keywords=["database", "internal", "email"],
            sink_keywords=["http", "api"],
            requires_no_control=True,
            sensitivity_types=["personal", "credentials", "internal"],
        ),
    ),
]


def match_incidents(graph_dict: dict) -> list[dict]:
    """Match the scan's risk graph against known incident patterns.

    Args:
        graph_dict: Serialized graph from RiskGraph.to_dict()

    Returns:
        List of match dicts sorted by confidence, only >= 0.5.
    """
    matches: list[dict] = []

    for incident in KNOWN_INCIDENTS:
        confidence = _compute_match_confidence(graph_dict, incident.graph_pattern)
        if confidence >= 0.5:
            matches.append({
                "incident_id": incident.id,
                "name": incident.name,
                "date": incident.date,
                "impact": incident.impact,
                "confidence": round(confidence, 2),
                "attack_summary": incident.attack_summary,
                "source_url": incident.url,
            })

    matches.sort(key=lambda m: m["confidence"], reverse=True)
    return matches


def _compute_match_confidence(graph_dict: dict, pattern: GraphPattern) -> float:
    """Score how closely the graph matches an incident pattern.

    Four checks, each worth 0.25:
    1. Source keyword match (data_store node labels)
    2. Sink keyword match (external node labels)
    3. Uncontrolled path exists
    4. Sensitivity type overlap
    """
    score = 0.0
    nodes = graph_dict.get("nodes", [])
    risk_surface = graph_dict.get("risk_surface", {})

    # 1. Source type match — check data_store node labels
    source_labels = [
        n.get("label", "").lower()
        for n in nodes
        if n.get("type") == "data_store"
    ]
    if pattern.source_keywords:
        if any(
            kw in label
            for kw in pattern.source_keywords
            for label in source_labels
        ):
            score += 0.25

    # 2. Sink type match — check external node labels
    sink_labels = [
        n.get("label", "").lower()
        for n in nodes
        if n.get("type") == "external"
    ]
    if pattern.sink_keywords:
        if any(
            kw in label
            for kw in pattern.sink_keywords
            for label in sink_labels
        ):
            score += 0.25

    # 3. Uncontrolled path exists
    if pattern.requires_no_control:
        if risk_surface.get("uncontrolled_path_count", 0) > 0:
            score += 0.25
    else:
        score += 0.25

    # 4. Sensitivity type overlap
    graph_sensitivities = set(risk_surface.get("sensitive_data_types", []))
    if pattern.sensitivity_types:
        if graph_sensitivities & set(pattern.sensitivity_types):
            score += 0.25
    else:
        score += 0.25

    return score
