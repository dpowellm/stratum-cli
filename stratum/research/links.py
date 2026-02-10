"""Contextual research link selection.

Selects up to 3 research links relevant to the specific
findings in a scan. Not a generic link dump.
"""
from __future__ import annotations

import dataclasses

from stratum.models import Finding


@dataclasses.dataclass
class ResearchLink:
    title: str
    url: str
    relevance: str


def select_research_links(findings: list[Finding]) -> list[ResearchLink]:
    """Select research links contextual to actual findings."""
    links: list[ResearchLink] = []
    finding_ids = {f.id for f in findings}

    # Always include OWASP if any finding maps to it
    if any(f.owasp_id for f in findings):
        # Collect unique ASI IDs
        asi_ids = sorted({f.owasp_id for f in findings if f.owasp_id})
        links.append(ResearchLink(
            title="OWASP Top 10 for Agentic Applications 2026",
            url="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
            relevance=f"Your findings map to {', '.join(asi_ids)}",
        ))

    # MCP-specific research if any MCP findings
    if finding_ids & {"STRATUM-005", "STRATUM-006"}:
        links.append(ResearchLink(
            title="Pynt: Quantifying Risk Across 281 MCPs",
            url="https://www.pynt.io/resources-hub/mcp-security-research-2025",
            relevance="Your project uses MCP servers.",
        ))

    # Tool poisoning research if exfiltration or code exec
    if finding_ids & {"STRATUM-001", "STRATUM-003"}:
        links.append(ResearchLink(
            title="MCPTox: Tool Poisoning Attack Benchmark",
            url="https://arxiv.org/abs/2508.14925",
            relevance="Your agent has unguarded data/execution paths.",
        ))

    # Reliability research if timeout/error findings
    if finding_ids & {"STRATUM-008", "STRATUM-009"}:
        links.append(ResearchLink(
            title="LangChain: State of Agent Engineering 2025",
            url="https://www.langchain.com/state-of-agent-engineering",
            relevance="Quality is the #1 barrier to production agents.",
        ))

    return links[:3]  # Max 3 links
