"""MCP composite risk calculation.

Based on Pynt's analysis of 281 real-world MCP configurations.
Base rate: 9% of MCPs are fully exploitable (untrusted input +
sensitive capability, no human approval required).

Source: pynt.io/resources-hub/mcp-security-research-2025
"""

MCP_BASE_EXPLOIT_RATE = 0.09  # 9% per MCP are fully exploitable


def composite_risk(n: int) -> float:
    """Probability that at least one of n MCPs is exploitable."""
    if n <= 0:
        return 0.0
    return 1.0 - (1.0 - MCP_BASE_EXPLOIT_RATE) ** n


def risk_label(n: int) -> str:
    """Human-readable risk label for n MCPs."""
    if n < 2:
        return ""
    p = composite_risk(n)
    pct = round(p * 100)
    return f"Composite exploit probability: ~{pct}%"
