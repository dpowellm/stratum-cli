"""OWASP ASI mapping for Stratum findings.

Based on OWASP Top 10 for Agentic Applications 2026.
Source: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
"""

OWASP_MAP: dict[str, tuple[str, str]] = {
    "STRATUM-001": ("ASI01", "Agent Goal Hijacking"),
    "STRATUM-002": ("ASI09", "Human-Agent Trust Exploitation"),
    "STRATUM-003": ("ASI02", "Tool Misuse & Exploitation"),
    "STRATUM-004": ("ASI06", "Insufficient Control Over Agent Actions"),
    "STRATUM-005": ("ASI04", "Supply Chain & Environment Risks"),
    "STRATUM-006": ("ASI04", "Supply Chain & Environment Risks"),
    "STRATUM-007": ("ASI02", "Tool Misuse & Exploitation"),
    "STRATUM-008": ("ASI08", "Cascading Failures"),
    "STRATUM-009": ("ASI08", "Cascading Failures"),
    "STRATUM-010": ("ASI05", "Insufficient Sandboxing / Control"),
    "ENV-001":     ("ASI04", "Supply Chain & Environment Risks"),
    # Learning & Governance
    "LEARNING-001": ("ASI10", "Rogue Agents"),
    "LEARNING-002": ("ASI10", "Rogue Agents"),
    "LEARNING-003": ("ASI07", "Insecure Inter-Agent Communication"),
    "LEARNING-004": ("ASI10", "Rogue Agents"),
    "CONTEXT-001":  ("ASI10", "Rogue Agents"),
    "CONTEXT-002":  ("ASI10", "Rogue Agents"),
    "CONTEXT-003":  ("ASI07", "Insecure Inter-Agent Communication"),
    "TELEMETRY-001": ("ASI04", "Supply Chain & Environment Risks"),
    "TELEMETRY-002": ("ASI04", "Supply Chain & Environment Risks"),
    "TELEMETRY-003": ("ASI05", "Insufficient Sandboxing / Control"),
    "EVAL-001":     ("ASI09", "Human-Agent Trust Exploitation"),
    "EVAL-002":     ("ASI05", "Insufficient Sandboxing / Control"),
    "IDENTITY-001": ("ASI03", "Identity & Privilege Abuse"),
    "IDENTITY-002": ("ASI03", "Identity & Privilege Abuse"),
    "IDENTITY-003": ("ASI03", "Identity & Privilege Abuse"),
    "PORTABILITY-001": ("", ""),
    "PORTABILITY-002": ("ASI05", "Insufficient Sandboxing / Control"),
    "PORTABILITY-003": ("", ""),
}


def get_owasp(finding_id: str) -> tuple[str, str]:
    """Return (owasp_id, owasp_name) for a finding ID."""
    return OWASP_MAP.get(finding_id, ("", ""))
