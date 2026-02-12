"""Operational risk rules — things that cause outages, cost overruns, or degraded service."""
from __future__ import annotations

from stratum.models import (
    Finding, ScanResult, Severity, Confidence, RiskCategory,
)
from stratum.knowledge.remediation import framework_remediation


def evaluate_operational_risks(result: ScanResult) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_check_single_provider(result))
    findings.extend(_check_no_cost_controls(result))
    return findings


# ---------------------------------------------------------------------------
# STRATUM-OP01: Single Model Provider Dependency
# ---------------------------------------------------------------------------

PROVIDERS: dict[str, list[str]] = {
    "openai": ["OPENAI_API_KEY", "ChatOpenAI", "openai"],
    "anthropic": ["ANTHROPIC_API_KEY", "ChatAnthropic", "anthropic"],
    "google": ["GOOGLE_API_KEY", "ChatGoogleGenerativeAI", "google"],
    "azure": ["AZURE_OPENAI_API_KEY", "AzureChatOpenAI"],
}


def _check_single_provider(result: ScanResult) -> list[Finding]:
    """All agents depend on a single LLM provider with no fallback."""
    detected_providers: set[str] = set()
    for provider, signals in PROVIDERS.items():
        for signal in signals:
            if any(signal in _env_str(ev) for ev in result.env_vars):
                detected_providers.add(provider)
            if any(
                signal in (c.library or "") or signal in (c.evidence or "")
                for c in result.capabilities
            ):
                detected_providers.add(provider)

    if len(detected_providers) != 1:
        return []

    provider = detected_providers.pop()
    agent_count = len(result.agent_definitions)
    return [Finding(
        id="STRATUM-OP01",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        category=RiskCategory.OPERATIONAL,
        title=f"All agents depend on {provider} — no fallback provider",
        path=f"{agent_count} agents → {provider} → single point of failure",
        description=(
            f"Every agent in this project runs on {provider}. "
            f"A provider outage, rate limit, or API deprecation halts everything simultaneously."
        ),
        evidence=[f"env: {provider.upper()}_API_KEY"],
        scenario=(
            f"{provider.capitalize()} has a 4-hour outage (this has happened multiple times). "
            f"All {agent_count} agents stop responding. "
            f"Users get errors. Workflows stall mid-execution."
        ),
        business_context="Service availability risk, vendor lock-in.",
        remediation=(
            f"Add a fallback provider. Use litellm for provider abstraction:\n"
            f"  pip install litellm\n"
            f"  from litellm import completion\n"
            f"  response = completion(model='{provider}/gpt-4', "
            f"fallbacks=['anthropic/claude-3.5-sonnet'])"
        ),
        effort="med",
        finding_class="reliability",
        owasp_id="ASI08",
        owasp_name="Cascading Failures",
    )]


# ---------------------------------------------------------------------------
# STRATUM-OP02: No Cost Controls
# ---------------------------------------------------------------------------

COST_SIGNALS = {
    "max_iter", "max_rpm", "max_tokens", "rate_limit",
    "recursion_limit", "max_turns", "budget",
}


def _check_no_cost_controls(result: ScanResult) -> list[Finding]:
    """No max_iterations, max_tokens, or rate limiting detected."""
    has_cost_control = any(
        any(sig in (g.detail or "").lower() for sig in COST_SIGNALS)
        for g in result.guardrails
    )

    if has_cost_control:
        return []

    if result.total_capabilities < 5:
        return []

    return [Finding(
        id="STRATUM-OP02",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        category=RiskCategory.OPERATIONAL,
        title="No cost controls on agent execution",
        path=f"{result.total_capabilities} capabilities × no iteration limit → unbounded spend",
        description=(
            f"No max_iterations, max_rpm, rate_limit, or token budget detected across "
            f"{result.total_capabilities} capabilities. A reasoning loop or retry storm "
            f"can generate thousands of API calls."
        ),
        evidence=["(no cost control signals found)"],
        scenario=(
            "The agent enters a retry loop trying to parse a malformed response. "
            "Each retry makes an LLM call. After 2,000 iterations, you have a $500 API bill "
            "and no useful output."
        ),
        business_context="Surprise cost, resource exhaustion.",
        remediation=framework_remediation(
            result.detected_frameworks, "add_cost_controls", "",
        ),
        effort="low",
        finding_class="reliability",
        owasp_id="ASI08",
        owasp_name="Cascading Failures",
    )]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _env_str(ev) -> str:
    """Extract string representation from env var."""
    if isinstance(ev, str):
        return ev
    return getattr(ev, 'name', str(ev))
