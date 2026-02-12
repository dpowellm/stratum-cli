"""Business risk rules — risks that impact the organization beyond technical security."""
from __future__ import annotations

from pathlib import Path

from stratum.models import (
    Capability, Finding, ScanResult, Severity, Confidence, RiskCategory,
)
from stratum.knowledge.remediation import framework_remediation


def evaluate_business_risks(result: ScanResult) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_check_autonomous_external_comms(result))
    findings.extend(_check_financial_without_approval(result))
    findings.extend(_check_no_audit_trail(result))
    findings.extend(_check_unstructured_decisions(result))
    return findings


# ---------------------------------------------------------------------------
# STRATUM-BR01: Autonomous External Communication
# ---------------------------------------------------------------------------

HUMAN_FACING = {"smtplib", "slack_sdk", "twilio", "GmailToolkit", "sendgrid",
                "GmailSendMessage", "GmailCreateDraft"}


def _check_autonomous_external_comms(result: ScanResult) -> list[Finding]:
    """Agents that send external messages without human review."""
    human_outbound = [
        c for c in result.capabilities
        if c.kind == "outbound"
        and (c.library in HUMAN_FACING
             or c.function_name.strip("[]") in HUMAN_FACING
             or any(h in (c.library or "") for h in ("slack", "gmail", "smtp", "twilio")))
    ]

    if not human_outbound:
        return []

    findings: list[Finding] = []
    for cap in human_outbound:
        has_hitl = any(
            g.kind in ("hitl", "output_filter")
            and (cap.function_name.strip("[]") in g.covers_tools
                 or _same_project(g.source_file, cap.source_file))
            for g in result.guardrails
        )
        if not has_hitl:
            owning_agent = _find_owning_agent(cap, result.agent_definitions)
            agent_context = f" via agent '{owning_agent.role}'" if owning_agent else ""
            tool_name = cap.function_name.strip("[]")

            severity = Severity.HIGH if cap.confidence == Confidence.CONFIRMED else Severity.MEDIUM

            findings.append(Finding(
                id="STRATUM-BR01",
                severity=severity,
                confidence=cap.confidence,
                category=RiskCategory.BUSINESS,
                title="Agent sends external messages without human review",
                path=f"agent reasoning → {tool_name} → {_outbound_target(cap)}{agent_context}",
                description=(
                    f"Your agent sends messages to real humans via {cap.library or tool_name} "
                    f"with no review step. A hallucinated response, wrong information, or "
                    f"inappropriate tone goes directly to recipients."
                ),
                evidence=[f"{cap.source_file}:{cap.line_number}"],
                scenario=(
                    f"The agent drafts an email response to a customer complaint. "
                    f"It hallucinates a refund promise that doesn't match company policy. "
                    f"The email is sent immediately via {tool_name} — no one reviewed it."
                ),
                business_context="Reputation damage, incorrect commitments, potential liability.",
                remediation=framework_remediation(
                    result.detected_frameworks, "add_hitl", tool_name,
                ),
                effort="low",
                finding_class="business",
                owasp_id="ASI09",
                owasp_name="Human-Agent Trust Exploitation",
                quick_fix_type="add_hitl",
            ))

    return _deduplicate_findings(findings, "STRATUM-BR01")


# ---------------------------------------------------------------------------
# STRATUM-BR02: Financial Action Without Approval
# ---------------------------------------------------------------------------

FINANCIAL_LIBRARIES = {"stripe", "paypal", "braintree", "adyen", "square"}


def _check_financial_without_approval(result: ScanResult) -> list[Finding]:
    """Financial operations with no approval gate."""
    financial_caps = [
        c for c in result.capabilities
        if c.kind == "financial"
        or c.library in FINANCIAL_LIBRARIES
        or (c.kind == "outbound" and any(
            f in (c.library or "").lower()
            for f in ("stripe", "paypal", "payment", "invoice")
        ))
    ]

    if not financial_caps:
        return []

    findings: list[Finding] = []
    for cap in financial_caps:
        has_approval = any(
            g.kind == "hitl"
            and (cap.function_name.strip("[]") in g.covers_tools
                 or _same_project(g.source_file, cap.source_file))
            for g in result.guardrails
        )
        if not has_approval:
            severity = Severity.HIGH if cap.confidence == Confidence.CONFIRMED else Severity.MEDIUM
            tool_name = cap.function_name.strip("[]")
            findings.append(Finding(
                id="STRATUM-BR02",
                severity=severity,
                confidence=cap.confidence,
                category=RiskCategory.BUSINESS,
                title="Financial operation with no approval gate",
                path=f"agent reasoning → {tool_name} → payment action, no approval",
                description=(
                    f"Your agent can trigger financial operations via {cap.library or tool_name} "
                    f"with no human approval step. A reasoning error or prompt injection "
                    f"could trigger unauthorized transactions."
                ),
                evidence=[f"{cap.source_file}:{cap.line_number}"],
                scenario=(
                    "The agent processes a refund request. A prompt injection in the customer message "
                    "changes the amount from $50 to $5,000. The charge is processed immediately."
                ),
                business_context="Direct financial loss, chargebacks, regulatory scrutiny.",
                remediation=framework_remediation(
                    result.detected_frameworks, "add_hitl", tool_name,
                ),
                effort="low",
                finding_class="business",
                owasp_id="ASI09",
                owasp_name="Human-Agent Trust Exploitation",
                quick_fix_type="add_hitl",
            ))
    return _deduplicate_findings(findings, "STRATUM-BR02")


# ---------------------------------------------------------------------------
# STRATUM-BR03: No Audit Trail for Consequential Actions
# ---------------------------------------------------------------------------

OBSERVABILITY_LIBRARIES = {
    "langsmith", "langfuse", "arize", "phoenix", "opentelemetry",
    "mlflow", "wandb", "helicone", "braintrust",
}

OBS_ENV_VARS = {
    "LANGCHAIN_TRACING_V2", "LANGFUSE_SECRET_KEY", "LANGFUSE_PUBLIC_KEY",
    "LANGSMITH_API_KEY", "ARIZE_API_KEY", "OTEL_EXPORTER_OTLP_ENDPOINT",
    "HELICONE_API_KEY", "BRAINTRUST_API_KEY",
}


def _check_no_audit_trail(result: ScanResult) -> list[Finding]:
    """Consequential actions with no observability."""
    has_observability = any(
        any(obs in (c.library or "") for obs in OBSERVABILITY_LIBRARIES)
        for c in result.capabilities
    )
    if not has_observability:
        has_observability = any(
            _env_var_name(ev) in OBS_ENV_VARS for ev in result.env_vars
        )

    if has_observability:
        return []

    consequential = [
        c for c in result.capabilities
        if c.kind in ("destructive", "financial", "outbound")
        and c.confidence == Confidence.CONFIRMED
    ]

    if len(consequential) < 2:
        return []

    return [Finding(
        id="STRATUM-BR03",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        category=RiskCategory.BUSINESS,
        title=f"No audit trail for {len(consequential)} consequential actions",
        path=f"{len(consequential)} confirmed actions → no logging → no forensic trail",
        description=(
            f"Your agent performs {len(consequential)} confirmed consequential actions "
            f"(deletions, external sends, financial ops) but has no observability "
            f"library or tracing configured. When something goes wrong, there's no "
            f"trail to reconstruct what happened."
        ),
        evidence=["(no observability imports or env vars found)"],
        scenario=(
            "A customer reports they received a wrong email from your agent. "
            "You have no logs of what the agent sent, what prompt generated it, "
            "or what data it accessed. You can't even confirm whether the email was sent."
        ),
        business_context="Compliance risk, inability to investigate incidents, no accountability.",
        remediation=(
            "Add observability. Options:\n"
            "  Langfuse (open source): pip install langfuse\n"
            "  LangSmith: set LANGCHAIN_TRACING_V2=true\n"
            "  OpenTelemetry: vendor-neutral, self-hostable."
        ),
        effort="low",
        finding_class="governance",
        owasp_id="ASI05",
        owasp_name="Insufficient Sandboxing / Control",
    )]


# ---------------------------------------------------------------------------
# STRATUM-BR04: Decision-Making Without Structured Output
# ---------------------------------------------------------------------------

DECISION_KEYWORDS = {
    "approv", "classif", "scor", "evaluat", "filter", "triage",
    "review", "assess", "judge", "rate", "rank",
}


def _check_unstructured_decisions(result: ScanResult) -> list[Finding]:
    """Agents making classification/approval decisions without structured output."""
    findings: list[Finding] = []
    for agent in result.agent_definitions:
        role_lower = (agent.role or "").lower()
        name_lower = (agent.name or "").lower()
        combined = role_lower + " " + name_lower

        is_decision_agent = any(kw in combined for kw in DECISION_KEYWORDS)
        if not is_decision_agent:
            continue

        has_structured = any(
            g.kind == "validation"
            and "output_pydantic" in g.detail
            and _same_project(g.source_file, agent.source_file)
            for g in result.guardrails
        )

        if not has_structured:
            findings.append(Finding(
                id="STRATUM-BR04",
                severity=Severity.MEDIUM,
                confidence=Confidence.PROBABLE,
                category=RiskCategory.BUSINESS,
                title=f"Decision agent '{agent.role or agent.name}' has no structured output",
                path=f"input → {agent.name} (decision-making) → unstructured output → downstream action",
                description=(
                    f"Agent '{agent.role or agent.name}' appears to make classification or "
                    f"evaluation decisions but produces unstructured output. Downstream consumers "
                    f"have no schema to validate against, making results inconsistent and unexplainable."
                ),
                evidence=[agent.source_file],
                scenario=(
                    "The agent evaluates a candidate and outputs free text. "
                    "Sometimes it says 'approved', sometimes 'looks good', sometimes 'pass'. "
                    "The downstream system can't reliably parse the decision."
                ),
                business_context="Inconsistent decisions, unexplainable outcomes, audit failure.",
                remediation=framework_remediation(
                    result.detected_frameworks, "add_structured_output", agent.name,
                ),
                effort="low",
                finding_class="business",
                owasp_id="ASI10",
                owasp_name="Rogue Agents",
            ))

    return findings[:3]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _same_project(file_a: str, file_b: str) -> bool:
    """Check if two files belong to the same sub-project."""
    parts_a = Path(file_a).parts
    parts_b = Path(file_b).parts
    common = 0
    for pa, pb in zip(parts_a, parts_b):
        if pa == pb:
            common += 1
        else:
            break
    return common >= 2


def _find_owning_agent(cap: Capability, agent_defs: list) -> object | None:
    """Find which agent owns a capability by matching tool names."""
    tool_name = cap.function_name.strip("[]")
    for agent in agent_defs:
        if tool_name in agent.tool_names:
            return agent
    return None


def _outbound_target(cap: Capability) -> str:
    """Infer the outbound target from a capability."""
    lib = (cap.library or "").lower()
    fn = cap.function_name.strip("[]").lower()
    if "gmail" in lib or "gmail" in fn:
        return "Gmail outbound"
    if "slack" in lib or "slack" in fn:
        return "Slack"
    if "smtp" in lib:
        return "SMTP outbound"
    if "twilio" in lib:
        return "Twilio SMS"
    if "stripe" in lib:
        return "Stripe"
    return "external service"


def _env_var_name(ev) -> str:
    """Extract name from env var (could be string or object)."""
    if isinstance(ev, str):
        parts = ev.split("=", 1)
        return parts[0]
    return getattr(ev, 'name', str(ev))


def _deduplicate_findings(findings: list[Finding], finding_id: str) -> list[Finding]:
    """Deduplicate findings by evidence, keeping highest severity."""
    seen_evidence: set[str] = set()
    unique: list[Finding] = []
    for f in findings:
        key = tuple(sorted(f.evidence))
        key_str = str(key)
        if key_str not in seen_evidence:
            seen_evidence.add(key_str)
            unique.append(f)
    return unique
