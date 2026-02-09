"""All 10 risk path rules.

Security (6): data exfil, destructive, code exec, MCP CVE, MCP creds, MCP supply chain.
Operational + Business (4): unvalidated financial, no error handling, no timeout, volatile state.
"""
from __future__ import annotations

import logging

from stratum.models import (
    Capability, Confidence, Finding, GuardrailSignal,
    MCPServer, RiskCategory, Severity,
)
from stratum.knowledge.db import (
    KNOWN_CVES, FINANCIAL_IMPORTS, HTTP_LIBRARIES,
)

logger = logging.getLogger(__name__)


def evaluate(
    capabilities: list[Capability],
    mcp_servers: list[MCPServer],
    guardrails: list[GuardrailSignal],
    checkpoint_type: str,
) -> list[Finding]:
    """Run all 10 path rules and return findings."""
    findings: list[Finding] = []

    # Security paths (6)
    findings.extend(_check_data_exfil(capabilities, guardrails))
    findings.extend(_check_destructive(capabilities, guardrails))
    findings.extend(_check_code_exec(capabilities))
    findings.extend(_check_mcp_cve(mcp_servers))
    findings.extend(_check_mcp_credentials(mcp_servers))
    findings.extend(_check_mcp_supply_chain(mcp_servers))

    # Operational + business paths (4)
    findings.extend(_check_unvalidated_financial(capabilities, guardrails))
    findings.extend(_check_no_error_handling(capabilities))
    findings.extend(_check_no_timeout(capabilities))
    findings.extend(_check_volatile_state(checkpoint_type, capabilities))

    return findings


def _derive_finding_confidence(*capabilities: Capability) -> Confidence:
    """A chain is as strong as its weakest link.

    If ANY input capability is HEURISTIC -> finding is HEURISTIC -> max MEDIUM.
    If ANY is PROBABLE -> finding is PROBABLE -> max HIGH.
    Only all-CONFIRMED -> finding can be CRITICAL.
    """
    dominated = Confidence.CONFIRMED
    for cap in capabilities:
        if cap.confidence == Confidence.HEURISTIC:
            return Confidence.HEURISTIC
        if cap.confidence == Confidence.PROBABLE:
            dominated = Confidence.PROBABLE
    return dominated


def _version_gte(version_str: str, fixed_str: str) -> bool:
    """Semver comparison: True if version_str >= fixed_str.

    Uses numeric tuple comparison, NOT string comparison.
    Non-numeric segments -> return False (assume vulnerable).
    """
    try:
        def parse(v: str) -> tuple[int, ...]:
            return tuple(int(x) for x in v.strip().split("."))
        return parse(version_str) >= parse(fixed_str)
    except (ValueError, AttributeError):
        return False


def _has_relevant_guard(
    guardrails: list[GuardrailSignal],
    tool_names: set[str],
    guard_kinds: set[str],
) -> str:
    """Check guardrails for relevance to specific tools.

    Returns:
      "relevant" - a guardrail specifically covers these tools AND has usage -> suppress
      "unrelated" - guardrails exist but don't cover, or import-only -> downgrade
      "none" - no guardrails at all -> full severity
    """
    if not guardrails:
        return "none"

    for g in guardrails:
        if g.kind in guard_kinds:
            if g.kind == "hitl":
                if _hitl_covers_any(g, tool_names):
                    return "relevant"
            elif g.kind in ("output_filter", "input_filter"):
                if g.has_usage:
                    return "relevant"
            elif g.kind == "validation":
                return "relevant"

    return "unrelated"


def _hitl_covers_any(guard: GuardrailSignal, tool_names: set[str]) -> bool:
    """Check if a HITL guardrail covers any of the given tool names."""
    if not guard.covers_tools:
        return True  # Broad HITL covers everything
    return bool(set(guard.covers_tools) & tool_names)


# ── STRATUM-001: Data Exfiltration Path ──────────────────────────────────────


def _check_data_exfil(
    capabilities: list[Capability],
    guardrails: list[GuardrailSignal],
) -> list[Finding]:
    """Data access + outbound with no relevant guardrail -> exfiltration path."""
    data_caps = [c for c in capabilities
                 if c.kind == "data_access" and c.confidence != Confidence.HEURISTIC]
    outbound_caps = [c for c in capabilities
                     if c.kind == "outbound" and c.confidence != Confidence.HEURISTIC]

    if not data_caps or not outbound_caps:
        return []

    findings: list[Finding] = []
    # Generate one finding per data+outbound pair (up to reasonable limit)
    seen_pairs: set[tuple[str, str]] = set()
    for dc in data_caps:
        for oc in outbound_caps:
            pair_key = (dc.function_name, oc.function_name)
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)

            tool_names = {dc.function_name, oc.function_name}
            guard_status = _has_relevant_guard(
                guardrails, tool_names,
                {"output_filter", "input_filter", "hitl"},
            )

            if guard_status == "relevant":
                continue

            confidence = _derive_finding_confidence(dc, oc)
            severity = Severity.CRITICAL if guard_status == "none" else Severity.HIGH

            findings.append(Finding(
                id="STRATUM-001",
                severity=severity,
                confidence=confidence,
                category=RiskCategory.SECURITY,
                title="Data Exfiltration Path",
                path=(f"{dc.function_name} ({dc.library}, line {dc.line_number}) "
                      f"-> no output filter -> "
                      f"{oc.function_name} ({oc.library}, line {oc.line_number})"),
                description=(
                    "A prompt injection makes the agent include DB results in the "
                    "next outbound message. The EchoLeak attack class (CVE-2025-32711)."
                ),
                evidence=[
                    f"{dc.source_file}:{dc.line_number}",
                    f"{oc.source_file}:{oc.line_number}",
                ],
                scenario=(
                    f"An attacker crafts input that causes the agent to query "
                    f"{dc.function_name} and exfiltrate results via {oc.function_name}."
                ),
                remediation=(
                    f'graph.compile(interrupt_before=["{oc.function_name}"])'
                ),
                effort="low",
                references=[
                    "https://embracethered.com/blog/posts/2024/m365-copilot-echo-leak/",
                ],
                owasp_id="ASI01",
            ))

    return findings[:1]  # One data exfil finding (the most dangerous pair)


# ── STRATUM-002: Destructive Action, No Human Gate ───────────────────────────


def _check_destructive(
    capabilities: list[Capability],
    guardrails: list[GuardrailSignal],
) -> list[Finding]:
    """Destructive capability with no relevant HITL -> data loss path."""
    destructive_caps = [c for c in capabilities
                        if c.kind == "destructive" and c.confidence != Confidence.HEURISTIC]

    if not destructive_caps:
        return []

    findings: list[Finding] = []
    for dc in destructive_caps:
        tool_names = {dc.function_name}
        guard_status = _has_relevant_guard(
            guardrails, tool_names, {"hitl"},
        )

        if guard_status == "relevant":
            continue

        confidence = _derive_finding_confidence(dc)
        severity = Severity.CRITICAL if guard_status == "none" else Severity.HIGH

        findings.append(Finding(
            id="STRATUM-002",
            severity=severity,
            confidence=confidence,
            category=RiskCategory.SECURITY,
            title="Destructive Action, No Human Gate",
            path=(f"user input -> agent reasoning -> {dc.function_name} "
                  f"({dc.evidence}, line {dc.line_number}) -> data loss, no undo"),
            description=(
                "The agent can execute destructive database operations without "
                "human approval. A misinterpreted instruction or prompt injection "
                "could cause irreversible data loss."
            ),
            evidence=[f"{dc.source_file}:{dc.line_number}"],
            scenario=(
                f"The agent interprets 'clean up old records' as a reason to call "
                f"{dc.function_name}, deleting production data with no confirmation step."
            ),
            remediation=(
                f'graph.compile(interrupt_before=["{dc.function_name}"])'
            ),
            effort="low",
            owasp_id="ASI02",
        ))

    return findings


# ── STRATUM-003: Code Execution via Agent Tool ───────────────────────────────


def _check_code_exec(capabilities: list[Capability]) -> list[Finding]:
    """Code execution capability -> host compromise path. Always HIGH."""
    code_caps = [c for c in capabilities
                 if c.kind == "code_exec" and c.confidence != Confidence.HEURISTIC]

    if not code_caps:
        return []

    findings: list[Finding] = []
    for cc in code_caps:
        confidence = _derive_finding_confidence(cc)

        findings.append(Finding(
            id="STRATUM-003",
            severity=Severity.HIGH,
            confidence=confidence,
            category=RiskCategory.SECURITY,
            title="Code Execution via Agent Tool",
            path=(f"user input -> {cc.function_name} ({cc.library}, "
                  f"{cc.evidence}, line {cc.line_number}) -> host OS"),
            description=(
                "The agent can execute arbitrary commands on the host system. "
                "A prompt injection could lead to full host compromise."
            ),
            evidence=[f"{cc.source_file}:{cc.line_number}"],
            scenario=(
                f"An attacker injects a prompt that causes the agent to call "
                f"{cc.function_name} with a malicious command, gaining shell access."
            ),
            remediation=(
                "Sandbox the execution environment or add interrupt_before"
            ),
            effort="med",
            owasp_id="ASI05",
        ))

    return findings


# ── STRATUM-004: Known CVE in MCP Server ─────────────────────────────────────


def _check_mcp_cve(mcp_servers: list[MCPServer]) -> list[Finding]:
    """MCP server matches a known CVE -> direct vulnerability."""
    findings: list[Finding] = []

    for server in mcp_servers:
        pkg = server.npm_package
        if not pkg:
            continue

        for cve_pkg, cve_info in KNOWN_CVES.items():
            if pkg != cve_pkg:
                continue

            # Check version
            fixed = cve_info.get("fixed", "")
            if fixed and server.package_version:
                if _version_gte(server.package_version, fixed):
                    continue  # Patched

            findings.append(Finding(
                id="STRATUM-004",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category=RiskCategory.SECURITY,
                title=f"Known Vulnerable MCP: {pkg}",
                path=(f"{server.source_file} -> {pkg} "
                      f"({'unpinned' if not server.package_version else server.package_version}) "
                      f"-> {cve_info['cve']} (CVSS {cve_info['cvss']}): {cve_info['summary']}"),
                description=(
                    f"The MCP server {pkg} has a known vulnerability: "
                    f"{cve_info['cve']} ({cve_info['summary']}). "
                    f"CVSS: {cve_info['cvss']}."
                ),
                evidence=[f"{server.source_file}:{server.name}"],
                scenario=(
                    f"An attacker exploits {cve_info['cve']} in the {pkg} MCP server "
                    f"to execute arbitrary code or exfiltrate data."
                ),
                remediation=f"Pin: npx {pkg}@{fixed}" if fixed else f"Remove or replace {pkg}",
                effort="low",
                references=cve_info.get("urls", []),
                owasp_id="ASI04",
            ))

    return findings


# ── STRATUM-005: MCP Credential Exposure ─────────────────────────────────────


def _check_mcp_credentials(mcp_servers: list[MCPServer]) -> list[Finding]:
    """Production credentials passed to third-party MCP server process."""
    findings: list[Finding] = []

    for server in mcp_servers:
        if server.is_known_safe:
            continue
        if not server.env_vars_passed:
            continue

        sensitive_vars = [
            v for v in server.env_vars_passed
            if any(pat in v.upper() for pat in
                   ["DATABASE", "SECRET", "PASSWORD", "AWS_", "STRIPE_",
                    "OPENAI_", "ANTHROPIC_"])
        ]

        if not sensitive_vars:
            continue

        findings.append(Finding(
            id="STRATUM-005",
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            category=RiskCategory.SECURITY,
            title="Production Credentials to Third-Party MCP",
            path=(f"{server.source_file} -> {server.name} (third-party) <- "
                  f"{', '.join(sensitive_vars)}"),
            description=(
                f"Production secrets ({', '.join(sensitive_vars)}) are passed directly "
                f"to the third-party MCP server '{server.name}'. The server process "
                f"has full access to these credentials."
            ),
            evidence=[f"{server.source_file}:{server.name}"],
            scenario=(
                f"The MCP server '{server.name}' is compromised or malicious. "
                f"It exfiltrates {sensitive_vars[0]} to an external endpoint."
            ),
            remediation="Use scoped read-only credentials for MCP servers",
            effort="med",
            owasp_id="ASI04",
        ))

    return findings


# ── STRATUM-006: MCP Supply Chain Risk ───────────────────────────────────────


def _check_mcp_supply_chain(mcp_servers: list[MCPServer]) -> list[Finding]:
    """Unpinned packages or remote servers with no auth."""
    findings: list[Finding] = []

    for server in mcp_servers:
        if server.is_known_safe:
            continue

        # Unpinned NPM package from unknown publisher
        if server.npm_package and not server.package_version and not server.is_known_safe:
            findings.append(Finding(
                id="STRATUM-006",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                category=RiskCategory.SECURITY,
                title=f"Unpinned MCP: {server.npm_package}",
                path=(f"{server.source_file} -> {server.npm_package} (unpinned, "
                      f"unverified publisher)"),
                description=(
                    f"The MCP server '{server.name}' uses an unpinned npm package "
                    f"'{server.npm_package}' from an unverified publisher. "
                    f"A supply chain attack could inject malicious code."
                ),
                evidence=[f"{server.source_file}:{server.name}:unpinned"],
                scenario=(
                    f"The npm package '{server.npm_package}' is typosquatted or the "
                    f"maintainer account is compromised. The next npx invocation "
                    f"pulls a backdoored version."
                ),
                remediation=(
                    f"Pin version: npx {server.npm_package}@<version>"
                ),
                effort="low",
                owasp_id="ASI04",
            ))

        # Remote server with no auth
        if server.is_remote and not server.has_auth:
            findings.append(Finding(
                id="STRATUM-006",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                category=RiskCategory.SECURITY,
                title=f"Remote MCP, no auth: {server.name}",
                path=(f"{server.source_file} -> {server.name} "
                      f"(remote, no authentication)"),
                description=(
                    f"The MCP server '{server.name}' connects to a remote endpoint "
                    f"without any authentication tokens. Anyone who discovers the "
                    f"endpoint URL can impersonate the server."
                ),
                evidence=[f"{server.source_file}:{server.name}:remote-no-auth"],
                scenario=(
                    f"An attacker discovers the remote MCP endpoint URL and serves "
                    f"poisoned tool responses, manipulating agent behavior."
                ),
                remediation="Add authentication (API key, OAuth) to the MCP connection",
                effort="med",
                owasp_id="ASI04",
            ))

    return findings


# ── STRATUM-007: Unvalidated Financial Operation ─────────────────────────────


def _check_unvalidated_financial(
    capabilities: list[Capability],
    guardrails: list[GuardrailSignal],
) -> list[Finding]:
    """Financial operation with no input validation and no HITL."""
    financial_caps = [
        c for c in capabilities
        if c.kind == "financial"
        and c.confidence != Confidence.HEURISTIC
        and not c.has_input_validation
    ]

    # Also check outbound caps that use financial libraries
    for c in capabilities:
        if (c.kind == "outbound"
                and c.confidence != Confidence.HEURISTIC
                and c.library in FINANCIAL_IMPORTS
                and not c.has_input_validation):
            financial_caps.append(c)

    if not financial_caps:
        return []

    tool_names = {c.function_name for c in financial_caps}
    guard_status = _has_relevant_guard(
        guardrails, tool_names, {"hitl", "validation"},
    )

    if guard_status == "relevant":
        return []

    severity = Severity.HIGH if guard_status == "none" else Severity.MEDIUM
    confidence = _derive_finding_confidence(*financial_caps)

    findings: list[Finding] = []
    for fc in financial_caps:
        findings.append(Finding(
            id="STRATUM-007",
            severity=severity,
            confidence=confidence,
            category=RiskCategory.BUSINESS,
            title=f"Unvalidated Financial: {fc.function_name}",
            path=(f"user input -> {fc.function_name} ({fc.library}, "
                  f"line {fc.line_number}) -> financial transaction, no validation"),
            description=(
                "The agent can process financial transactions without input validation "
                "or human approval. A misinterpreted instruction could process incorrect "
                "amounts with real financial impact."
            ),
            evidence=[f"{fc.source_file}:{fc.line_number}"],
            scenario=(
                f"The agent misinterprets 'cancel order 500' as 'refund $500.00' and "
                f"calls {fc.function_name} without any bounds checking on the amount."
            ),
            remediation=(
                f'# Add validation before financial operations\n'
                f'if amount > MAX_AUTO_REFUND:\n'
                f'    raise ValueError("Amount exceeds auto-refund limit")\n'
                f'# Or add HITL:\n'
                f'graph.compile(interrupt_before=["{fc.function_name}"])'
            ),
            effort="low",
            owasp_id="ASI02",
        ))

    return findings


# ── STRATUM-008: No Error Handling on External Dependencies ──────────────────


def _check_no_error_handling(capabilities: list[Capability]) -> list[Finding]:
    """2+ external calls without try/except -> operational risk."""
    unhandled = [
        c for c in capabilities
        if c.kind in ("outbound", "data_access", "financial")
        and c.confidence == Confidence.CONFIRMED
        and not c.has_error_handling
    ]

    if len(unhandled) < 2:
        return []

    evidence = [f"{c.source_file}:{c.line_number}" for c in unhandled[:5]]

    return [Finding(
        id="STRATUM-008",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        category=RiskCategory.OPERATIONAL,
        title=f"No error handling on {len(unhandled)} external calls",
        path=(f"{len(unhandled)} external calls without try/except -> "
              "silent failures or unhandled crashes"),
        description=(
            f"{len(unhandled)} external calls (database, HTTP, financial) have no "
            f"error handling. A network timeout or service outage causes the agent "
            f"to crash instead of degrading gracefully."
        ),
        evidence=evidence,
        scenario=(
            "The database goes down. The agent crashes mid-workflow instead of "
            "reporting the error, leaving the user with no feedback."
        ),
        remediation=(
            "try:\n"
            "    result = requests.get(url, timeout=30)\n"
            "except requests.RequestException as e:\n"
            '    return f"Service unavailable: {e}"'
        ),
        effort="med",
        owasp_id="ASI08",
    )]


# ── STRATUM-009: No Timeout on HTTP Calls ────────────────────────────────────


def _check_no_timeout(capabilities: list[Capability]) -> list[Finding]:
    """2+ HTTP calls without timeout -> agent hangs indefinitely."""
    no_timeout = [
        c for c in capabilities
        if c.kind == "outbound"
        and c.confidence == Confidence.CONFIRMED
        and c.library in HTTP_LIBRARIES
        and not c.has_timeout
    ]

    if len(no_timeout) < 2:
        return []

    evidence = [f"{c.source_file}:{c.line_number}" for c in no_timeout[:5]]

    return [Finding(
        id="STRATUM-009",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        category=RiskCategory.OPERATIONAL,
        title=f"No timeout on {len(no_timeout)} HTTP calls",
        path=(f"{len(no_timeout)} HTTP calls without timeout= -> "
              "agent hangs indefinitely"),
        description=(
            f"{len(no_timeout)} HTTP calls using requests/httpx/aiohttp have no "
            f"timeout parameter. A slow or unresponsive server causes the agent "
            f"to hang indefinitely."
        ),
        evidence=evidence,
        scenario=(
            "An external API goes down. The agent hangs on the HTTP call forever, "
            "consuming resources and never responding to the user."
        ),
        remediation=(
            "requests.get(url, timeout=30)"
        ),
        effort="low",
        owasp_id="ASI08",
    )]


# ── STRATUM-010: Volatile Agent State ────────────────────────────────────────


def _check_volatile_state(
    checkpoint_type: str,
    capabilities: list[Capability],
) -> list[Finding]:
    """In-memory-only or no checkpointing with multi-step workflows."""
    if checkpoint_type == "durable":
        return []

    confirmed_count = sum(
        1 for c in capabilities if c.confidence == Confidence.CONFIRMED
    )

    if confirmed_count < 3:
        return []

    if checkpoint_type == "memory_only":
        title = "In-memory-only agent state"
        desc = (
            f"The agent uses MemorySaver (in-memory only) with {confirmed_count} "
            f"confirmed capabilities. A process restart loses all conversation "
            f"state and in-progress workflows."
        )
        remediation = (
            "from langgraph.checkpoint.postgres import PostgresSaver\n"
            "checkpointer = PostgresSaver.from_conn_string(DATABASE_URL)"
        )
    else:
        title = "No checkpointing detected"
        desc = (
            f"No checkpoint mechanism detected with {confirmed_count} confirmed "
            f"capabilities. Multi-step agent workflows have no persistence."
        )
        remediation = (
            "from langgraph.checkpoint.memory import MemorySaver\n"
            "checkpointer = MemorySaver()  # minimum\n"
            "# Better: use PostgresSaver for durability"
        )

    return [Finding(
        id="STRATUM-010",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        category=RiskCategory.OPERATIONAL,
        title=title,
        path=f"{checkpoint_type} checkpointing + {confirmed_count} capabilities -> state loss risk",
        description=desc,
        evidence=["agent.py"],
        scenario=(
            "The server process crashes mid-workflow. The agent loses track of "
            "what it was doing, potentially leaving a financial transaction half-complete."
        ),
        remediation=remediation,
        effort="med",
        owasp_id="ASI08",
    )]
