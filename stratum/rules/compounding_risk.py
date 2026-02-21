"""Compounding risk rules — emergent risks from agent interactions.

These rules find risks that only exist because of agent interactions —
no single agent is dangerous alone, but together they create emergent risk.
"""
from __future__ import annotations

from pathlib import Path

from stratum.models import (
    Capability, Finding, ScanResult, Severity, Confidence, RiskCategory,
)
from stratum.rules.helpers import scope_evidence_to_project


def evaluate_compounding_risks(result: ScanResult) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_check_shared_tool_different_trust(result))
    findings.extend(_check_chain_amplification(result))
    findings.extend(_check_cross_boundary_delegation(result))
    findings.extend(_check_uncoordinated_external_writes(result))
    return findings


# ---------------------------------------------------------------------------
# STRATUM-CR01: Shared Tool, Different Trust Contexts
# ---------------------------------------------------------------------------

def _check_shared_tool_different_trust(result: ScanResult) -> list[Finding]:
    """Two agents share a tool but operate in different trust contexts.

    This is the pattern behind EchoLeak: the ingestion agent and the action
    agent share the same tool/API surface with no isolation between them.
    """
    findings: list[Finding] = []

    # Build agent → crew map for same-crew filtering
    agent_crews: dict[str, set[str]] = {}
    for crew in getattr(result, 'crew_definitions', []):
        for name in crew.agent_names:
            agent_crews.setdefault(name, set()).add(crew.name)

    # Group agents by shared tools
    tool_agents: dict[str, list] = {}
    for agent in result.agent_definitions:
        for tool in agent.tool_names:
            tool_agents.setdefault(tool, []).append(agent)

    for tool_name, agents in tool_agents.items():
        if len(agents) < 2:
            continue

        ingestion_agents = [a for a in agents if _processes_external_input(a, result)]
        action_agents = [a for a in agents if _performs_actions(a, result)]

        for ingest in ingestion_agents:
            for actor in action_agents:
                if ingest.name == actor.name:
                    continue

                # Only emit if both agents are in the same crew (or crew-less)
                i_crews = agent_crews.get(ingest.name, set())
                a_crews = agent_crews.get(actor.name, set())
                if i_crews and a_crews and not (i_crews & a_crews):
                    continue

                findings.append(Finding(
                    id="STRATUM-CR01",
                    severity=Severity.HIGH,
                    confidence=(
                        Confidence.CONFIRMED
                        if _both_confirmed(ingest, actor, result)
                        else Confidence.PROBABLE
                    ),
                    category=RiskCategory.COMPOUNDING,
                    title=f"Shared tool '{tool_name}' bridges untrusted input to external action",
                    path=(
                        f"untrusted input → {ingest.role or ingest.name} → [{tool_name}] "
                        f"→ {actor.role or actor.name} → external action"
                    ),
                    description=(
                        f"Agent '{ingest.role or ingest.name}' processes external/untrusted input "
                        f"and shares '{tool_name}' with agent '{actor.role or actor.name}', "
                        f"which performs external actions. A prompt injection in the input can "
                        f"propagate through the shared tool context to trigger unauthorized actions."
                    ),
                    evidence=scope_evidence_to_project(
                        [ingest.source_file, actor.source_file],
                        ingest.source_file,
                    ),
                    scenario=(
                        f"A crafted email arrives. '{ingest.name}' processes it and its context "
                        f"is now influenced by the injected instructions. '{actor.name}' shares "
                        f"the same tool ({tool_name}) and acts on the contaminated context — "
                        f"sending a response the attacker designed."
                    ),
                    business_context=(
                        "This is the architectural pattern behind real-world AI exfiltration incidents. "
                        "No individual agent is misconfigured — the risk emerges from the interaction."
                    ),
                    remediation=(
                        f"Isolate trust contexts between agents:\n"
                        f"  1. Use separate tool instances for {ingest.name} and {actor.name}\n"
                        f"  2. Add an output filter on {ingest.name} before passing to {actor.name}\n"
                        f"  3. Add human_input=True on {actor.name}'s outbound tasks"
                    ),
                    effort="med",
                    finding_class="compounding",
                    owasp_id="ASI01",
                    owasp_name="Agent Goal Hijacking",
                    references=["https://embracethered.com/blog/posts/2024/m365-copilot-echo-leak/"],
                ))

    return _deduplicate_findings(findings, "STRATUM-CR01")


# ---------------------------------------------------------------------------
# STRATUM-CR02: Chain Amplification
# ---------------------------------------------------------------------------

def _check_chain_amplification(result: ScanResult) -> list[Finding]:
    """Sequential agent chains where errors/hallucinations amplify through each step."""
    findings: list[Finding] = []

    for crew in result.crew_definitions:
        if crew.process_type != "sequential" or len(crew.agent_names) < 3:
            continue

        # Check for inter-agent validation
        intermediate_agents = crew.agent_names[1:-1]
        has_intermediate_validation = False
        for agent_name in intermediate_agents:
            has_validation = any(
                g.kind == "validation"
                and "output_pydantic" in g.detail
                and _agent_in_guardrail_scope(agent_name, g, result)
                for g in result.guardrails
            )
            if has_validation:
                has_intermediate_validation = True
                break

        if not has_intermediate_validation:
            chain_str = " → ".join(crew.agent_names)
            findings.append(Finding(
                id="STRATUM-CR02",
                severity=Severity.MEDIUM,
                confidence=Confidence.PROBABLE,
                category=RiskCategory.COMPOUNDING,
                title=f"{len(crew.agent_names)}-agent chain with no intermediate validation",
                path=f"{chain_str} (no validation between steps)",
                description=(
                    f"Crew '{crew.name}' runs {len(crew.agent_names)} agents sequentially "
                    f"with no structured output validation between steps. "
                    f"A hallucination in step 1 propagates through the chain, "
                    f"gaining false confidence at each step."
                ),
                evidence=[crew.source_file],
                scenario=(
                    f"'{crew.agent_names[0]}' hallucinates a data point. "
                    f"'{crew.agent_names[1]}' treats it as fact and builds analysis on it. "
                    f"By the time '{crew.agent_names[-1]}' produces the final output, "
                    f"the hallucination is deeply embedded and presented with high confidence."
                ),
                business_context=(
                    "Compounding hallucination risk. Each unvalidated step amplifies errors. "
                    "The final output may be confidently wrong."
                ),
                remediation=(
                    "Add structured output validation between steps:\n"
                    "  task = Task(\n"
                    "      description=\"...\",\n"
                    "+     output_pydantic=IntermediateResult,  # schema validates between steps\n"
                    "  )"
                ),
                effort="med",
                finding_class="compounding",
                owasp_id="ASI10",
                owasp_name="Rogue Agents",
            ))

    return findings


# ---------------------------------------------------------------------------
# STRATUM-CR03: Cross-Boundary Delegation
# ---------------------------------------------------------------------------

def _check_cross_boundary_delegation(result: ScanResult) -> list[Finding]:
    """An agent with low-privilege tools delegates to an agent with high-privilege tools."""
    findings: list[Finding] = []

    for rel in result.agent_relationships:
        if rel.relationship_type != "delegates_to":
            continue

        source = _find_agent(rel.source_agent, result.agent_definitions)
        target = _find_agent(rel.target_agent, result.agent_definitions)
        if not source or not target:
            continue

        source_cap_kinds = _agent_cap_kinds(source, result)
        target_cap_kinds = _agent_cap_kinds(target, result)

        source_is_reader = source_cap_kinds <= {"data_access", "outbound"}
        target_has_power = target_cap_kinds & {"destructive", "financial"}

        if source_is_reader and target_has_power:
            power_kinds = ", ".join(target_cap_kinds & {"destructive", "financial"})
            findings.append(Finding(
                id="STRATUM-CR03",
                severity=Severity.HIGH,
                confidence=Confidence.PROBABLE,
                category=RiskCategory.COMPOUNDING,
                title=f"'{source.name}' can influence '{target.name}' which has destructive capabilities",
                path=(
                    f"{source.role or source.name} ({', '.join(source_cap_kinds or {'read-only'})}) "
                    f"→ {target.role or target.name} ({', '.join(target_cap_kinds)})"
                ),
                description=(
                    f"Agent '{source.role or source.name}' feeds into or delegates to "
                    f"'{target.role or target.name}', which has {power_kinds} "
                    f"capabilities. A compromise of the upstream agent's reasoning can "
                    f"trigger destructive actions through the downstream agent."
                ),
                evidence=[source.source_file, target.source_file],
                scenario=(
                    f"'{source.name}' is tricked via prompt injection into requesting a destructive action. "
                    f"'{target.name}' receives this as a legitimate instruction from a trusted peer "
                    f"and executes the action — because there's no privilege boundary between them."
                ),
                business_context="Privilege escalation through agent chain.",
                remediation=(
                    f"Add an approval gate between {source.name} and {target.name}:\n"
                    f"  - Validate {source.name}'s output schema before passing to {target.name}\n"
                    f"  - Add human_input=True on {target.name}'s destructive tasks\n"
                    f"  - Log all cross-agent delegations for audit"
                ),
                effort="med",
                finding_class="compounding",
                owasp_id="ASI01",
                owasp_name="Agent Goal Hijacking",
            ))

    return _deduplicate_findings(findings, "STRATUM-CR03")


# ---------------------------------------------------------------------------
# STRATUM-CR04: Uncoordinated External Writes
# ---------------------------------------------------------------------------

COMMS_TARGETS = {"Gmail outbound", "Slack", "SMTP outbound", "Twilio SMS"}


def _check_uncoordinated_external_writes(result: ScanResult) -> list[Finding]:
    """Multiple agents write to the same external service with no coordination."""
    findings: list[Finding] = []

    target_caps: dict[str, list[tuple[Capability, str]]] = {}
    for cap in result.capabilities:
        if cap.kind != "outbound":
            continue
        target = _outbound_target(cap)
        owning_agent = _find_owning_agent(cap, result.agent_definitions)
        agent_name = owning_agent.name if owning_agent else "unknown"
        target_caps.setdefault(target, []).append((cap, agent_name))

    for target, caps_and_agents in target_caps.items():
        if target not in COMMS_TARGETS:
            continue
        unique_agents = set(agent for _, agent in caps_and_agents if agent != "unknown")
        if len(unique_agents) < 2:
            continue

        agent_list = ", ".join(sorted(unique_agents))
        findings.append(Finding(
            id="STRATUM-CR04",
            severity=Severity.MEDIUM,
            confidence=Confidence.PROBABLE,
            category=RiskCategory.COMPOUNDING,
            title=f"Multiple agents send to {target} with no coordination",
            path=f"{agent_list} → {target} (no dedup, no ordering)",
            description=(
                f"Agents {agent_list} all send messages via {target} with no coordination layer. "
                f"A single user action could trigger multiple, inconsistent messages — "
                f"or the same message sent twice."
            ),
            evidence=[c.source_file for c, _ in caps_and_agents],
            scenario=(
                f"A user request triggers two agents. Both decide to respond via {target}. "
                f"The recipient gets two messages with slightly different information, "
                f"creating confusion about which is authoritative."
            ),
            business_context="Brand inconsistency, customer confusion, message fatigue.",
            remediation=(
                f"Add a coordination layer:\n"
                f"  - Route all {target} messages through a single outbound agent\n"
                f"  - Add deduplication on recipient+topic within a time window\n"
                f"  - Use a message queue with exactly-once delivery"
            ),
            effort="med",
            finding_class="compounding",
            owasp_id="ASI08",
            owasp_name="Cascading Failures",
        ))

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

INPUT_SIGNALS = {
    "filter", "read", "ingest", "parse", "receive",
    "scan", "fetch", "scrape", "monitor", "watch",
}

ACTION_SIGNALS = {
    "write", "send", "respond", "action", "execute",
    "draft", "post", "notify", "dispatch", "create",
}


def _processes_external_input(agent, result: ScanResult) -> bool:
    """Does this agent process untrusted/external input?"""
    role_lower = (agent.role or "").lower() + " " + (agent.name or "").lower()
    if any(sig in role_lower for sig in INPUT_SIGNALS):
        return True

    for tool in agent.tool_names:
        for cap in result.capabilities:
            fn = cap.function_name.strip("[]")
            if fn == tool or cap.function_name == f"[{tool}]":
                if cap.kind == "data_access":
                    return True
    return False


def _performs_actions(agent, result: ScanResult) -> bool:
    """Does this agent perform external/consequential actions?"""
    role_lower = (agent.role or "").lower() + " " + (agent.name or "").lower()
    if any(sig in role_lower for sig in ACTION_SIGNALS):
        return True

    for tool in agent.tool_names:
        for cap in result.capabilities:
            fn = cap.function_name.strip("[]")
            if fn == tool or cap.function_name == f"[{tool}]":
                if cap.kind in ("outbound", "destructive", "financial"):
                    return True
    return False


def _both_confirmed(ingest, actor, result: ScanResult) -> bool:
    """Check if both agents' relevant capabilities are confirmed."""
    ingest_confirmed = any(
        c.confidence == Confidence.CONFIRMED and c.kind == "data_access"
        for c in result.capabilities
        if c.function_name.strip("[]") in ingest.tool_names
    )
    actor_confirmed = any(
        c.confidence == Confidence.CONFIRMED and c.kind in ("outbound", "destructive")
        for c in result.capabilities
        if c.function_name.strip("[]") in actor.tool_names
    )
    return ingest_confirmed and actor_confirmed


def _agent_cap_kinds(agent, result: ScanResult) -> set[str]:
    """Get the set of capability kinds for an agent's tools."""
    kinds: set[str] = set()
    for tool in agent.tool_names:
        for cap in result.capabilities:
            fn = cap.function_name.strip("[]")
            if fn == tool or cap.function_name == f"[{tool}]":
                kinds.add(cap.kind)
    return kinds


def _find_agent(agent_name: str, agent_defs: list):
    """Find an agent by name."""
    for a in agent_defs:
        if a.name == agent_name:
            return a
    return None


def _find_owning_agent(cap: Capability, agent_defs: list):
    """Find which agent owns a capability."""
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
    return "external service"


def _agent_in_guardrail_scope(agent_name: str, guard, result: ScanResult) -> bool:
    """Check if a guardrail applies to a given agent."""
    agent = _find_agent(agent_name, result.agent_definitions)
    if not agent:
        return False
    return _same_project(guard.source_file, agent.source_file)


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


def _deduplicate_findings(findings: list[Finding], finding_id: str) -> list[Finding]:
    """Deduplicate by evidence, keeping highest severity."""
    seen: set[str] = set()
    unique: list[Finding] = []
    for f in findings:
        key = str(tuple(sorted(f.evidence)))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
