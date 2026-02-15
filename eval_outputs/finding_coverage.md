# Finding Coverage Report

**Fixture:** simple_crew (3-agent CrewAI project)
**Total rules:** 29
**Fired:** 14
**Coverage:** 14/29 (48%)

---

## Coverage Matrix

| Rule ID | Status | Severity | Instances |
|---------|--------|----------|-----------|
| STRAT-DC-001 | FIRED | HIGH | 1 |
| STRAT-DC-002 | FIRED | CRITICAL | 1 |
| STRAT-DC-003 | not fired | - | 0 |
| STRAT-DC-004 | not fired | - | 0 |
| STRAT-DC-005 | not fired | - | 0 |
| STRAT-DC-006 | not fired | - | 0 |
| STRAT-DC-007 | not fired | - | 0 |
| STRAT-DC-008 | FIRED | HIGH | 1 |
| STRAT-OC-001 | not fired | - | 0 |
| STRAT-OC-002 | FIRED | MEDIUM | 1 |
| STRAT-OC-003 | not fired | - | 0 |
| STRAT-OC-004 | not fired | - | 0 |
| STRAT-SI-001 | FIRED | CRITICAL | 2 |
| STRAT-SI-002 | FIRED | HIGH | 3 |
| STRAT-SI-003 | not fired | - | 0 |
| STRAT-SI-004 | FIRED | HIGH | 1 |
| STRAT-SI-005 | FIRED | HIGH | 2 |
| STRAT-SI-006 | not fired | - | 0 |
| STRAT-SI-007 | not fired | - | 0 |
| STRAT-EA-001 | FIRED | HIGH | 1 |
| STRAT-EA-002 | not fired | - | 0 |
| STRAT-EA-003 | not fired | - | 0 |
| STRAT-EA-004 | FIRED | MEDIUM | 1 |
| STRAT-EA-006 | not fired | - | 0 |
| STRAT-AB-001 | FIRED | HIGH | 3 |
| STRAT-AB-003 | FIRED | HIGH | 2 |
| STRAT-AB-004 | not fired | - | 0 |
| STRAT-AB-006 | FIRED | HIGH | 1 |
| STRAT-AB-007 | FIRED | MEDIUM | 1 |

---

## Fired Findings Detail

### STRAT-DC-001 — Unsupervised Multi-Step Decision Chain
- **Severity:** HIGH
- **Path:** Senior Research Analyst -> Financial Analyst -> Trade Executor
- **Description:** Delegation chain of 3 agents with no human checkpoint. Decisions cascade without human review.
- **Evidence:** crew.py
- **Remediation:** Add human_input=True (CrewAI) or interrupt_before (LangGraph) at critical points in the delegation chain.
- **Structural basis:** 3-agent chain via task_sequence + feeds_into edges, all agents have human_input_enabled=False.

### STRAT-DC-002 — Irreversible Action Without Approval Gate
- **Severity:** CRITICAL
- **Path:** Senior Research Analyst -> smtplib
- **Description:** smtplib is irreversible with no human approval gate.
- **Evidence:** crew.py; crew.py:76
- **Remediation:** Add approval_required guardrail or human_input=True on the Task.
- **Structural basis:** cap_smtplib_outbound has reversibility=irreversible and no APPROVAL_REQUIRED or GATED_BY edges exist.

### STRAT-DC-008 — No Timeout or Circuit Breaker on Agent Chain
- **Severity:** HIGH
- **Path:** Senior Research Analyst -> Financial Analyst -> Trade Executor
- **Description:** Chain of 3 agents with no timeout configuration. Chain can hang indefinitely.
- **Evidence:** crew.py
- **Structural basis:** 3-agent chain where all agents have timeout_config=False and no RATE_LIMITED_BY edges.

### STRAT-OC-002 — Competing Resource Consumers Without Prioritization
- **Severity:** MEDIUM
- **Path:** Financial Analyst -> Senior Research Analyst -> Trade Executor -> Email (SMTP)
- **Description:** 3 agents call Email (SMTP) with no shared rate coordination.
- **Evidence:** crew.py
- **Structural basis:** 3 agents all have sends_to edges to ext_email_smtp, with no rate_limited_by or arbitrated_by edges.

### STRAT-SI-001 — Silent Error Propagation Across Agent Boundary (x2)
- **Severity:** CRITICAL
- **Instance 1 path:** Senior Research Analyst -> Financial Analyst
- **Instance 2 path:** Financial Analyst -> Trade Executor
- **Description:** Agent returns defaults on error (pattern: default_on_error) and feeds into downstream agent with no input validation. Error signal is permanently lost.
- **Structural basis:** error_handling_pattern=default_on_error on source agent, feeds_into edge to target agent, no validation_on_input on target agent's tools.

### STRAT-SI-002 — Confidence Laundering Through Agent Chain (x3)
- **Severity:** HIGH
- **Paths:** researcher->analyst (2-hop), researcher->analyst->executor (3-hop), analyst->executor (2-hop)
- **Description:** Chain of agents via feeds_into with no confidence/uncertainty metadata preserved.
- **Structural basis:** feeds_into edges between agents, no output_schema set on any agent (output_schema=None).

### STRAT-SI-004 — Schema Mismatch on Data Flow
- **Severity:** HIGH
- **Path:** Financial Analyst -> Senior Research Analyst -> Trade Executor
- **Description:** 2 inter-agent data flows lack schema contracts.
- **Structural basis:** feeds_into edges exist between agents but schema_validated=False on all, schema_coverage_pct=0%.

### STRAT-SI-005 — Unvalidated External Data Ingestion (x2)
- **Severity:** HIGH
- **Instance 1:** Email (SMTP) -> smtplib -> Senior Research Analyst
- **Instance 2:** Serper API -> SerperDevTool -> Senior Research Analyst
- **Structural basis:** External service nodes connect to capability nodes (trust_level=external) with tool_of edges to agents, capabilities have validation_on_input=False.

### STRAT-EA-001 — Implicit Authority Escalation Through Delegation
- **Severity:** HIGH
- **Path:** Financial Analyst -> SerperDevTool -> FileReadTool
- **Description:** Financial Analyst has 3 direct capabilities but can reach 5 through delegation. Escalated: SerperDevTool, FileReadTool.
- **Evidence:** Direct: smtplib, psycopg2, psycopg2; Escalated: SerperDevTool, FileReadTool
- **Structural basis:** implicit_authority_over edge from agent_analyst to cap_SerperDevTool_outbound, computed via delegates_to + tool_of transitivity.

### STRAT-EA-004 — Transitive Data Access Through Delegation
- **Severity:** MEDIUM
- **Path:** Financial Analyst -> Crewai Tools
- **Description:** Financial Analyst can reach 1 data store via delegation that it has no direct access to: Crewai Tools.
- **Structural basis:** delegates_to edge from analyst to researcher, researcher has reads_from to ds_crewai_tools, analyst does not.

### STRAT-AB-001 — Unbounded Autonomous Volume (x3)
- **Severity:** HIGH
- **Agents:** Senior Research Analyst, Financial Analyst, Trade Executor
- **Description:** Each agent has irreversible capabilities [smtplib] with no rate limiting or human checkpoint.
- **Structural basis:** tool_of edges from cap_smtplib_outbound (reversibility=irreversible) to all 3 agents, no rate_limited_by edges, human_input_enabled=False.

### STRAT-AB-003 — Regulatory Exposure Without Audit Trail (x2)
- **Severity:** HIGH
- **Instance 1:** Senior Research Analyst -> smtplib (regulatory_category=communications)
- **Instance 2:** Senior Research Analyst -> SerperDevTool (regulatory_category=communications)
- **Structural basis:** Capabilities with regulatory_category set, agents have no OBSERVED_BY edges to observability sinks. observability_coverage_pct=0%.

### STRAT-AB-006 — No Rollback on Multi-Step Workflow
- **Severity:** HIGH
- **Path:** Senior Research Analyst -> Financial Analyst -> Trade Executor
- **Description:** Multi-step workflow of 3 agents includes irreversible actions with no compensating transaction or rollback mechanism.
- **Structural basis:** task_sequence chain of 3 agents, cap_smtplib_outbound has reversibility=irreversible, no compensating edges.

### STRAT-AB-007 — Concentration of External Dependencies
- **Severity:** MEDIUM
- **Path:** Financial Analyst -> Senior Research Analyst -> Trade Executor -> Email (SMTP)
- **Description:** 3 agents depend on Email (SMTP) with no fallback.
- **Structural basis:** 3 agents all have sends_to edges to ext_email_smtp, no alternative external service nodes.

---

## Unfired Findings — Structural Explanations

### STRAT-DC-003 — Unobserved Decision Point
- **Why not fired:** Requires an agent with makes_decisions=True that has no OBSERVED_BY edge. No agent in the fixture has makes_decisions=True because none have approve/reject/categorize/route capabilities.

### STRAT-DC-004 — Cascading Autonomous Decisions
- **Why not fired:** Requires 2+ agents with makes_decisions=True in a connected chain. No agents have decision-making capabilities (approve, reject, route, categorize subtypes).

### STRAT-DC-005 — Single-Point Bottleneck Agent
- **Why not fired:** Requires an agent with betweenness_centrality above the threshold and high tool_count. The fixture's max betweenness is 0.0952 (agent_researcher), which does not exceed the rule's threshold.

### STRAT-DC-006 — Recursive Delegation Loop
- **Why not fired:** Requires a cycle in delegates_to edges. The fixture has analyst->researcher and analyst->executor but no delegation back to analyst, so no cycle exists.

### STRAT-DC-007 — Trust Boundary Chain Without Validation
- **Why not fired:** Requires a chain of 3+ agents where edges cross trust boundaries. All agents are trust_level=internal; trust crossings occur between agents and external-trust capabilities, not between agents themselves.

### STRAT-OC-001 — Conflicting Agent Objectives
- **Why not fired:** Requires agents with conflicting objective_tags. All 3 agents have objective_tag=maximize_portfolio (same tag), so no conflict is detected.

### STRAT-OC-003 — Partial Bucket B (requires multi-crew context)
- **Why not fired:** This is a Bucket B rule requiring cross-crew comparison. The fixture has only one crew.

### STRAT-OC-004 — Partial Bucket B (requires multi-crew context)
- **Why not fired:** This is a Bucket B rule requiring cross-crew comparison. The fixture has only one crew.

### STRAT-SI-003 — Ambiguous Output Type Without Schema
- **Why not fired:** Requires an agent that produces decisions (makes_decisions=True) with no output_schema. No agent has makes_decisions=True in this fixture.

### STRAT-SI-006 — Feedback Loop Without Dampening
- **Why not fired:** Requires a feedback loop involving feeds_into/delegates_to edges where agents form a cycle. The detected feedback loop (feedback_loops_detected=1) does not meet the rule's specific structural requirements for agent-to-agent cyclic flows.

### STRAT-SI-007 — Stale Cache in Data Flow
- **Why not fired:** Requires a data_store with freshness_mechanism=none being read by multiple agents in a write-then-read pattern. The fixture's data stores have freshness_mechanism values that don't trigger this rule, or the read/write pattern doesn't match the stale cache scenario.

### STRAT-EA-002 — Capability Accumulation Beyond Role Scope
- **Why not fired:** Requires an agent with tools_count significantly exceeding its duty_class expectations. No agents have duty_class set (all empty), so the role-scoping comparison cannot be made.

### STRAT-EA-003 — Unscoped Delegation
- **Why not fired:** Requires a delegates_to edge with scoped=False. The fixture's delegates_to edges have scoped=True (CrewAI delegation is tool-scoped by default).

### STRAT-EA-006 — Shadow Authority Through Shared State
- **Why not fired:** Requires agents to have shared_state_conflict edges AND one agent writing data that changes another agent's behavior. While 3 shared_state_conflict edges exist, the rule requires specific write->read patterns through shared data stores that constitute behavioral influence, which the fixture's agents don't exhibit.

### STRAT-AB-004 — Cross-Domain Data Flow Without Isolation
- **Why not fired:** Requires agents with different agent_domain values sharing data stores. All agents have agent_domain="" (not set), so no cross-domain comparison can be made.
