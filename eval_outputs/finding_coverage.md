# Finding Coverage Report

**Fixture:** simple_crew (3-agent crewAI project)
**Total rules:** 29
**Fired:** 14
**Coverage:** 14/29 (48%)

| Rule ID | Status | Severity |
|---------|--------|----------|
| STRAT-DC-001 | FIRED | HIGH |
| STRAT-DC-002 | FIRED | CRITICAL |
| STRAT-DC-003 | not fired | - |
| STRAT-DC-004 | not fired | - |
| STRAT-DC-005 | not fired | - |
| STRAT-DC-006 | not fired | - |
| STRAT-DC-007 | not fired | - |
| STRAT-DC-008 | FIRED | HIGH |
| STRAT-OC-001 | not fired | - |
| STRAT-OC-002 | FIRED | MEDIUM |
| STRAT-OC-003 | not fired | - |
| STRAT-OC-004 | not fired | - |
| STRAT-SI-001 | FIRED | CRITICAL |
| STRAT-SI-002 | FIRED | HIGH |
| STRAT-SI-003 | not fired | - |
| STRAT-SI-004 | FIRED | HIGH |
| STRAT-SI-005 | FIRED | HIGH |
| STRAT-SI-006 | not fired | - |
| STRAT-SI-007 | not fired | - |
| STRAT-EA-001 | FIRED | HIGH |
| STRAT-EA-002 | not fired | - |
| STRAT-EA-003 | not fired | - |
| STRAT-EA-004 | FIRED | MEDIUM |
| STRAT-EA-006 | not fired | - |
| STRAT-AB-001 | FIRED | HIGH |
| STRAT-AB-003 | FIRED | HIGH |
| STRAT-AB-004 | not fired | - |
| STRAT-AB-006 | FIRED | HIGH |
| STRAT-AB-007 | FIRED | MEDIUM |

## Fired Findings Detail

### STRAT-DC-001 — Unsupervised Multi-Step Decision Chain
- **Severity:** HIGH
- **Path:** Senior Research Analyst → Financial Analyst → Trade Executor
- **Description:** Delegation chain of 3 agents with no human checkpoint. Decisions cascade without human review.
- **Evidence:** crew.py

### STRAT-DC-002 — Irreversible Action Without Approval Gate
- **Severity:** CRITICAL
- **Path:** Senior Research Analyst → smtplib
- **Description:** smtplib is irreversible with no human approval gate.
- **Evidence:** crew.py; crew.py:76

### STRAT-DC-008 — No Timeout or Circuit Breaker on Agent Chain
- **Severity:** HIGH
- **Path:** Senior Research Analyst → Financial Analyst → Trade Executor
- **Description:** Chain of 3 agents with no timeout configuration. Chain can hang indefinitely.
- **Evidence:** crew.py

### STRAT-OC-002 — Competing Resource Consumers Without Prioritization
- **Severity:** MEDIUM
- **Path:** Trade Executor → Financial Analyst → Senior Research Analyst → Email (SMTP)
- **Description:** 3 agents call Email (SMTP) with no shared rate coordination: Trade Executor, Financial Analyst, Senior Research Analyst.
- **Evidence:** crew.py

### STRAT-SI-001 — Silent Error Propagation Across Agent Boundary
- **Severity:** CRITICAL
- **Path:** Senior Research Analyst → Financial Analyst
- **Description:** Senior Research Analyst returns defaults on error (pattern: default_on_error) and feeds into Financial Analyst with no input validation. Error signal is permanently lost.
- **Evidence:** crew.py

### STRAT-SI-001 — Silent Error Propagation Across Agent Boundary
- **Severity:** CRITICAL
- **Path:** Financial Analyst → Trade Executor
- **Description:** Financial Analyst returns defaults on error (pattern: default_on_error) and feeds into Trade Executor with no input validation. Error signal is permanently lost.
- **Evidence:** crew.py

### STRAT-SI-002 — Confidence Laundering Through Agent Chain
- **Severity:** HIGH
- **Path:** Senior Research Analyst → Financial Analyst
- **Description:** Chain of 2 agents via feeds_into with no confidence/uncertainty metadata preserved. Downstream decisions treat uncertain data as certain.
- **Evidence:** crew.py

### STRAT-SI-002 — Confidence Laundering Through Agent Chain
- **Severity:** HIGH
- **Path:** Senior Research Analyst → Financial Analyst → Trade Executor
- **Description:** Chain of 3 agents via feeds_into with no confidence/uncertainty metadata preserved. Downstream decisions treat uncertain data as certain.
- **Evidence:** crew.py

### STRAT-SI-002 — Confidence Laundering Through Agent Chain
- **Severity:** HIGH
- **Path:** Financial Analyst → Trade Executor
- **Description:** Chain of 2 agents via feeds_into with no confidence/uncertainty metadata preserved. Downstream decisions treat uncertain data as certain.
- **Evidence:** crew.py

### STRAT-SI-004 — Schema Mismatch on Data Flow
- **Severity:** HIGH
- **Path:** Trade Executor → Financial Analyst → Senior Research Analyst
- **Description:** 2 inter-agent data flows lack schema contracts: Senior Research Analyst → Financial Analyst, Financial Analyst → Trade Executor.
- **Evidence:** crew.py

### STRAT-SI-005 — Unvalidated External Data Ingestion
- **Severity:** HIGH
- **Path:** Email (SMTP) → smtplib → Senior Research Analyst
- **Description:** External data flows through smtplib to agent without input validation.
- **Evidence:** crew.py:76; crew.py

### STRAT-SI-005 — Unvalidated External Data Ingestion
- **Severity:** HIGH
- **Path:** Serper API → SerperDevTool → Senior Research Analyst
- **Description:** External data flows through SerperDevTool to agent without input validation.
- **Evidence:** crew.py

### STRAT-EA-001 — Implicit Authority Escalation Through Delegation
- **Severity:** HIGH
- **Path:** Financial Analyst → FileReadTool → SerperDevTool
- **Description:** Financial Analyst has 3 direct capabilities but can reach 5 through delegation. Escalated: FileReadTool, SerperDevTool.
- **Evidence:** crew.py; Direct: psycopg2, smtplib, psycopg2; Escalated: FileReadTool, SerperDevTool

### STRAT-EA-004 — Transitive Data Access Through Delegation
- **Severity:** MEDIUM
- **Path:** Financial Analyst → Crewai Tools
- **Description:** Financial Analyst can reach 1 data stores via delegation that it has no direct access to: Crewai Tools.
- **Evidence:** crew.py

### STRAT-AB-001 — Unbounded Autonomous Volume
- **Severity:** HIGH
- **Path:** Senior Research Analyst → smtplib
- **Description:** Senior Research Analyst has irreversible capabilities [smtplib] with no rate limiting or human checkpoint.
- **Evidence:** crew.py; crew.py:76

### STRAT-AB-001 — Unbounded Autonomous Volume
- **Severity:** HIGH
- **Path:** Financial Analyst → smtplib
- **Description:** Financial Analyst has irreversible capabilities [smtplib] with no rate limiting or human checkpoint.
- **Evidence:** crew.py; crew.py:76

### STRAT-AB-001 — Unbounded Autonomous Volume
- **Severity:** HIGH
- **Path:** Trade Executor → smtplib
- **Description:** Trade Executor has irreversible capabilities [smtplib] with no rate limiting or human checkpoint.
- **Evidence:** crew.py; crew.py:76

### STRAT-AB-003 — Regulatory Exposure Without Audit Trail
- **Severity:** HIGH
- **Path:** Senior Research Analyst → smtplib
- **Description:** smtplib has regulatory category 'communications' but agent Senior Research Analyst has no observability/audit trail.
- **Evidence:** crew.py; crew.py:76

### STRAT-AB-003 — Regulatory Exposure Without Audit Trail
- **Severity:** HIGH
- **Path:** Senior Research Analyst → SerperDevTool
- **Description:** SerperDevTool has regulatory category 'communications' but agent Senior Research Analyst has no observability/audit trail.
- **Evidence:** crew.py

### STRAT-AB-006 — No Rollback on Multi-Step Workflow
- **Severity:** HIGH
- **Path:** Senior Research Analyst → Financial Analyst → Trade Executor
- **Description:** Multi-step workflow of 3 agents includes irreversible actions with no compensating transaction or rollback mechanism.
- **Evidence:** crew.py

### STRAT-AB-007 — Concentration of External Dependencies
- **Severity:** MEDIUM
- **Path:** Trade Executor → Financial Analyst → Senior Research Analyst → Email (SMTP)
- **Description:** 3 agents depend on Email (SMTP) with no fallback. Dependent agents: Trade Executor, Financial Analyst, Senior Research Analyst.
- **Evidence:** crew.py
