# Finding Coverage Report

**Fixture:** simple_crew (3-agent crewAI project)
**Total rules:** 29
**Fired:** 1
**Coverage:** 1/29 (3%)

| Rule ID | Status | Severity |
|---------|--------|----------|
| STRAT-DC-001 | not fired | - |
| STRAT-DC-002 | FIRED | CRITICAL |
| STRAT-DC-003 | not fired | - |
| STRAT-DC-004 | not fired | - |
| STRAT-DC-005 | not fired | - |
| STRAT-DC-006 | not fired | - |
| STRAT-DC-007 | not fired | - |
| STRAT-DC-008 | not fired | - |
| STRAT-OC-001 | not fired | - |
| STRAT-OC-002 | not fired | - |
| STRAT-OC-003 | not fired | - |
| STRAT-OC-004 | not fired | - |
| STRAT-SI-001 | not fired | - |
| STRAT-SI-002 | not fired | - |
| STRAT-SI-003 | not fired | - |
| STRAT-SI-004 | not fired | - |
| STRAT-SI-005 | not fired | - |
| STRAT-SI-006 | not fired | - |
| STRAT-SI-007 | not fired | - |
| STRAT-EA-001 | not fired | - |
| STRAT-EA-002 | not fired | - |
| STRAT-EA-003 | not fired | - |
| STRAT-EA-004 | not fired | - |
| STRAT-EA-006 | not fired | - |
| STRAT-AB-001 | not fired | - |
| STRAT-AB-003 | not fired | - |
| STRAT-AB-004 | not fired | - |
| STRAT-AB-006 | not fired | - |
| STRAT-AB-007 | not fired | - |

## Fired Findings Detail

### STRAT-DC-002 — Irreversible Action Without Approval Gate
- **Severity:** CRITICAL
- **Path:** smtplib
- **Description:** smtplib is irreversible with no human approval gate.
- **Evidence:** crew.py:34

### STRAT-DC-002 — Irreversible Action Without Approval Gate
- **Severity:** CRITICAL
- **Path:** SerperDevTool
- **Description:** SerperDevTool is irreversible with no human approval gate.
- **Evidence:** crew.py

### STRAT-DC-002 — Irreversible Action Without Approval Gate
- **Severity:** CRITICAL
- **Path:** FileReadTool
- **Description:** FileReadTool is irreversible with no human approval gate.
- **Evidence:** crew.py
