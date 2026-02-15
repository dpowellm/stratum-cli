# Composition Coverage Report

**Total COMP rules:** 7
**Total XCOMP rules:** 6
**Fired:** 4

## Within-Reliability Compositions (STRAT-COMP)

| ID | Status | Title |
|----|--------|-------|
| STRAT-COMP-001 | FIRED | Unsupervised Chain With Silent Error Propagation |
| STRAT-COMP-002 | not fired | - |
| STRAT-COMP-003 | FIRED | Unsupervised Chain With Implicit Authority Escalation |
| STRAT-COMP-004 | FIRED | Silent Errors Across Unvalidated Data Boundaries |
| STRAT-COMP-005 | not fired | - |
| STRAT-COMP-006 | FIRED | Unbounded Autonomous Execution of Irreversible Actions |
| STRAT-COMP-007 | not fired | - |

## Cross-Dataset Compositions (STRAT-XCOMP)

| ID | Status | Title |
|----|--------|-------|
| STRAT-XCOMP-001 | not fired | - |
| STRAT-XCOMP-002 | not fired | - |
| STRAT-XCOMP-003 | not fired | - |
| STRAT-XCOMP-004 | not fired | - |
| STRAT-XCOMP-005 | not fired | - |
| STRAT-XCOMP-006 | not fired | - |

## Fired Compositions Detail

### STRAT-COMP-001 — Unsupervised Chain With Silent Error Propagation
- **Severity:** CRITICAL
- **Description:** Unsupervised decision chain WITH silent error propagation through the same chain. The chain can make bad decisions AND no one sees the errors.
- **Evidence:** Constituent A: STRAT-DC-001 (Unsupervised Multi-Step Decision Chain); Constituent B: STRAT-SI-001 (Silent Error Propagation Across Agent Boundary); crew.py

### STRAT-COMP-003 — Unsupervised Chain With Implicit Authority Escalation
- **Severity:** CRITICAL
- **Description:** Unsupervised chain where agents exercise authority they weren't directly granted. Escalation without oversight.
- **Evidence:** Constituent A: STRAT-DC-001 (Unsupervised Multi-Step Decision Chain); Constituent B: STRAT-EA-001 (Implicit Authority Escalation Through Delegation); crew.py

### STRAT-COMP-004 — Silent Errors Across Unvalidated Data Boundaries
- **Severity:** CRITICAL
- **Description:** Errors propagate silently across unvalidated data boundaries. No schema contracts AND no error visibility.
- **Evidence:** Constituent A: STRAT-SI-001 (Silent Error Propagation Across Agent Boundary); Constituent B: STRAT-SI-004 (Schema Mismatch on Data Flow); crew.py

### STRAT-COMP-006 — Unbounded Autonomous Execution of Irreversible Actions
- **Severity:** CRITICAL
- **Description:** Unbounded autonomous execution of irreversible actions. No rate limiting AND no approval gate on destructive capabilities.
- **Evidence:** Constituent A: STRAT-AB-001 (Unbounded Autonomous Volume); Constituent B: STRAT-DC-002 (Irreversible Action Without Approval Gate); crew.py
