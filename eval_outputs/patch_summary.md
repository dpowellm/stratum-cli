# PATCH-001 Graph Topology Fix — Summary

**Fixture:** `eval_outputs/test_fixtures/simple_crew/` (3-agent CrewAI project)
**Date:** 2026-02-14

---

## Before / After Comparison

| Metric | Before (pre-patch) | After (post-patch) |
|--------|--------------------|--------------------|
| **Agents detected** | 1 (all named "Agent", deduped to 1) | 3 (researcher, analyst, executor) |
| **Capabilities** | 2 | 5 |
| **Data stores** | 1 | 3 |
| **External services** | 1 | 2 |
| **Total nodes** | 5 | 13 |
| **Total edges** | ~5 (cap-level only) | 43 |
| **Agent-connected edges** | 0 | 34 |
| **Reliability findings** | 1 (DC-002 only) | 22 (15 unique rule IDs) |
| **Composite findings** | 0 | 4 |
| **Observation points** | 0 | 9 |
| **Reliability risk score** | 100/100 | 100/100 |
| **Security risk score** | ~30 | 65 |
| **Gap classification** | security_clean_reliability_poor | both_poor |

---

## Node Counts by Type

| Node Type | Count |
|-----------|-------|
| agent | 3 |
| capability | 5 |
| data_store | 3 |
| external | 2 |
| **TOTAL** | **13** |

## Edge Counts by Type

| Edge Type | Total | Agent-connected |
|-----------|-------|-----------------|
| tool_of | 11 | 11 |
| reads_from | 6 | 4 |
| writes_to | 4 | 3 |
| sends_to | 6 | 4 |
| task_sequence | 2 | 2 |
| feeds_into | 2 | 2 |
| delegates_to | 2 | 2 |
| shares_with | 4 | 0 |
| implicit_authority_over | 1 | 1 |
| error_boundary | 2 | 2 |
| shared_state_conflict | 3 | 3 |
| **TOTAL** | **43** | **34** |

---

## Reliability Findings (22 total, 15 unique IDs)

### Decision Chain Risk (DC)

| ID | Severity | Count | Status |
|----|----------|-------|--------|
| STRAT-DC-001 | HIGH | 1 | FIRED |
| STRAT-DC-002 | CRITICAL | 1 | FIRED |
| STRAT-DC-008 | HIGH | 1 | FIRED |

### Objective & Incentive Conflict (OC)

| ID | Severity | Count | Status |
|----|----------|-------|--------|
| STRAT-OC-002 | MEDIUM | 1 | FIRED |

### Signal Integrity & Error Propagation (SI)

| ID | Severity | Count | Status |
|----|----------|-------|--------|
| STRAT-SI-001 | CRITICAL | 2 | FIRED |
| STRAT-SI-002 | HIGH | 3 | FIRED |
| STRAT-SI-004 | HIGH | 1 | FIRED |
| STRAT-SI-005 | HIGH | 2 | FIRED |

### Emergent Authority & Scope Creep (EA)

| ID | Severity | Count | Status |
|----|----------|-------|--------|
| STRAT-EA-001 | HIGH | 1 | FIRED |
| STRAT-EA-004 | MEDIUM | 1 | FIRED |

### Aggregate Behavioral Exposure (AB)

| ID | Severity | Count | Status |
|----|----------|-------|--------|
| STRAT-AB-001 | HIGH | 3 | FIRED |
| STRAT-AB-003 | HIGH | 2 | FIRED |
| STRAT-AB-006 | HIGH | 1 | FIRED |
| STRAT-AB-007 | MEDIUM | 1 | FIRED |

### Anomalies

| ID | Severity | Count | Status |
|----|----------|-------|--------|
| STRAT-ANOMALY-WRITEONLY | LOW | 1 | FIRED |

---

## Composite Findings (4 total)

| ID | Severity | Title |
|----|----------|-------|
| STRAT-COMP-001 | CRITICAL | Unsupervised Chain With Silent Error Propagation |
| STRAT-COMP-003 | CRITICAL | Unsupervised Chain With Implicit Authority Escalation |
| STRAT-COMP-004 | CRITICAL | Silent Errors Across Unvalidated Data Boundaries |
| STRAT-COMP-006 | CRITICAL | Unbounded Autonomous Execution of Irreversible Actions |

---

## Observation Points (9 total)

| ID | Category | Priority | Node |
|----|----------|----------|------|
| OBS-002 | error_boundary | critical | Senior Research Analyst |
| OBS-003 | error_boundary | critical | Financial Analyst |
| OBS-012 | authority_audit | critical | Financial Analyst |
| OBS-001 | decision_audit | high | Trade Executor |
| OBS-004 | volume_monitoring | high | Senior Research Analyst |
| OBS-005 | volume_monitoring | high | Senior Research Analyst |
| OBS-006 | volume_monitoring | high | Senior Research Analyst |
| OBS-010 | schema_validation | medium | Senior Research Analyst |
| OBS-011 | schema_validation | medium | Financial Analyst |

---

## Structural Metrics

| Metric | Value |
|--------|-------|
| Total agents | 3 |
| Total capabilities | 5 |
| Total data stores | 3 |
| Total edges | 43 |
| Total guardrails | 0 |
| Total observability sinks | 0 |
| Max delegation depth | 2 |
| Max data flow depth | 3 |
| Graph density | 0.2756 |
| Trust boundary crossings | 14 (14 unguarded) |
| Shared state conflicts | 3 |
| Irreversible capabilities | 1 (1 unguarded) |
| Error propagation paths | 2 |
| Feedback loops | 1 (1 undampened) |
| Unvalidated data flows | 2 |
| Schema coverage | 0% |
| Human checkpoint ratio | 0% |
| Approval gate ratio | 0% |
| Control coverage | 0% |
| Observability coverage | 0% |

---

## Scores

| Axis | Score | Interpretation |
|------|-------|----------------|
| Security risk | 65/100 | HIGH |
| Reliability risk | 100/100 | CRITICAL (capped) |
| Gap classification | both_poor | Both axes need attention |

---

## Files Modified in PATCH-001

1. `stratum/graph/agents.py` — Fixed agent naming (variable names) and tool resolution
2. `stratum/graph/builder.py` — File-based capability fallback, agent data access edges, task_sequence
3. `stratum/parsers/agents.py` — Added task context flows and delegation relationship extraction
4. `stratum/parsers/capabilities.py` — Handle `with...as` (ast.With) patterns
5. `stratum/knowledge/db.py` — Added INSERT/UPDATE to destructive SQL keywords
6. `stratum/reliability/engine.py` — DC-001 edge type expansion
7. `stratum/reliability/enrichment.py` — Per-agent delegation, REVERSIBLE_TOOLS set
8. `stratum/scanner.py` — Wired new parsers into CrewAI dispatch
9. `eval_outputs/test_fixtures/simple_crew/crew.py` — 3-agent fixture with error handling patterns
