# Enrichment Proof

Evidence that the enrichment layer populated expected fields on all node and edge types.

---

## a) Capability Nodes with Reversibility (3+ non-"unknown")

| Node ID | Label | Reversibility | Regulatory Category | Data Mutation | External Service | Idempotent |
|---------|-------|---------------|---------------------|---------------|------------------|------------|
| cap_psycopg2_data_access | psycopg2 | **conditional** | | True | False | None |
| cap_psycopg2_destructive | psycopg2 | **conditional** | | True | False | False |
| cap_smtplib_outbound | smtplib | **irreversible** | communications | False | True | False |
| cap_SerperDevTool_outbound | SerperDevTool | **reversible** | communications | False | True | False |
| cap_FileReadTool_data_access | FileReadTool | **reversible** | | False | False | None |

All 5 capabilities have reversibility set to a value other than "unknown". Three distinct values present: reversible (2), irreversible (1), conditional (2).

---

## b) Agent Nodes with error_handling_pattern

| Node ID | Label | error_handling_pattern | delegation_enabled | human_input_enabled | objective_tag | betweenness_centrality |
|---------|-------|-----------------------|--------------------|---------------------|---------------|------------------------|
| agent_researcher | Senior Research Analyst | **default_on_error** | False | False | maximize_portfolio | 0.0952 |
| agent_analyst | Financial Analyst | **default_on_error** | **True** | False | maximize_portfolio | 0.0714 |
| agent_executor | Trade Executor | **default_on_error** | False | False | maximize_portfolio | 0.0 |

All 3 agents have error_handling_pattern populated. Only agent_analyst has delegation_enabled=True (per-agent AST detection).

### Additional Agent Enrichment Fields

| Agent | model_pinned | timeout_config | max_iterations | memory_enabled | tools_count | delegation_depth | critical_caps_reachable | implicit_authorities | error_blast_radius |
|-------|-------------|----------------|----------------|----------------|-------------|-----------------|------------------------|---------------------|--------------------|
| researcher | False | False | None | False | 0 | 0 | 1 | 0 | 2 |
| analyst | False | False | None | False | 0 | 1 | 1 | 1 | 1 |
| executor | False | False | None | False | 0 | 0 | 1 | 0 | 0 |

---

## c) Computed Edges

### implicit_authority_over (1 edge)
| Source | Target | Description |
|--------|--------|-------------|
| agent_analyst (Financial Analyst) | cap_SerperDevTool_outbound (SerperDevTool) | Analyst can reach SerperDevTool via delegates_to -> researcher -> tool_of |

### error_boundary (2 edges)
| Source | Target | Description |
|--------|--------|-------------|
| agent_researcher (Senior Research Analyst) | agent_analyst (Financial Analyst) | Error boundary: researcher has error_handling_pattern=default_on_error and feeds_into analyst |
| agent_analyst (Financial Analyst) | agent_executor (Trade Executor) | Error boundary: analyst has error_handling_pattern=default_on_error and feeds_into executor |

### shared_state_conflict (3 edges)
| Source | Target | Description |
|--------|--------|-------------|
| agent_analyst (Financial Analyst) | agent_executor (Trade Executor) | Both write to the same data store(s) |
| agent_analyst (Financial Analyst) | agent_researcher (Senior Research Analyst) | Both write to the same data store(s) |
| agent_executor (Trade Executor) | agent_researcher (Senior Research Analyst) | Both write to the same data store(s) |

### error_propagation_path
No error_propagation_path edges were computed. This edge type requires fail_silent agents (error_handling_pattern=fail_silent), but all agents have default_on_error. The error_boundary edges (above) serve a similar purpose for default_on_error agents.

**Total computed edges: 6** (1 implicit_authority_over + 2 error_boundary + 3 shared_state_conflict)

---

## d) All tool_of Edges

| Capability | Agent | Notes |
|-----------|-------|-------|
| cap_SerperDevTool_outbound (SerperDevTool) | agent_researcher (Senior Research Analyst) | Direct assignment via tools=[SerperDevTool()] [trust_crossing] |
| cap_FileReadTool_data_access (FileReadTool) | agent_researcher (Senior Research Analyst) | Direct assignment via tools=[FileReadTool()] |
| cap_psycopg2_data_access (psycopg2) | agent_researcher (Senior Research Analyst) | File-based fallback (module-level function in same file) |
| cap_psycopg2_data_access (psycopg2) | agent_analyst (Financial Analyst) | File-based fallback |
| cap_psycopg2_data_access (psycopg2) | agent_executor (Trade Executor) | File-based fallback |
| cap_psycopg2_destructive (psycopg2) | agent_researcher (Senior Research Analyst) | File-based fallback (INSERT INTO pattern) |
| cap_psycopg2_destructive (psycopg2) | agent_analyst (Financial Analyst) | File-based fallback |
| cap_psycopg2_destructive (psycopg2) | agent_executor (Trade Executor) | File-based fallback |
| cap_smtplib_outbound (smtplib) | agent_researcher (Senior Research Analyst) | File-based fallback (with...as pattern) [trust_crossing] |
| cap_smtplib_outbound (smtplib) | agent_analyst (Financial Analyst) | File-based fallback [trust_crossing] |
| cap_smtplib_outbound (smtplib) | agent_executor (Trade Executor) | File-based fallback [trust_crossing] |

**Total tool_of edges: 11** (2 direct framework tool assignments + 9 file-based fallback)

---

## Edge Enrichment Summary

| Edge Type | Count | Has trust_crossing | Has schema_validated | Has scoped | Has conditional |
|-----------|-------|--------------------|----------------------|------------|-----------------|
| tool_of | 11 | 4 | 0 | 0 | 0 |
| reads_from | 6 | 1 | 0 | 0 | 0 |
| writes_to | 4 | 0 | 0 | 0 | 0 |
| sends_to | 6 | 4 | 0 | 0 | 0 |
| task_sequence | 2 | 0 | 0 | 0 | 0 |
| feeds_into | 2 | 0 | 0 | 0 | 0 |
| delegates_to | 2 | 0 | 0 | 2 | 0 |
| shares_with | 4 | 4 | 0 | 0 | 0 |
| implicit_authority_over | 1 | 0 | 0 | 0 | 0 |
| error_boundary | 2 | 0 | 0 | 0 | 0 |
| shared_state_conflict | 3 | 0 | 0 | 0 | 0 |

---

## Data Store Enrichment

| Node ID | Label | Concurrency Control | Persistence | Access Pattern |
|---------|-------|---------------------|-------------|----------------|
| ds_postgresql | PostgreSQL | version | persistent | read_only |
| ds_psycopg2_write | PostgreSQL (write) | version | persistent | write_only |
| ds_crewai_tools | Crewai Tools | none | persistent | read_only |
